package service

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/steveiliop56/tinyauth/internal/config"
	"github.com/steveiliop56/tinyauth/internal/utils/decoders"
	"github.com/steveiliop56/tinyauth/internal/utils/tlog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

var _ = unstructured.Unstructured{}

type ingressKey struct {
	namespace string
	name      string
}

type ingressAppKey struct {
	ingressKey
	appName string
}

type ingressApp struct {
	domain  string
	appName string
	app     config.App
}

type KubernetesService struct {
	client       dynamic.Interface
	ctx          context.Context
	cancel       context.CancelFunc
	started      bool
	v1GVR        *schema.GroupVersionResource
	v1beta1GVR   *schema.GroupVersionResource
	mu           sync.RWMutex
	ingressApps  map[ingressKey][]ingressApp
	domainIndex  map[string]ingressAppKey
	appNameIndex map[string]ingressAppKey
}

func NewKubernetesService() *KubernetesService {
	return &KubernetesService{
		ingressApps:  make(map[ingressKey][]ingressApp),
		domainIndex:  make(map[string]ingressAppKey),
		appNameIndex: make(map[string]ingressAppKey),
	}
}

func (k *KubernetesService) addIngressApps(namespace, name string, apps []ingressApp) {
	k.mu.Lock()
	defer k.mu.Unlock()

	key := ingressKey{namespace, name}
	// Remove existing entries for this ingress
	if existing, ok := k.ingressApps[key]; ok {
		for _, app := range existing {
			delete(k.domainIndex, app.domain)
			delete(k.appNameIndex, app.appName)
		}
	}
	// Add new entries
	k.ingressApps[key] = apps
	for _, app := range apps {
		appKey := ingressAppKey{key, app.appName}
		k.domainIndex[app.domain] = appKey
		k.appNameIndex[app.appName] = appKey
	}
}

func (k *KubernetesService) removeIngress(namespace, name string) {
	k.mu.Lock()
	defer k.mu.Unlock()

	key := ingressKey{namespace, name}
	if apps, ok := k.ingressApps[key]; ok {
		for _, app := range apps {
			delete(k.domainIndex, app.domain)
			delete(k.appNameIndex, app.appName)
		}
		delete(k.ingressApps, key)
	}
}

func (k *KubernetesService) getByDomain(domain string) (config.App, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if appKey, ok := k.domainIndex[domain]; ok {
		if apps, ok := k.ingressApps[appKey.ingressKey]; ok {
			for _, app := range apps {
				if app.domain == domain && app.appName == appKey.appName {
					return app.app, true
				}
			}
		}
	}
	return config.App{}, false
}

func (k *KubernetesService) getByAppName(appName string) (config.App, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if appKey, ok := k.appNameIndex[appName]; ok {
		if apps, ok := k.ingressApps[appKey.ingressKey]; ok {
			for _, app := range apps {
				if app.appName == appName {
					return app.app, true
				}
			}
		}
	}
	return config.App{}, false
}

func (k *KubernetesService) updateFromList(items []unstructured.Unstructured) {
	for _, item := range items {
		namespace := item.GetNamespace()
		name := item.GetName()
		annotations := item.GetAnnotations()
		if annotations == nil {
			k.removeIngress(namespace, name)
			continue
		}
		labels, err := decoders.DecodeLabels[config.Apps](annotations, "apps")
		if err != nil {
			tlog.App.Debug().Err(err).Msg("Failed to decode labels from annotations")
			k.removeIngress(namespace, name)
			continue
		}
		var apps []ingressApp
		for appName, appLabels := range labels.Apps {
			if appLabels.Config.Domain == "" {
				continue
			}
			apps = append(apps, ingressApp{
				domain:  appLabels.Config.Domain,
				appName: appName,
				app:     appLabels,
			})
		}
		if len(apps) == 0 {
			k.removeIngress(namespace, name)
		} else {
			k.addIngressApps(namespace, name, apps)
		}
	}
}

func (k *KubernetesService) resyncGVR(gvr schema.GroupVersionResource) error {
	ctx, cancel := context.WithTimeout(k.ctx, 30*time.Second)
	defer cancel()

	list, err := k.client.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		tlog.App.Debug().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Failed to list ingresses during resync")
		return err
	}
	k.updateFromList(list.Items)
	tlog.App.Debug().Str("api", gvr.GroupVersion().String()).Int("count", len(list.Items)).Msg("Resynced ingress cache")
	return nil
}

func (k *KubernetesService) watchGVR(gvr schema.GroupVersionResource) {
	resyncTicker := time.NewTicker(5 * time.Minute)
	defer resyncTicker.Stop()

	// Initial resync
	if err := k.resyncGVR(gvr); err != nil {
		tlog.App.Error().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Initial resync failed, retrying in 30 seconds")
		time.Sleep(30 * time.Second)
	}

	for {
		select {
		case <-k.ctx.Done():
			tlog.App.Debug().Str("api", gvr.GroupVersion().String()).Msg("Stopping watcher")
			return
		case <-resyncTicker.C:
			if err := k.resyncGVR(gvr); err != nil {
				tlog.App.Warn().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Periodic resync failed")
			}
		default:
			ctx, cancel := context.WithCancel(k.ctx)
			watcher, err := k.client.Resource(gvr).Watch(ctx, metav1.ListOptions{})
			if err != nil {
				tlog.App.Error().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Failed to start watcher")
				cancel()
				time.Sleep(10 * time.Second)
				continue
			}

			tlog.App.Debug().Str("api", gvr.GroupVersion().String()).Msg("Watcher started")
		inner:
			for {
				select {
				case <-k.ctx.Done():
					watcher.Stop()
					cancel()
					return
				case event, ok := <-watcher.ResultChan():
					if !ok {
						tlog.App.Debug().Str("api", gvr.GroupVersion().String()).Msg("Watcher channel closed")
						watcher.Stop()
						cancel()
						break inner
					}
					switch event.Type {
					case watch.Added, watch.Modified:
						item, ok := event.Object.(*unstructured.Unstructured)
						if !ok {
							tlog.App.Warn().Str("api", gvr.GroupVersion().String()).Msg("Failed to cast watched object")
							continue
						}
						namespace := item.GetNamespace()
						name := item.GetName()
						annotations := item.GetAnnotations()
						if annotations == nil {
							k.removeIngress(namespace, name)
							continue
						}
						labels, err := decoders.DecodeLabels[config.Apps](annotations, "apps")
						if err != nil {
							tlog.App.Debug().Err(err).Msg("Failed to decode labels from annotations")
							k.removeIngress(namespace, name)
							continue
						}
						var apps []ingressApp
						for appName, appLabels := range labels.Apps {
							if appLabels.Config.Domain == "" {
								continue
							}
							apps = append(apps, ingressApp{
								domain:  appLabels.Config.Domain,
								appName: appName,
								app:     appLabels,
							})
						}
						if len(apps) == 0 {
							k.removeIngress(namespace, name)
						} else {
							k.addIngressApps(namespace, name, apps)
						}
					case watch.Deleted:
						item, ok := event.Object.(*unstructured.Unstructured)
						if !ok {
							tlog.App.Warn().Str("api", gvr.GroupVersion().String()).Msg("Failed to cast watched object")
							continue
						}
						k.removeIngress(item.GetNamespace(), item.GetName())
					default:
						// ignore other event types
					}
				case <-resyncTicker.C:
					if err := k.resyncGVR(gvr); err != nil {
						tlog.App.Warn().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Periodic resync failed")
					}
				}
			}
		}
	}
}

func (k *KubernetesService) Init() error {
	var config *rest.Config
	var err error

	// Try in-cluster config first
	config, err = rest.InClusterConfig()
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to get in-cluster Kubernetes config")
		k.started = false
		return nil
	}

	client, err := dynamic.NewForConfig(config)
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to create Kubernetes client")
		k.started = false
		return nil
	}

	// Create discovery client to check available APIs
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		tlog.App.Error().Err(err).Msg("Failed to create discovery client")
		k.started = false
		return nil
	}

	k.client = client
	k.ctx, k.cancel = context.WithCancel(context.Background())

	// Check which Ingress APIs are available
	apiGroups, err := discoveryClient.ServerPreferredResources()
	if err != nil {
		// This can happen with partial discovery errors, log and continue
		tlog.App.Debug().Err(err).Msg("Failed to discover API resources")
	}

	// Start watching available Ingress APIs
	v1Available := false
	v1beta1Available := false

	if apiGroups != nil {
		for _, apiGroup := range apiGroups {
			if apiGroup.GroupVersion == "networking.k8s.io/v1" {
				for _, resource := range apiGroup.APIResources {
					if resource.Name == "ingresses" && resource.Kind == "Ingress" {
						v1Available = true
					}
				}
			}
			if apiGroup.GroupVersion == "extensions/v1beta1" {
				for _, resource := range apiGroup.APIResources {
					if resource.Name == "ingresses" && resource.Kind == "Ingress" {
						v1beta1Available = true
					}
				}
			}
		}
	}

	// Check permissions for available APIs
	checkAccess := func(gvr schema.GroupVersionResource) bool {
		ctx, cancel := context.WithTimeout(k.ctx, 5*time.Second)
		defer cancel()

		_, err := k.client.Resource(gvr).List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil {
			tlog.App.Debug().Err(err).Str("api", gvr.GroupVersion().String()).Msg("Cannot access Ingress API")
			return false
		}
		return true
	}

	if v1Available {
		gvr := schema.GroupVersionResource{
			Group:    "networking.k8s.io",
			Version:  "v1",
			Resource: "ingresses",
		}
		if checkAccess(gvr) {
			tlog.App.Debug().Msg("networking.k8s.io/v1 Ingress API accessible")
			k.v1GVR = &gvr
			go k.watchIngressV1()
		} else {
			tlog.App.Warn().Msg("Insufficient permissions for networking.k8s.io/v1 Ingress")
			v1Available = false
		}
	} else {
		tlog.App.Debug().Msg("networking.k8s.io/v1 Ingress API not available")
	}

	if v1beta1Available {
		gvr := schema.GroupVersionResource{
			Group:    "extensions",
			Version:  "v1beta1",
			Resource: "ingresses",
		}
		if checkAccess(gvr) {
			tlog.App.Debug().Msg("extensions/v1beta1 Ingress API accessible")
			k.v1beta1GVR = &gvr
			go k.watchIngressV1beta1()
		} else {
			tlog.App.Warn().Msg("Insufficient permissions for extensions/v1beta1 Ingress")
			v1beta1Available = false
		}
	} else {
		tlog.App.Debug().Msg("extensions/v1beta1 Ingress API not available")
	}

	if !v1Available && !v1beta1Available {
		tlog.App.Warn().Msg("No Ingress API available or accessible, Kubernetes label provider will not work")
		k.started = false
		return nil
	}

	k.started = true
	tlog.App.Info().Msg("Kubernetes label provider initialized")
	return nil
}

func (k *KubernetesService) GetLabels(appDomain string) (config.App, error) {
	if !k.started {
		tlog.App.Debug().Msg("Kubernetes not connected, returning empty labels")
		return config.App{}, nil
	}

	// First check cache
	if app, found := k.getByDomain(appDomain); found {
		tlog.App.Debug().Str("domain", appDomain).Msg("Found labels in cache by domain")
		return app, nil
	}
	appName := strings.SplitN(appDomain, ".", 2)[0]
	if app, found := k.getByAppName(appName); found {
		tlog.App.Debug().Str("domain", appDomain).Str("appName", appName).Msg("Found labels in cache by app name")
		return app, nil
	}

	tlog.App.Debug().Str("domain", appDomain).Msg("Cache miss, falling back to API")

	// Try v1 API first
	if k.v1GVR != nil {
		app, err := k.getLabelsFromGVR(*k.v1GVR, appDomain)
		if err != nil {
			tlog.App.Debug().Err(err).Msg("Failed to get labels from v1 Ingress")
		}
		if app.Config.Domain != "" {
			return app, nil
		}
	}
	// Fall back to v1beta1
	if k.v1beta1GVR != nil {
		app, err := k.getLabelsFromGVR(*k.v1beta1GVR, appDomain)
		if err != nil {
			tlog.App.Debug().Err(err).Msg("Failed to get labels from v1beta1 Ingress")
		}
		if app.Config.Domain != "" {
			return app, nil
		}
	}
	return config.App{}, nil
}

func (k *KubernetesService) getLabelsFromGVR(gvr schema.GroupVersionResource, appDomain string) (config.App, error) {
	ctx, cancel := context.WithTimeout(k.ctx, 10*time.Second)
	defer cancel()

	list, err := k.client.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return config.App{}, err
	}

	// Update cache with all ingresses from this list
	k.updateFromList(list.Items)
	tlog.App.Debug().Str("api", gvr.GroupVersion().String()).Int("count", len(list.Items)).Msg("Updated cache from list")

	// Search for matching app
	for _, item := range list.Items {
		annotations := item.GetAnnotations()
		if annotations == nil {
			continue
		}
		labels, err := decoders.DecodeLabels[config.Apps](annotations, "apps")
		if err != nil {
			tlog.App.Debug().Err(err).Msg("Failed to decode labels from annotations")
			continue
		}
		for appName, appLabels := range labels.Apps {
			if appLabels.Config.Domain == appDomain {
				tlog.App.Debug().Str("name", item.GetName()).Str("namespace", item.GetNamespace()).Msg("Found matching ingress by domain")
				return appLabels, nil
			}
			if strings.SplitN(appDomain, ".", 2)[0] == appName {
				tlog.App.Debug().Str("name", item.GetName()).Str("namespace", item.GetNamespace()).Msg("Found matching ingress by app name")
				return appLabels, nil
			}
		}
	}
	return config.App{}, nil
}

// watchIngressV1 starts watching networking.k8s.io/v1 ingresses
func (k *KubernetesService) watchIngressV1() {
	if k.v1GVR == nil {
		return
	}
	k.watchGVR(*k.v1GVR)
}

// watchIngressV1beta1 starts watching extensions/v1beta1 ingresses
func (k *KubernetesService) watchIngressV1beta1() {
	if k.v1beta1GVR == nil {
		return
	}
	k.watchGVR(*k.v1beta1GVR)
}
