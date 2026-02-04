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
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var _ = unstructured.Unstructured{}

type KubernetesService struct {
	client     dynamic.Interface
	ctx        context.Context
	cancel     context.CancelFunc
	started    bool
	v1GVR      *schema.GroupVersionResource
	v1beta1GVR *schema.GroupVersionResource
	mu         sync.RWMutex
	cache      map[string]config.App
}

func NewKubernetesService() *KubernetesService {
	return &KubernetesService{
		cache: make(map[string]config.App),
	}
}

func (k *KubernetesService) Init() error {
	var config *rest.Config
	var err error

	// Try in-cluster config first
	config, err = rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig
		kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			tlog.App.Debug().Err(err).Msg("Kubernetes not connected")
			k.started = false
			return nil
		}
	}

	client, err := dynamic.NewForConfig(config)
	if err != nil {
		tlog.App.Debug().Err(err).Msg("Failed to create Kubernetes client")
		k.started = false
		return nil
	}

	// Create discovery client to check available APIs
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		tlog.App.Debug().Err(err).Msg("Failed to create discovery client")
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
			// go k.watchIngressV1() // TODO: implement watcher
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
			// go k.watchIngressV1beta1() // TODO: implement watcher
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

// watchIngressV1 and watchIngressV1beta1 are placeholders for future watcher implementation
// func (k *KubernetesService) watchIngressV1() {}
// func (k *KubernetesService) watchIngressV1beta1() {}
