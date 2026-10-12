package service

import (
	"context"
	"fmt"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/apis/tinyauth/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type KubernetesCRDInput struct {
	Log    *logger.Logger
	Ctx    context.Context
	Client kubernetes.Interface
}

type KubernetesCRDExtractor struct {
	log    *logger.Logger
	ctx    context.Context
	client kubernetes.Interface
}

func NewKubernetesCRDExtractor(i KubernetesCRDInput) *KubernetesCRDExtractor {
	return &KubernetesCRDExtractor{
		log:    i.Log,
		ctx:    i.Ctx,
		client: i.Client,
	}
}

func (k *KubernetesCRDExtractor) Extract(app *v1alpha1.Application) ExtractionResult {
	meta := &ResourceMeta{
		Typ:       ResourceTypeCRD,
		Name:      app.GetName(),
		Namespace: app.GetNamespace(),
	}

	if !ensureResourceMeta(meta) {
		k.log.App.Warn().Str("namespace", meta.Namespace).Str("name", meta.Name).Msg("Resource has no namespace or name, skipping")
		return ExtractionResult{}
	}

	if app.Spec.Config.Domain == "" {
		k.log.App.Warn().Str("name", meta.Name).Str("namespace", meta.Namespace).Msg("Application has no domain, skipping")
		return ExtractionResult{
			Meta: meta,
		}
	}

	if !ensureAscii(app.Spec.Config.Domain) {
		k.log.App.Warn().Str("name", meta.Name).Str("namespace", meta.Namespace).Str("domain", app.Spec.Config.Domain).Msg("Domain is invalid, skipping")
		return ExtractionResult{
			Meta: meta,
		}
	}

	// Convert the CRD to the internal representation.
	internalApp := app.Spec.ToInternalApp()

	if ref := app.Spec.Response.BasicAuth.PasswordSecretRef; ref != nil {
		ctx, cancel := context.WithTimeout(k.ctx, 10*time.Second)
		secret, err := k.client.CoreV1().Secrets(meta.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		cancel()

		missingKey := false
		if err == nil {
			if password, ok := secret.Data[ref.Key]; ok {
				internalApp.Response.BasicAuth.Password = string(password)
			} else {
				missingKey = true
				err = fmt.Errorf("key %q not found in Secret %q", ref.Key, ref.Name)
			}
		}

		optional := ref.Optional != nil && *ref.Optional
		if err != nil && !(optional && (missingKey || apierrors.IsNotFound(err))) {
			k.log.App.Warn().Err(err).
				Str("namespace", meta.Namespace).
				Str("name", meta.Name).
				Str("secret", ref.Name).
				Str("key", ref.Key).
				Msg("Failed to resolve basic auth password Secret, skipping")

			return ExtractionResult{Meta: meta}
		}
	}
	return ExtractionResult{
		Meta: meta,
		Apps: map[string]model.App{
			meta.Name: internalApp,
		},
	}
}
