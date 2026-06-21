package kmssecret

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/hanzokms/kubernetes-operator/api/v1alpha1"
	"github.com/hanzokms/kubernetes-operator/internal/config"
	"github.com/hanzokms/kubernetes-operator/internal/util"
	"github.com/go-logr/logr"
	k8Errors "k8s.io/apimachinery/pkg/api/errors"
)

type KMSSecretHandler struct {
	client.Client
	Scheme            *runtime.Scheme
	IsNamespaceScoped bool
}

func NewKMSSecretHandler(client client.Client, scheme *runtime.Scheme, isNamespaceScoped bool) *KMSSecretHandler {
	return &KMSSecretHandler{
		Client:            client,
		Scheme:            scheme,
		IsNamespaceScoped: isNamespaceScoped,
	}
}

func (h *KMSSecretHandler) SetupAPIConfig(kmsSecret v1alpha1.KMSSecret, kmsGlobalConfig config.KMSGlobalConfig) error {
	if kmsSecret.Spec.HostAPI == "" {
		config.API_HOST_URL = kmsGlobalConfig.HostAPI
	} else {
		config.API_HOST_URL = util.AppendAPIEndpoint(kmsSecret.Spec.HostAPI)
	}
	return nil
}

func (h *KMSSecretHandler) getKMSCaCertificateFromKubeSecret(ctx context.Context, caRef v1alpha1.CaReference) (caCertificate string, err error) {

	caCertificateFromKubeSecret, err := util.GetKubeSecretByNamespacedName(ctx, h.Client, types.NamespacedName{
		Namespace: caRef.SecretNamespace,
		Name:      caRef.SecretName,
	})

	if k8Errors.IsNotFound(err) {
		return "", fmt.Errorf("kubernetes secret containing custom CA certificate cannot be found. [err=%s]", err)
	}

	if err != nil {
		if util.IsNamespaceScopedError(err, h.IsNamespaceScoped) {
			return "", fmt.Errorf("unable to fetch Kubernetes CA certificate secret. Your Operator installation is namespace scoped, and cannot read secrets outside of the namespace it is installed in. Please ensure the CA certificate secret is in the same namespace as the operator. [err=%v]", err)
		}
		return "", fmt.Errorf("something went wrong when fetching your CA certificate [err=%s]", err)
	}

	caCertificateFromSecret := string(caCertificateFromKubeSecret.Data[caRef.SecretKey])

	return caCertificateFromSecret, nil
}

func (h *KMSSecretHandler) HandleCACertificate(ctx context.Context, kmsSecret v1alpha1.KMSSecret, globalTlsConfig *v1alpha1.TLSConfig) error {
	if kmsSecret.Spec.TLS.CaRef.SecretName != "" {
		caCert, err := h.getKMSCaCertificateFromKubeSecret(ctx, kmsSecret.Spec.TLS.CaRef)
		if err != nil {
			return err
		}
		config.API_CA_CERTIFICATE = caCert
	} else if globalTlsConfig != nil {
		caCert, err := h.getKMSCaCertificateFromKubeSecret(ctx, globalTlsConfig.CaRef)
		if err != nil {
			return err
		}
		config.API_CA_CERTIFICATE = caCert
	} else {
		config.API_CA_CERTIFICATE = ""
	}
	return nil
}

func (h *KMSSecretHandler) ReconcileKMSSecret(ctx context.Context, logger logr.Logger, kmsSecret *v1alpha1.KMSSecret, managedKubeSecretReferences []v1alpha1.ManagedKubeSecretConfig, managedKubeConfigMapReferences []v1alpha1.ManagedKubeConfigMapConfig, resourceVariablesMap map[string]util.ResourceVariables) (int, error) {
	reconciler := &KMSSecretReconciler{
		Client:            h.Client,
		Scheme:            h.Scheme,
		IsNamespaceScoped: h.IsNamespaceScoped,
	}
	return reconciler.ReconcileKMSSecret(ctx, logger, kmsSecret, managedKubeSecretReferences, managedKubeConfigMapReferences, resourceVariablesMap)
}

func (h *KMSSecretHandler) SetReadyToSyncSecretsConditions(ctx context.Context, logger logr.Logger, kmsSecret *v1alpha1.KMSSecret, secretsCount int, errorToConditionOn error) {
	reconciler := &KMSSecretReconciler{
		Client:            h.Client,
		Scheme:            h.Scheme,
		IsNamespaceScoped: h.IsNamespaceScoped,
	}
	reconciler.SetReadyToSyncSecretsConditions(ctx, logger, kmsSecret, secretsCount, errorToConditionOn)
}

func (h *KMSSecretHandler) SetKMSAutoRedeploymentReady(ctx context.Context, logger logr.Logger, kmsSecret *v1alpha1.KMSSecret, numDeployments int, errorToConditionOn error) {
	reconciler := &KMSSecretReconciler{
		Client:            h.Client,
		Scheme:            h.Scheme,
		IsNamespaceScoped: h.IsNamespaceScoped,
	}
	reconciler.SetKMSAutoRedeploymentReady(ctx, logger, kmsSecret, numDeployments, errorToConditionOn)
}

func (h *KMSSecretHandler) CloseInstantUpdatesStream(ctx context.Context, logger logr.Logger, kmsSecret *v1alpha1.KMSSecret, resourceVariablesMap map[string]util.ResourceVariables) error {
	reconciler := &KMSSecretReconciler{
		Client:            h.Client,
		Scheme:            h.Scheme,
		IsNamespaceScoped: h.IsNamespaceScoped,
	}
	return reconciler.CloseInstantUpdatesStream(ctx, logger, kmsSecret, resourceVariablesMap)
}

// Ensures that SSE stream is open, incase if the stream is already opened - this is a noop
func (h *KMSSecretHandler) OpenInstantUpdatesStream(ctx context.Context, logger logr.Logger, kmsSecret *v1alpha1.KMSSecret, resourceVariablesMap map[string]util.ResourceVariables, eventCh chan<- event.TypedGenericEvent[client.Object]) error {
	reconciler := &KMSSecretReconciler{
		Client:            h.Client,
		Scheme:            h.Scheme,
		IsNamespaceScoped: h.IsNamespaceScoped,
	}
	return reconciler.OpenInstantUpdatesStream(ctx, logger, kmsSecret, resourceVariablesMap, eventCh)
}
