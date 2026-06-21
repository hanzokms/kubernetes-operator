package kmspushsecret

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hanzokms/kubernetes-operator/api/v1alpha1"
	"github.com/hanzokms/kubernetes-operator/internal/config"
	"github.com/hanzokms/kubernetes-operator/internal/util"
	"github.com/go-logr/logr"
	k8Errors "k8s.io/apimachinery/pkg/api/errors"
)

type KMSPushSecretHandler struct {
	client.Client
	Scheme            *runtime.Scheme
	IsNamespaceScoped bool
}

func NewKMSPushSecretHandler(client client.Client, scheme *runtime.Scheme, isNamespaceScoped bool) *KMSPushSecretHandler {
	return &KMSPushSecretHandler{
		Client:            client,
		Scheme:            scheme,
		IsNamespaceScoped: isNamespaceScoped,
	}
}

func (h *KMSPushSecretHandler) SetupAPIConfig(kmsPushSecret v1alpha1.KMSPushSecret, kmsGlobalConfig config.KMSGlobalConfig) error {
	if kmsPushSecret.Spec.HostAPI == "" {
		config.API_HOST_URL = kmsGlobalConfig.HostAPI
	} else {
		config.API_HOST_URL = util.AppendAPIEndpoint(kmsPushSecret.Spec.HostAPI)
	}
	return nil
}

func (h *KMSPushSecretHandler) getKMSCaCertificateFromKubeSecret(ctx context.Context, caRef v1alpha1.CaReference) (caCertificate string, err error) {

	caCertificateFromKubeSecret, err := util.GetKubeSecretByNamespacedName(ctx, h.Client, types.NamespacedName{
		Namespace: caRef.SecretNamespace,
		Name:      caRef.SecretName,
	})

	if k8Errors.IsNotFound(err) {
		return "", fmt.Errorf("kubernetes secret containing custom CA certificate cannot be found. [err=%s]", err)
	}

	if util.IsNamespaceScopedError(err, h.IsNamespaceScoped) {
		return "", fmt.Errorf("unable to fetch Kubernetes CA certificate secret. Your Operator installation is namespace scoped, and cannot read secrets outside of the namespace it is installed in. Please ensure the CA certificate secret is in the same namespace as the operator. [err=%v]", err)
	}

	if err != nil {
		return "", fmt.Errorf("something went wrong when fetching your CA certificate [err=%s]", err)
	}

	caCertificateFromSecret := string(caCertificateFromKubeSecret.Data[caRef.SecretKey])

	return caCertificateFromSecret, nil
}

func (h *KMSPushSecretHandler) HandleCACertificate(ctx context.Context, kmsPushSecret v1alpha1.KMSPushSecret, globalTlsConfig *v1alpha1.TLSConfig) error {
	if kmsPushSecret.Spec.TLS.CaRef.SecretName != "" {
		caCert, err := h.getKMSCaCertificateFromKubeSecret(ctx, kmsPushSecret.Spec.TLS.CaRef)
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

func (h *KMSPushSecretHandler) ReconcileKMSPushSecret(ctx context.Context, logger logr.Logger, kmsPushSecret *v1alpha1.KMSPushSecret, resourceVariablesMap map[string]util.ResourceVariables) error {
	reconciler := &KMSPushSecretReconciler{
		Client:            h.Client,
		Scheme:            h.Scheme,
		IsNamespaceScoped: h.IsNamespaceScoped,
	}
	return reconciler.ReconcileKMSPushSecret(ctx, logger, kmsPushSecret, resourceVariablesMap)
}

func (h *KMSPushSecretHandler) DeleteManagedSecrets(ctx context.Context, logger logr.Logger, kmsPushSecret *v1alpha1.KMSPushSecret, resourceVariablesMap map[string]util.ResourceVariables) error {
	reconciler := &KMSPushSecretReconciler{
		Client:            h.Client,
		Scheme:            h.Scheme,
		IsNamespaceScoped: h.IsNamespaceScoped,
	}
	return reconciler.DeleteManagedSecrets(ctx, logger, kmsPushSecret, resourceVariablesMap)
}

func (h *KMSPushSecretHandler) SetReconcileStatusCondition(ctx context.Context, kmsPushSecret *v1alpha1.KMSPushSecret, err error) {
	reconciler := &KMSPushSecretReconciler{
		Client:            h.Client,
		Scheme:            h.Scheme,
		IsNamespaceScoped: h.IsNamespaceScoped,
	}
	reconciler.SetReconcileStatusCondition(ctx, kmsPushSecret, err)
}
