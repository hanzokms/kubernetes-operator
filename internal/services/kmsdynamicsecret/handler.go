package kmsdynamicsecret

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/hanzokms/kubernetes-operator/api/v1alpha1"
	"github.com/hanzokms/kubernetes-operator/internal/config"
	"github.com/hanzokms/kubernetes-operator/internal/util"
	"github.com/go-logr/logr"
	k8Errors "k8s.io/apimachinery/pkg/api/errors"
)

type KMSDynamicSecretHandler struct {
	client.Client
	Scheme            *runtime.Scheme
	Random            *rand.Rand
	IsNamespaceScoped bool
}

func NewKMSDynamicSecretHandler(client client.Client, scheme *runtime.Scheme, isNamespaceScoped bool) *KMSDynamicSecretHandler {
	return &KMSDynamicSecretHandler{
		Client:            client,
		Scheme:            scheme,
		Random:            rand.New(rand.NewSource(time.Now().UnixNano())),
		IsNamespaceScoped: isNamespaceScoped,
	}
}

func (h *KMSDynamicSecretHandler) SetupAPIConfig(kmsDynamicSecret v1alpha1.KMSDynamicSecret, kmsGlobalConfig config.KMSGlobalConfig) error {
	if kmsDynamicSecret.Spec.HostAPI == "" {
		config.API_HOST_URL = kmsGlobalConfig.HostAPI
	} else {
		config.API_HOST_URL = util.AppendAPIEndpoint(kmsDynamicSecret.Spec.HostAPI)
	}
	return nil
}

func (h *KMSDynamicSecretHandler) getKMSCaCertificateFromKubeSecret(ctx context.Context, caRef v1alpha1.CaReference) (caCertificate string, err error) {

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

func (h *KMSDynamicSecretHandler) HandleCACertificate(ctx context.Context, kmsDynamicSecret v1alpha1.KMSDynamicSecret, globalTlsConfig *v1alpha1.TLSConfig) error {
	if kmsDynamicSecret.Spec.TLS.CaRef.SecretName != "" {
		caCert, err := h.getKMSCaCertificateFromKubeSecret(ctx, kmsDynamicSecret.Spec.TLS.CaRef)
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

func (h *KMSDynamicSecretHandler) ReconcileKMSDynamicSecret(ctx context.Context, logger logr.Logger, kmsDynamicSecret *v1alpha1.KMSDynamicSecret, resourceVariablesMap map[string]util.ResourceVariables) (time.Duration, error) {
	reconciler := &KMSDynamicSecretReconciler{
		Client:            h.Client,
		Scheme:            h.Scheme,
		Random:            h.Random,
		IsNamespaceScoped: h.IsNamespaceScoped,
	}
	return reconciler.ReconcileKMSDynamicSecret(ctx, logger, kmsDynamicSecret, resourceVariablesMap)
}

func (h *KMSDynamicSecretHandler) HandleLeaseRevocation(ctx context.Context, logger logr.Logger, kmsDynamicSecret *v1alpha1.KMSDynamicSecret, resourceVariablesMap map[string]util.ResourceVariables) error {
	reconciler := &KMSDynamicSecretReconciler{
		Client:            h.Client,
		Scheme:            h.Scheme,
		Random:            h.Random,
		IsNamespaceScoped: h.IsNamespaceScoped,
	}
	return reconciler.HandleLeaseRevocation(ctx, logger, kmsDynamicSecret, resourceVariablesMap)
}

func (h *KMSDynamicSecretHandler) SetReconcileConditionStatus(ctx context.Context, logger logr.Logger, kmsDynamicSecret *v1alpha1.KMSDynamicSecret, errorToConditionOn error) {
	reconciler := &KMSDynamicSecretReconciler{
		Client:            h.Client,
		Scheme:            h.Scheme,
		Random:            h.Random,
		IsNamespaceScoped: h.IsNamespaceScoped,
	}
	reconciler.SetReconcileConditionStatus(ctx, logger, kmsDynamicSecret, errorToConditionOn)
}

func (h *KMSDynamicSecretHandler) SetReconcileAutoRedeploymentConditionStatus(ctx context.Context, logger logr.Logger, kmsDynamicSecret *v1alpha1.KMSDynamicSecret, numDeployments int, errorToConditionOn error) {
	reconciler := &KMSDynamicSecretReconciler{
		Client:            h.Client,
		Scheme:            h.Scheme,
		Random:            h.Random,
		IsNamespaceScoped: h.IsNamespaceScoped,
	}
	reconciler.SetReconcileAutoRedeploymentConditionStatus(ctx, logger, kmsDynamicSecret, numDeployments, errorToConditionOn)
}
