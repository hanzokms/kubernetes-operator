/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	defaultErrors "errors"

	kmssecret "github.com/hanzokms/kubernetes-operator/internal/services/kmssecret"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	secretsv1alpha1 "github.com/hanzokms/kubernetes-operator/api/v1alpha1"
	"github.com/hanzokms/kubernetes-operator/internal/controllerhelpers"
	"github.com/hanzokms/kubernetes-operator/internal/util"
	"github.com/go-logr/logr"
)

const DEFAULT_RESYNC_INTERVAL = time.Minute
const DEFAULT_RESYNC_INTERVAL_WITH_INSTANT_UPDATES = time.Hour

// KMSSecretReconciler reconciles a KMSSecret object
type KMSSecretReconciler struct {
	client.Client
	BaseLogger logr.Logger
	Scheme     *runtime.Scheme

	SourceCh          chan event.TypedGenericEvent[client.Object]
	IsNamespaceScoped bool
}

var kmsSecretResourceVariablesMap map[string]util.ResourceVariables = make(map[string]util.ResourceVariables)

func (r *KMSSecretReconciler) GetLogger(req ctrl.Request) logr.Logger {
	return r.BaseLogger.WithValues("kmssecret", req.NamespacedName)
}

//+kubebuilder:rbac:groups=kms.hanzo.ai,resources=kmssecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=kms.hanzo.ai,resources=kmssecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=kms.hanzo.ai,resources=kmssecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;delete
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;delete
//+kubebuilder:rbac:groups=apps,resources=deployments;daemonsets;statefulsets,verbs=list;watch;get;update
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list
//+kubebuilder:rbac:groups="authentication.k8s.io",resources=tokenreviews,verbs=create
//+kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the KMSSecret object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *KMSSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.GetLogger(req)

	var kmsSecretCRD secretsv1alpha1.KMSSecret

	err := r.Get(ctx, req.NamespacedName, &kmsSecretCRD)
	if err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{
				Requeue: false,
			}, nil
		} else {
			logger.Error(err, "unable to fetch Hanzo KMS Secret CRD from cluster")
			return ctrl.Result{}, fmt.Errorf("unable to fetch Hanzo KMS Secret CRD from cluster: %w", err)
		}
	}

	// It's important we don't directly modify the CRD object, so we create a copy of it and move existing data into it.
	managedKubeSecretReferences := kmsSecretCRD.Spec.ManagedKubeSecretReferences
	managedKubeConfigMapReferences := kmsSecretCRD.Spec.ManagedKubeConfigMapReferences

	if kmsSecretCRD.Spec.ManagedSecretReference.SecretName != "" && managedKubeSecretReferences != nil && len(managedKubeSecretReferences) > 0 {
		errMessage := "KMSSecret CRD cannot have both managedSecretReference and managedKubeSecretReferences"
		logger.Error(defaultErrors.New(errMessage), errMessage)
		return ctrl.Result{}, defaultErrors.New(errMessage)
	}

	if kmsSecretCRD.Spec.ManagedSecretReference.SecretName != "" {
		logger.Info("\n\n\nThe field `managedSecretReference` will be deprecated in the near future, please use `managedKubeSecretReferences` instead.\n\nRefer to the documentation for more information: https://hanzo.ai/docs/integrations/platforms/kubernetes/kms-secret-crd\n\n\n")

		if managedKubeSecretReferences == nil {
			managedKubeSecretReferences = []secretsv1alpha1.ManagedKubeSecretConfig{}
		}
		managedKubeSecretReferences = append(managedKubeSecretReferences, kmsSecretCRD.Spec.ManagedSecretReference)
	}

	if len(managedKubeSecretReferences) == 0 && len(managedKubeConfigMapReferences) == 0 {
		errMessage := "KMSSecret CRD must have at least one managed secret reference set in the `managedKubeSecretReferences` or `managedKubeConfigMapReferences` field"
		logger.Error(defaultErrors.New(errMessage), errMessage)
		return ctrl.Result{}, defaultErrors.New(errMessage)
	}

	// Remove finalizers if they exist. This is to support previous KMSSecret CRD's that have finalizers on them.
	// In order to delete secrets with finalizers, we first remove the finalizers so we can use the simplified and improved deletion process
	if !kmsSecretCRD.ObjectMeta.DeletionTimestamp.IsZero() && len(kmsSecretCRD.ObjectMeta.Finalizers) > 0 {
		kmsSecretCRD.ObjectMeta.Finalizers = []string{}
		if err := r.Update(ctx, &kmsSecretCRD); err != nil {
			logger.Error(err, fmt.Sprintf("Error removing finalizers from Hanzo KMS Secret %s", kmsSecretCRD.Name))
			return ctrl.Result{}, err
		}
		// Our finalizers have been removed, so the reconciler can do nothing.
		return ctrl.Result{}, nil
	}

	syncConfig := kmsSecretCRD.Spec.SyncConfig
	var requeueTime time.Duration

	if syncConfig == nil {
		syncConfig = &secretsv1alpha1.KMSSecretSyncConfig{
			ResyncInterval: fmt.Sprintf("%ds", kmsSecretCRD.Spec.ResyncInterval),
			InstantUpdates: kmsSecretCRD.Spec.InstantUpdates,
		}

		logger.Info("\n\n\nThe fields `instantUpdates` and `resyncInterval` are deprecated. Please use `syncConfig.instantUpdates` and `syncConfig.resyncInterval` instead.\n\nRefer to the documentation for more information: https://hanzo.ai/docs/integrations/platforms/kubernetes/kms-secret-crd\n\n\n")

	}

	// Determine the default resync interval based on InstantUpdates setting
	defaultResyncInterval := DEFAULT_RESYNC_INTERVAL
	if syncConfig.InstantUpdates {
		defaultResyncInterval = DEFAULT_RESYNC_INTERVAL_WITH_INSTANT_UPDATES
	}

	// Check if ResyncInterval was explicitly provided
	resyncIntervalProvided := syncConfig.ResyncInterval != "" && syncConfig.ResyncInterval != "0s"

	if resyncIntervalProvided {
		if duration, err := util.ConvertResyncIntervalToDuration(syncConfig.ResyncInterval, true); err == nil {
			if duration != 0 {
				requeueTime = duration
				logger.Info(fmt.Sprintf("resync interval set from syncConfig. interval: %v", requeueTime))
			} else {
				// Parsed to 0, use default based on InstantUpdates
				logger.Info(fmt.Sprintf("resync interval set to 0, using default of %v", defaultResyncInterval))
				requeueTime = defaultResyncInterval
			}
		} else {
			// Failed to parse the resync interval
			logger.Error(err, fmt.Sprintf("failed to parse resync interval from syncConfig, using default of %v. [err=%v]", defaultResyncInterval, err))
			requeueTime = defaultResyncInterval
		}
	} else {
		// ResyncInterval not provided, use default based on InstantUpdates
		logger.Info(fmt.Sprintf("resync interval not provided, using default of %v (instantUpdates=%v)", defaultResyncInterval, syncConfig.InstantUpdates))
		requeueTime = defaultResyncInterval
	}

	// Check if the resource is already marked for deletion
	if kmsSecretCRD.GetDeletionTimestamp() != nil {
		return ctrl.Result{
			Requeue: false,
		}, nil
	}

	// Get modified/default config
	kmsGlobalConfig, err := controllerhelpers.GetKMSConfigMap(ctx, r.Client, r.IsNamespaceScoped)
	if err != nil {
		logger.Error(err, "unable to fetch kms-config")
		return ctrl.Result{}, fmt.Errorf("unable to fetch kms-config: %w", err)
	}

	// Initialize the business logic handler
	handler := kmssecret.NewKMSSecretHandler(r.Client, r.Scheme, r.IsNamespaceScoped)

	// Setup API configuration through business logic
	err = handler.SetupAPIConfig(kmsSecretCRD, kmsGlobalConfig)
	if err != nil {
		logger.Error(err, "unable to setup API configuration")
		return ctrl.Result{}, fmt.Errorf("unable to setup API configuration: %w", err)
	}

	// Handle CA certificate through business logic
	err = handler.HandleCACertificate(ctx, kmsSecretCRD, kmsGlobalConfig.TLS)
	if err != nil {
		logger.Error(err, "unable to handle CA certificate")
		return ctrl.Result{}, fmt.Errorf("unable to handle CA certificate: %w", err)
	}

	secretsCount, err := handler.ReconcileKMSSecret(ctx, logger, &kmsSecretCRD, managedKubeSecretReferences, managedKubeConfigMapReferences, kmsSecretResourceVariablesMap)
	handler.SetReadyToSyncSecretsConditions(ctx, logger, &kmsSecretCRD, secretsCount, err)

	if err != nil {
		logger.Error(err, "unable to reconcile KMSSecret")
		return ctrl.Result{}, fmt.Errorf("unable to reconcile KMSSecret: %w", err)
	}

	numDeployments, err := controllerhelpers.ReconcileDeploymentsWithMultipleManagedSecrets(ctx, r.Client, logger, managedKubeSecretReferences, r.IsNamespaceScoped)
	handler.SetKMSAutoRedeploymentReady(ctx, logger, &kmsSecretCRD, numDeployments, err)

	if err != nil {
		logger.Error(err, "unable to reconcile auto redeployment")
		return ctrl.Result{}, fmt.Errorf("unable to reconcile auto redeployment: %w", err)
	}

	if syncConfig.InstantUpdates {
		if err := handler.OpenInstantUpdatesStream(ctx, logger, &kmsSecretCRD, kmsSecretResourceVariablesMap, r.SourceCh); err != nil {
			// Log SSE errors but don't fail reconciliation - periodic resync will continue
			logger.Error(err, "instant updates stream failed, falling back to periodic sync only")
		} else {
			logger.Info("Instant updates are enabled")
		}
	} else {
		handler.CloseInstantUpdatesStream(ctx, logger, &kmsSecretCRD, kmsSecretResourceVariablesMap)
	}

	// Sync again after the specified time
	logger.Info(fmt.Sprintf("Successfully synced %d secrets. Operator will requeue after [%v]", secretsCount, requeueTime))
	return ctrl.Result{
		RequeueAfter: requeueTime,
	}, nil
}

func (r *KMSSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.SourceCh = make(chan event.TypedGenericEvent[client.Object])

	return ctrl.NewControllerManagedBy(mgr).
		WatchesRawSource(
			source.Channel[client.Object](r.SourceCh, &util.EnqueueDelayedEventHandler{Delay: time.Second * 10}),
		).
		For(&secretsv1alpha1.KMSSecret{}, builder.WithPredicates(predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				if e.ObjectOld.GetGeneration() == e.ObjectNew.GetGeneration() {
					return false // Skip reconciliation for status-only changes
				}

				if kmsSecretResourceVariablesMap != nil {
					if rv, ok := kmsSecretResourceVariablesMap[string(e.ObjectNew.GetUID())]; ok {
						// Explicit SSE cleanup before context cancellation
						if rv.ServerSentEvents != nil {
							rv.ServerSentEvents.Close()
						}
						rv.CancelCtx()
						delete(kmsSecretResourceVariablesMap, string(e.ObjectNew.GetUID()))
					}
				}
				return true
			},
			DeleteFunc: func(e event.DeleteEvent) bool {
				if kmsSecretResourceVariablesMap != nil {
					if rv, ok := kmsSecretResourceVariablesMap[string(e.Object.GetUID())]; ok {
						// Explicit SSE cleanup before context cancellation
						if rv.ServerSentEvents != nil {
							rv.ServerSentEvents.Close()
						}
						rv.CancelCtx()
						delete(kmsSecretResourceVariablesMap, string(e.Object.GetUID()))
					}
				}
				return true
			},
		})).Complete(r)

}
