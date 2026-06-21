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
	"math/rand"
	"time"

	kmsdynamicsecret "github.com/hanzokms/kubernetes-operator/internal/services/kmsdynamicsecret"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	secretsv1alpha1 "github.com/hanzokms/kubernetes-operator/api/v1alpha1"
	"github.com/hanzokms/kubernetes-operator/internal/constants"
	"github.com/hanzokms/kubernetes-operator/internal/controllerhelpers"
	"github.com/hanzokms/kubernetes-operator/internal/util"
	"github.com/go-logr/logr"
)

// KMSDynamicSecretReconciler reconciles a KMSDynamicSecret object
type KMSDynamicSecretReconciler struct {
	client.Client
	BaseLogger        logr.Logger
	Scheme            *runtime.Scheme
	Random            *rand.Rand
	IsNamespaceScoped bool
}

var kmsDynamicSecretsResourceVariablesMap map[string]util.ResourceVariables = make(map[string]util.ResourceVariables)

func (r *KMSDynamicSecretReconciler) GetLogger(req ctrl.Request) logr.Logger {
	return r.BaseLogger.WithValues("kmsdynamicsecret", req.NamespacedName)
}

// +kubebuilder:rbac:groups=kms.hanzo.ai,resources=kmsdynamicsecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kms.hanzo.ai,resources=kmsdynamicsecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kms.hanzo.ai,resources=kmsdynamicsecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=list;watch;get;update
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list
//+kubebuilder:rbac:groups="authentication.k8s.io",resources=tokenreviews,verbs=create
//+kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create

func (r *KMSDynamicSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	logger := r.GetLogger(req)

	var kmsDynamicSecretCRD secretsv1alpha1.KMSDynamicSecret
	requeueTime := time.Second * 5

	err := r.Get(ctx, req.NamespacedName, &kmsDynamicSecretCRD)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Hanzo KMS Dynamic Secret CRD not found")
			return ctrl.Result{
				Requeue: false,
			}, nil
		} else {
			logger.Error(err, "Unable to fetch Hanzo KMS Dynamic Secret CRD from cluster")
			return ctrl.Result{}, fmt.Errorf("unable to fetch Hanzo KMS Dynamic Secret CRD from cluster: %w", err)
		}
	}

	// Add finalizer if it doesn't exist
	if !controllerutil.ContainsFinalizer(&kmsDynamicSecretCRD, constants.KMS_DYNAMIC_SECRET_FINALIZER_NAME) {
		controllerutil.AddFinalizer(&kmsDynamicSecretCRD, constants.KMS_DYNAMIC_SECRET_FINALIZER_NAME)
		if err := r.Update(ctx, &kmsDynamicSecretCRD); err != nil {
			return ctrl.Result{}, err
		}
		// Return early - the update will trigger a new reconcile with the fresh object. We can only update the CRD once or we'll see "the object has been modified; please apply your changes to the latest version and try again"
		return ctrl.Result{}, nil
	}

	// Check if it's being deleted
	if !kmsDynamicSecretCRD.DeletionTimestamp.IsZero() {
		logger.Info("Handling deletion of KMSDynamicSecret")
		if controllerutil.ContainsFinalizer(&kmsDynamicSecretCRD, constants.KMS_DYNAMIC_SECRET_FINALIZER_NAME) {
			// We remove finalizers before running deletion logic to be completely safe from stuck resources
			kmsDynamicSecretCRD.ObjectMeta.Finalizers = []string{}
			if err := r.Update(ctx, &kmsDynamicSecretCRD); err != nil {
				logger.Error(err, fmt.Sprintf("Error removing finalizers from KMSDynamicSecret %s", kmsDynamicSecretCRD.Name))
				return ctrl.Result{}, err
			}

			// Initialize the business logic handler
			handler := kmsdynamicsecret.NewKMSDynamicSecretHandler(r.Client, r.Scheme, r.IsNamespaceScoped)

			err := handler.HandleLeaseRevocation(ctx, logger, &kmsDynamicSecretCRD, kmsDynamicSecretsResourceVariablesMap)

			if kmsDynamicSecretsResourceVariablesMap != nil {
				if rv, ok := kmsDynamicSecretsResourceVariablesMap[string(kmsDynamicSecretCRD.GetUID())]; ok {
					rv.CancelCtx()
					delete(kmsDynamicSecretsResourceVariablesMap, string(kmsDynamicSecretCRD.GetUID()))
				}
			}

			if err != nil {
				return ctrl.Result{}, err // Even if this fails, we still want to delete the CRD
			}

		}
		return ctrl.Result{}, nil
	}

	// Get modified/default config
	kmsGlobalConfig, err := controllerhelpers.GetKMSConfigMap(ctx, r.Client, r.IsNamespaceScoped)
	if err != nil {
		logger.Error(err, "unable to fetch kms-config")
		return ctrl.Result{}, fmt.Errorf("unable to fetch kms-config: %w", err)
	}

	// Initialize the business logic handler
	handler := kmsdynamicsecret.NewKMSDynamicSecretHandler(r.Client, r.Scheme, r.IsNamespaceScoped)

	// Setup API configuration through business logic
	err = handler.SetupAPIConfig(kmsDynamicSecretCRD, kmsGlobalConfig)
	if err != nil {
		logger.Error(err, "unable to setup API configuration")
		return ctrl.Result{}, fmt.Errorf("unable to setup API configuration: %w", err)
	}

	// Handle CA certificate through business logic
	err = handler.HandleCACertificate(ctx, kmsDynamicSecretCRD, kmsGlobalConfig.TLS)
	if err != nil {
		logger.Error(err, "unable to handle CA certificate")
		return ctrl.Result{}, fmt.Errorf("unable to handle CA certificate: %w", err)
	}

	nextReconcile, err := handler.ReconcileKMSDynamicSecret(ctx, logger, &kmsDynamicSecretCRD, kmsDynamicSecretsResourceVariablesMap)
	handler.SetReconcileConditionStatus(ctx, logger, &kmsDynamicSecretCRD, err)

	if err == nil && nextReconcile.Seconds() >= 5 {
		requeueTime = nextReconcile
	}

	if err != nil {
		logger.Error(err, "unable to reconcile Hanzo KMS Dynamic Secret")
		return ctrl.Result{}, fmt.Errorf("unable to reconcile Hanzo KMS Dynamic Secret: %w", err)
	}

	numDeployments, err := controllerhelpers.ReconcileDeploymentsWithManagedSecrets(ctx, r.Client, logger, kmsDynamicSecretCRD.Spec.ManagedSecretReference, r.IsNamespaceScoped)
	handler.SetReconcileAutoRedeploymentConditionStatus(ctx, logger, &kmsDynamicSecretCRD, numDeployments, err)

	if err != nil {
		logger.Error(err, "unable to reconcile auto redeployment")
		return ctrl.Result{}, fmt.Errorf("unable to reconcile auto redeployment: %w", err)
	}

	// Sync again after the specified time
	logger.Info(fmt.Sprintf("Next reconciliation in [requeueTime=%v]", requeueTime))
	return ctrl.Result{
		RequeueAfter: requeueTime,
	}, nil
}

func (r *KMSDynamicSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {

	// Custom predicate that allows both spec changes and deletions
	specChangeOrDelete := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Only reconcile if spec/generation changed

			isSpecOrGenerationChange := e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()

			if isSpecOrGenerationChange {
				if kmsDynamicSecretsResourceVariablesMap != nil {
					if rv, ok := kmsDynamicSecretsResourceVariablesMap[string(e.ObjectNew.GetUID())]; ok {
						rv.CancelCtx()
						delete(kmsDynamicSecretsResourceVariablesMap, string(e.ObjectNew.GetUID()))
					}
				}
			}

			return isSpecOrGenerationChange
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			// Always reconcile on deletion

			if kmsDynamicSecretsResourceVariablesMap != nil {
				if rv, ok := kmsDynamicSecretsResourceVariablesMap[string(e.Object.GetUID())]; ok {
					rv.CancelCtx()
					delete(kmsDynamicSecretsResourceVariablesMap, string(e.Object.GetUID()))
				}
			}

			return true
		},
		CreateFunc: func(e event.CreateEvent) bool {
			// Reconcile on creation
			return true
		},
		GenericFunc: func(e event.GenericEvent) bool {
			// Ignore generic events
			return false
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.KMSDynamicSecret{}, builder.WithPredicates(
			specChangeOrDelete,
		)).
		Complete(r)
}
