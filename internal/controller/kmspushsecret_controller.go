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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	kmspushsecret "github.com/hanzokms/kubernetes-operator/internal/services/kmspushsecret"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	secretsv1alpha1 "github.com/hanzokms/kubernetes-operator/api/v1alpha1"
	"github.com/hanzokms/kubernetes-operator/internal/constants"
	"github.com/hanzokms/kubernetes-operator/internal/controllerhelpers"
	"github.com/hanzokms/kubernetes-operator/internal/util"
	"github.com/go-logr/logr"
)

// KMSPushSecretReconciler reconciles a KMSPushSecret object
type KMSPushSecretReconciler struct {
	client.Client
	BaseLogger        logr.Logger
	Scheme            *runtime.Scheme
	IsNamespaceScoped bool
}

var kmsPushSecretResourceVariablesMap map[string]util.ResourceVariables = make(map[string]util.ResourceVariables)

func (r *KMSPushSecretReconciler) GetLogger(req ctrl.Request) logr.Logger {
	return r.BaseLogger.WithValues("kmspushsecret", req.NamespacedName)
}

//+kubebuilder:rbac:groups=secrets.hanzo.ai,resources=kmspushsecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=secrets.hanzo.ai,resources=kmspushsecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=secrets.hanzo.ai,resources=kmspushsecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;delete
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;delete
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=list;watch;get;update
//+kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=pods,verbs=get;list
//+kubebuilder:rbac:groups="authentication.k8s.io",resources=tokenreviews,verbs=create
//+kubebuilder:rbac:groups="",resources=serviceaccounts/token,verbs=create
//+kubebuilder:rbac:groups=secrets.hanzo.ai,resources=clustergenerators,verbs=get;list;watch;create;update;patch;delete

func (r *KMSPushSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	logger := r.GetLogger(req)

	var kmsPushSecretCRD secretsv1alpha1.KMSPushSecret
	requeueTime := time.Minute // seconds

	err := r.Get(ctx, req.NamespacedName, &kmsPushSecretCRD)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("Hanzo KMS Push Secret CRD not found")
			// Initialize the business logic handler
			handler := kmspushsecret.NewKMSPushSecretHandler(r.Client, r.Scheme, r.IsNamespaceScoped)
			handler.DeleteManagedSecrets(ctx, logger, &kmsPushSecretCRD, kmsPushSecretResourceVariablesMap)

			return ctrl.Result{
				Requeue: false,
			}, nil
		} else {
			logger.Error(err, "Unable to fetch Hanzo KMS Push Secret CRD from cluster")
			return ctrl.Result{}, fmt.Errorf("unable to fetch Hanzo KMS Push Secret CRD from cluster: %w", err)
		}
	}

	// Add finalizer if it doesn't exist
	if !controllerutil.ContainsFinalizer(&kmsPushSecretCRD, constants.KMS_PUSH_SECRET_FINALIZER_NAME) {
		controllerutil.AddFinalizer(&kmsPushSecretCRD, constants.KMS_PUSH_SECRET_FINALIZER_NAME)
		if err := r.Update(ctx, &kmsPushSecretCRD); err != nil {
			return ctrl.Result{}, err
		}
		// Return early - the update will trigger a new reconcile with the fresh object "the object has been modified; please apply your changes to the latest version and try again"
		return ctrl.Result{}, nil
	}

	// Check if it's being deleted
	if !kmsPushSecretCRD.DeletionTimestamp.IsZero() {
		logger.Info("Handling deletion of KMSPushSecret")
		if controllerutil.ContainsFinalizer(&kmsPushSecretCRD, constants.KMS_PUSH_SECRET_FINALIZER_NAME) {
			// We remove finalizers before running deletion logic to be completely safe from stuck resources
			kmsPushSecretCRD.ObjectMeta.Finalizers = []string{}
			if err := r.Update(ctx, &kmsPushSecretCRD); err != nil {
				logger.Error(err, fmt.Sprintf("Error removing finalizers from KMSPushSecret %s", kmsPushSecretCRD.Name))
				return ctrl.Result{}, err
			}

			// Initialize the business logic handler
			handler := kmspushsecret.NewKMSPushSecretHandler(r.Client, r.Scheme, r.IsNamespaceScoped)

			if err := handler.DeleteManagedSecrets(ctx, logger, &kmsPushSecretCRD, kmsPushSecretResourceVariablesMap); err != nil {
				return ctrl.Result{}, err // Even if this fails, we still want to delete the CRD
			}

		}
		return ctrl.Result{}, nil
	}

	if kmsPushSecretCRD.Spec.Push.Secret == nil && kmsPushSecretCRD.Spec.Push.Generators == nil {
		logger.Info("No secret or generators found, skipping reconciliation. please define a source secret or generator")
		return ctrl.Result{}, nil
	}

	duration, err := util.ConvertIntervalToDuration(kmsPushSecretCRD.Spec.ResyncInterval)

	if err != nil {
		logger.Error(err, "unable to convert resync interval to duration")
		return ctrl.Result{}, fmt.Errorf("unable to convert resync interval to duration: %w", err)
	}
	requeueTime = duration

	if requeueTime != 0 {
		logger.Info(fmt.Sprintf("Manual re-sync interval set. Interval: %v", requeueTime))
	}

	// Check if the resource is already marked for deletion
	if kmsPushSecretCRD.GetDeletionTimestamp() != nil {
		return ctrl.Result{
			Requeue: false,
		}, nil
	}

	// Get modified/default config
	kmsGlobalConfig, err := controllerhelpers.GetKMSConfigMap(ctx, r.Client, r.IsNamespaceScoped)
	if err != nil {
		logger.Error(err, "unable to fetch kms-config")
		return ctrl.Result{}, err
	}

	// Initialize the business logic handler
	handler := kmspushsecret.NewKMSPushSecretHandler(r.Client, r.Scheme, r.IsNamespaceScoped)

	// Setup API configuration through business logic
	err = handler.SetupAPIConfig(kmsPushSecretCRD, kmsGlobalConfig)
	if err != nil {
		logger.Error(err, "unable to setup API configuration")
		return ctrl.Result{}, err
	}

	// Handle CA certificate through business logic
	err = handler.HandleCACertificate(ctx, kmsPushSecretCRD, kmsGlobalConfig.TLS)
	if err != nil {
		logger.Error(err, "unable to fetch CA certificate")
		return ctrl.Result{}, err
	}

	err = handler.ReconcileKMSPushSecret(ctx, logger, &kmsPushSecretCRD, kmsPushSecretResourceVariablesMap)
	handler.SetReconcileStatusCondition(ctx, &kmsPushSecretCRD, err)

	if err != nil {
		logger.Error(err, "unable to reconcile Hanzo KMS Push Secret")
		return ctrl.Result{}, err
	}

	// Sync again after the specified time
	if requeueTime != 0 {
		logger.Info(fmt.Sprintf("Operator will requeue after [%v]", requeueTime))
		return ctrl.Result{
			RequeueAfter: requeueTime,
		}, nil
	} else {
		logger.Info("Operator will reconcile on next spec change")
		return ctrl.Result{}, nil
	}
}

func (r *KMSPushSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Custom predicate that allows both spec changes and deletions
	specChangeOrDelete := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Only reconcile if spec/generation changed

			isSpecOrGenerationChange := e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()

			isAnnotationChange := false

			jsonOld, oldErr := json.Marshal(e.ObjectOld.GetAnnotations())
			jsonNew, newErr := json.Marshal(e.ObjectNew.GetAnnotations())

			if oldErr == nil && newErr == nil {
				isAnnotationChange = sha256.Sum256(jsonOld) != sha256.Sum256(jsonNew)
			}

			if isSpecOrGenerationChange || isAnnotationChange {
				if kmsPushSecretResourceVariablesMap != nil {
					if rv, ok := kmsPushSecretResourceVariablesMap[string(e.ObjectNew.GetUID())]; ok {
						rv.CancelCtx()
						delete(kmsPushSecretResourceVariablesMap, string(e.ObjectNew.GetUID()))
					}
				}
			}

			return isSpecOrGenerationChange || isAnnotationChange
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			// Always reconcile on deletion

			if kmsPushSecretResourceVariablesMap != nil {
				if rv, ok := kmsPushSecretResourceVariablesMap[string(e.Object.GetUID())]; ok {
					rv.CancelCtx()
					delete(kmsPushSecretResourceVariablesMap, string(e.Object.GetUID()))
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

	controllerManager := ctrl.NewControllerManagedBy(mgr).
		For(&secretsv1alpha1.KMSPushSecret{}, builder.WithPredicates(
			specChangeOrDelete,
		)).
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.findPushSecretsForSecret),
		)

	return controllerManager.Complete(r)
}

func (r *KMSPushSecretReconciler) findPushSecretsForSecret(ctx context.Context, o client.Object) []reconcile.Request {
	pushSecrets := &secretsv1alpha1.KMSPushSecretList{}
	if err := r.List(ctx, pushSecrets); err != nil {
		return []reconcile.Request{}
	}

	requests := []reconcile.Request{}
	for _, pushSecret := range pushSecrets.Items {
		if pushSecret.Spec.Push.Secret != nil &&
			pushSecret.Spec.Push.Secret.SecretName == o.GetName() &&
			pushSecret.Spec.Push.Secret.SecretNamespace == o.GetNamespace() {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      pushSecret.GetName(),
					Namespace: pushSecret.GetNamespace(),
				},
			})
		}

	}

	return requests
}
