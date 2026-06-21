package kmsdynamicsecret

import (
	"context"
	"fmt"

	"github.com/hanzokms/kubernetes-operator/api/v1alpha1"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (r *KMSDynamicSecretReconciler) SetReconcileAutoRedeploymentConditionStatus(ctx context.Context, logger logr.Logger, kmsDynamicSecret *v1alpha1.KMSDynamicSecret, numDeployments int, errorToConditionOn error) {
	if kmsDynamicSecret.Status.Conditions == nil {
		kmsDynamicSecret.Status.Conditions = []metav1.Condition{}
	}

	if errorToConditionOn == nil {
		meta.SetStatusCondition(&kmsDynamicSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/AutoRedeployReady",
			Status:  metav1.ConditionTrue,
			Reason:  "OK",
			Message: fmt.Sprintf("Hanzo KMS has found %v deployments which are ready to be auto redeployed when dynamic secret lease changes", numDeployments),
		})
	} else {
		meta.SetStatusCondition(&kmsDynamicSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/AutoRedeployReady",
			Status:  metav1.ConditionFalse,
			Reason:  "Error",
			Message: fmt.Sprintf("Failed reconcile deployments because: %v", errorToConditionOn),
		})
	}

	err := r.Client.Status().Update(ctx, kmsDynamicSecret)
	if err != nil {
		logger.Error(err, "Could not set condition for AutoRedeployReady")
	}
}

func (r *KMSDynamicSecretReconciler) SetAuthenticatedConditionStatus(ctx context.Context, logger logr.Logger, kmsDynamicSecret *v1alpha1.KMSDynamicSecret, errorToConditionOn error) {
	if kmsDynamicSecret.Status.Conditions == nil {
		kmsDynamicSecret.Status.Conditions = []metav1.Condition{}
	}

	if errorToConditionOn == nil {
		meta.SetStatusCondition(&kmsDynamicSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/Authenticated",
			Status:  metav1.ConditionTrue,
			Reason:  "OK",
			Message: "Hanzo KMS has successfully authenticated with the Hanzo KMS API",
		})
	} else {
		meta.SetStatusCondition(&kmsDynamicSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/Authenticated",
			Status:  metav1.ConditionFalse,
			Reason:  "Error",
			Message: fmt.Sprintf("Failed to authenticate with Hanzo KMS API because: %v", errorToConditionOn),
		})
	}

	err := r.Client.Status().Update(ctx, kmsDynamicSecret)
	if err != nil {
		logger.Error(err, "Could not set condition for Authenticated")
	}
}

func (r *KMSDynamicSecretReconciler) SetLeaseRenewalConditionStatus(ctx context.Context, logger logr.Logger, kmsDynamicSecret *v1alpha1.KMSDynamicSecret, errorToConditionOn error) {
	if kmsDynamicSecret.Status.Conditions == nil {
		kmsDynamicSecret.Status.Conditions = []metav1.Condition{}
	}

	if errorToConditionOn == nil {
		meta.SetStatusCondition(&kmsDynamicSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/LeaseRenewal",
			Status:  metav1.ConditionTrue,
			Reason:  "OK",
			Message: "Hanzo KMS has successfully renewed the lease",
		})
	} else {
		meta.SetStatusCondition(&kmsDynamicSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/LeaseRenewal",
			Status:  metav1.ConditionFalse,
			Reason:  "Error",
			Message: fmt.Sprintf("Failed to renew the lease because: %v", errorToConditionOn),
		})
	}

	err := r.Client.Status().Update(ctx, kmsDynamicSecret)
	if err != nil {
		logger.Error(err, "Could not set condition for LeaseRenewal")
	}
}

func (r *KMSDynamicSecretReconciler) SetCreatedLeaseConditionStatus(ctx context.Context, logger logr.Logger, kmsDynamicSecret *v1alpha1.KMSDynamicSecret, errorToConditionOn error) {
	if kmsDynamicSecret.Status.Conditions == nil {
		kmsDynamicSecret.Status.Conditions = []metav1.Condition{}
	}

	if errorToConditionOn == nil {
		meta.SetStatusCondition(&kmsDynamicSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/LeaseCreated",
			Status:  metav1.ConditionTrue,
			Reason:  "OK",
			Message: "Hanzo KMS has successfully created the lease",
		})
	} else {
		meta.SetStatusCondition(&kmsDynamicSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/LeaseCreated",
			Status:  metav1.ConditionFalse,
			Reason:  "Error",
			Message: fmt.Sprintf("Failed to create the lease because: %v", errorToConditionOn),
		})
	}

	err := r.Client.Status().Update(ctx, kmsDynamicSecret)
	if err != nil {
		logger.Error(err, "Could not set condition for LeaseCreated")
	}
}

func (r *KMSDynamicSecretReconciler) SetReconcileConditionStatus(ctx context.Context, logger logr.Logger, kmsDynamicSecret *v1alpha1.KMSDynamicSecret, errorToConditionOn error) {
	if kmsDynamicSecret.Status.Conditions == nil {
		kmsDynamicSecret.Status.Conditions = []metav1.Condition{}
	}

	if errorToConditionOn == nil {
		meta.SetStatusCondition(&kmsDynamicSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/Reconcile",
			Status:  metav1.ConditionTrue,
			Reason:  "OK",
			Message: "Hanzo KMS has successfully reconciled the KMSDynamicSecret",
		})
	} else {
		meta.SetStatusCondition(&kmsDynamicSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/Reconcile",
			Status:  metav1.ConditionFalse,
			Reason:  "Error",
			Message: fmt.Sprintf("Failed to reconcile the KMSDynamicSecret because: %v", errorToConditionOn),
		})
	}

	err := r.Client.Status().Update(ctx, kmsDynamicSecret)
	if err != nil {
		logger.Error(err, "Could not set condition for Reconcile")
	}
}
