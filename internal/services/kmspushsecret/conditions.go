package kmspushsecret

import (
	"context"
	"fmt"

	"github.com/hanzokms/kubernetes-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (r *KMSPushSecretReconciler) SetReconcileStatusCondition(ctx context.Context, kmsPushSecret *v1alpha1.KMSPushSecret, err error) error {

	if kmsPushSecret.Status.Conditions == nil {
		kmsPushSecret.Status.Conditions = []metav1.Condition{}
	}

	if err != nil {
		meta.SetStatusCondition(&kmsPushSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/Reconcile",
			Status:  metav1.ConditionTrue,
			Reason:  "Error",
			Message: fmt.Sprintf("Reconcile failed, secrets were not pushed to Hanzo KMS. Error: %s", err.Error()),
		})
	} else {
		meta.SetStatusCondition(&kmsPushSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/Reconcile",
			Status:  metav1.ConditionFalse,
			Reason:  "OK",
			Message: "Reconcile succeeded, secrets were pushed to Hanzo KMS",
		})
	}

	return r.Client.Status().Update(ctx, kmsPushSecret)

}

func (r *KMSPushSecretReconciler) SetFailedToReplaceSecretsStatusCondition(ctx context.Context, kmsPushSecret *v1alpha1.KMSPushSecret, failMessage string) error {
	if kmsPushSecret.Status.Conditions == nil {
		kmsPushSecret.Status.Conditions = []metav1.Condition{}
	}

	if failMessage != "" {
		meta.SetStatusCondition(&kmsPushSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/FailedToReplaceSecrets",
			Status:  metav1.ConditionTrue,
			Reason:  "Error",
			Message: failMessage,
		})
	} else {
		meta.SetStatusCondition(&kmsPushSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/FailedToReplaceSecrets",
			Status:  metav1.ConditionFalse,
			Reason:  "OK",
			Message: "No errors, no secrets failed to be replaced in Hanzo KMS",
		})
	}

	return r.Client.Status().Update(ctx, kmsPushSecret)
}

func (r *KMSPushSecretReconciler) SetFailedToCreateSecretsStatusCondition(ctx context.Context, kmsPushSecret *v1alpha1.KMSPushSecret, failMessage string) error {
	if kmsPushSecret.Status.Conditions == nil {
		kmsPushSecret.Status.Conditions = []metav1.Condition{}
	}

	if failMessage != "" {
		meta.SetStatusCondition(&kmsPushSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/FailedToCreateSecrets",
			Status:  metav1.ConditionTrue,
			Reason:  "Error",
			Message: failMessage,
		})
	} else {
		meta.SetStatusCondition(&kmsPushSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/FailedToCreateSecrets",
			Status:  metav1.ConditionFalse,
			Reason:  "OK",
			Message: "No errors encountered, no secrets failed to be created in Hanzo KMS",
		})
	}

	return r.Client.Status().Update(ctx, kmsPushSecret)
}

func (r *KMSPushSecretReconciler) SetFailedToUpdateSecretsStatusCondition(ctx context.Context, kmsPushSecret *v1alpha1.KMSPushSecret, failMessage string) error {
	if kmsPushSecret.Status.Conditions == nil {
		kmsPushSecret.Status.Conditions = []metav1.Condition{}
	}

	if failMessage != "" {
		meta.SetStatusCondition(&kmsPushSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/FailedToUpdateSecrets",
			Status:  metav1.ConditionTrue,
			Reason:  "Error",
			Message: failMessage,
		})
	} else {
		meta.SetStatusCondition(&kmsPushSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/FailedToUpdateSecrets",
			Status:  metav1.ConditionFalse,
			Reason:  "OK",
			Message: "No errors encountered, no secrets failed to be updated in Hanzo KMS",
		})
	}

	return r.Client.Status().Update(ctx, kmsPushSecret)
}

func (r *KMSPushSecretReconciler) SetFailedToDeleteSecretsStatusCondition(ctx context.Context, kmsPushSecret *v1alpha1.KMSPushSecret, failMessage string) error {
	if kmsPushSecret.Status.Conditions == nil {
		kmsPushSecret.Status.Conditions = []metav1.Condition{}
	}

	if failMessage != "" {
		meta.SetStatusCondition(&kmsPushSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/FailedToDeleteSecrets",
			Status:  metav1.ConditionTrue,
			Reason:  "Error",
			Message: failMessage,
		})
	} else {
		meta.SetStatusCondition(&kmsPushSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/FailedToDeleteSecrets",
			Status:  metav1.ConditionFalse,
			Reason:  "OK",
			Message: "No errors encountered, no secrets failed to be deleted",
		})
	}

	return r.Client.Status().Update(ctx, kmsPushSecret)
}

func (r *KMSPushSecretReconciler) SetAuthenticatedStatusCondition(ctx context.Context, kmsPushSecret *v1alpha1.KMSPushSecret, errorToConditionOn error) error {
	if kmsPushSecret.Status.Conditions == nil {
		kmsPushSecret.Status.Conditions = []metav1.Condition{}
	}

	if errorToConditionOn != nil {
		meta.SetStatusCondition(&kmsPushSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/Authenticated",
			Status:  metav1.ConditionFalse,
			Reason:  "Error",
			Message: "Failed to authenticate with Hanzo KMS API. This can be caused by invalid service token or an invalid API host that is set. Check operator logs for more info",
		})
	} else {
		meta.SetStatusCondition(&kmsPushSecret.Status.Conditions, metav1.Condition{
			Type:    "secrets.hanzo.ai/Authenticated",
			Status:  metav1.ConditionTrue,
			Reason:  "OK",
			Message: "Successfully authenticated with Hanzo KMS API",
		})
	}

	return r.Client.Status().Update(ctx, kmsPushSecret)
}
