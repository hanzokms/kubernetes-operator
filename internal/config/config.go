package config

import (
	"fmt"

	"github.com/hanzokms/kubernetes-operator/api/v1alpha1"
)

type KMSGlobalConfig struct {
	HostAPI string              `json:"hostAPI"`
	TLS     *v1alpha1.TLSConfig `json:"tls,omitempty"`
}

var API_HOST_URL string = "https://kms.hanzo.ai/api"
var API_CA_CERTIFICATE string = ""

func ParseKMSGlobalConfig(rawMap map[string]string) (KMSGlobalConfig, error) {
	config := KMSGlobalConfig{}

	if hostAPI, ok := rawMap["hostAPI"]; ok {
		config.HostAPI = hostAPI
	}

	secretName := rawMap["tls.caRef.secretName"]
	secretNamespace := rawMap["tls.caRef.secretNamespace"]
	secretKey := rawMap["tls.caRef.key"]

	if secretName != "" || secretNamespace != "" || secretKey != "" {
		if secretName == "" || secretNamespace == "" || secretKey == "" {
			return config, fmt.Errorf("when tls.caRef is configured in the kms-config, all fields must be set (secretName, secretNamespace, key)")
		}
		config.TLS = &v1alpha1.TLSConfig{
			CaRef: v1alpha1.CaReference{
				SecretName:      secretName,
				SecretNamespace: secretNamespace,
				SecretKey:       secretKey,
			},
		}
	}

	return config, nil
}
