package util

import (
	"context"

	"github.com/hanzokms/kubernetes-operator/internal/util/sse"
	kmsSdk "github.com/hanzokms/go-sdk"
)

type ResourceVariables struct {
	KMSClient  kmsSdk.ClientInterface
	CancelCtx        context.CancelFunc
	AuthDetails      AuthenticationDetails
	ServerSentEvents *sse.ConnectionRegistry
}
