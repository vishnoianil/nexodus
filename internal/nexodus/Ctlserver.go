package nexodus

import "go.uber.org/zap"

type CtlServer interface {
	GetSocketPath() string
	Logger() *zap.SugaredLogger
	GetReceiver() any
}
