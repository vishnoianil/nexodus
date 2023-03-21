//go:build windows

package nexodus

import (
	"go.uber.org/zap"
)

// handlePeerRoute when a new configuration is deployed, delete/add the peer allowedIPs
func HandlePeerRoute(allowedIps []string, tunnelIface string, wgLocalAddress string, logger *zap.SugaredLogger) {
	for _, allowedIP := range allowedIps {
		if err := AddRoute(allowedIP, tunnelIface); err != nil {
			logger.Debugf("route add failed: %v", err)
		}
	}
}

// HandlePeerRouteDelete when a peer is this handles route deletion
func HandlePeerRouteDelete(dev string, allowedIps []string, logger *zap.SugaredLogger) {
	// TODO: Windoze route lookups
	for _, allowedIP := range allowedIps {
		if err := DeleteRoute(allowedIP, dev); err != nil {
			logger.Debug(err)
		}
	}
}
