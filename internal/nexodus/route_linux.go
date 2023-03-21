//go:build linux

package nexodus

import (
	"go.uber.org/zap"
)

// HandlePeerRoute when a new configuration is deployed, delete/add the peer allowedIPs
// TODO: remove dependency on logger.
func HandlePeerRoute(allowedIps []string, tunnelIface string, wgLocalAddress string, logger *zap.SugaredLogger) {
	for _, allowedIP := range allowedIps {
		routeExists, err := RouteExists(allowedIP)
		if err != nil {
			logger.Warnf("%v", err)
		}
		if !routeExists {
			if err := AddRoute(allowedIP, tunnelIface); err != nil {
				logger.Errorf("route add failed: %v", err)
			}
		}
	}
}

// HandlePeerRouteDelete when a peer is this handles route deletion
func HandlePeerRouteDelete(dev string, allowedIps []string, logger *zap.SugaredLogger) {
	for _, allowedIP := range allowedIps {
		routeExists, err := RouteExists(allowedIP)
		if !routeExists {
			continue
		}
		if err != nil {
			logger.Debug(err)
		}
		if routeExists {
			if err := DeleteRoute(allowedIP, dev); err != nil {
				logger.Debug(err)
			}
		}
	}
}
