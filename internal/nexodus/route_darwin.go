//go:build darwin

package nexodus

import (
	"fmt"
	"net"
	
	"go.uber.org/zap"
)

// handlePeerRoute when a new configuration is deployed, delete/add the peer allowedIPs
func HandlePeerRoute(allowedIps []string, tunnelIface string, wgLocalAddress string, logger *zap.SugaredLogger) {
	// Darwin maps to a utunX address which needs to be discovered (currently hardcoded to utun8)
	devName, err := getInterfaceByIP(net.ParseIP(wgLocalAddress))
	if err != nil {
		logger.Debugf("failed to find the darwin interface with the address [ %s ] %v", wgLocalAddress, err)
	}
	// If child prefix split the two prefixes (host /32) and child prefix
	for _, allowedIP := range allowedIps {
		_, err := RunCommand("route", "-q", "-n", "delete", "-inet", allowedIP, "-interface", devName)
		if err != nil {
			logger.Debugf("no route deleted: %v", err)
		}
		if err := AddRoute(allowedIP, devName); err != nil {
			logger.Debugf("%v", err)
		}
	}

}

// handlePeerRoute when a peer is this handles route deletion
func HandlePeerRouteDelete(dev string, allowedIps []string, logger *zap.SugaredLogger) {
	for _, allowedIP := range allowedIps {
		if err := DeleteRoute(allowedIP, dev); err != nil {
			logger.Debug(err)
		}
	}

}

// getInterfaceByIP looks up an interface by the IP provided
func getInterfaceByIP(ip net.IP) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ifaceIP, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ifaceIP.Equal(ip) {
				return iface.Name, nil
			}
		}
	}

	return "", fmt.Errorf("no interface was found for the ip %s", ip)
}
