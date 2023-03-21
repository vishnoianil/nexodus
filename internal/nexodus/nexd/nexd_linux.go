//go:build linux

package nexd

import (
	"fmt"
	"strconv"

	"github.com/nexodus-io/nexodus/internal/nexodus"
)

// setupLinuxInterface TODO replace with netlink calls
// this is called if this is the first run or if the local node
// address got assigned a new address by the controller
func (ax *Nexodus) setupInterface() error {

	logger := ax.logger
	// delete the wireguard ip link interface if it exists
	if nexodus.IfaceExists(logger, ax.tunnelIface) {
		_, err := nexodus.RunCommand("ip", "link", "del", ax.tunnelIface)
		if err != nil {
			logger.Debugf("failed to delete the ip link interface: %v\n", err)
		}
	}
	// create the wireguard ip link interface
	_, err := nexodus.RunCommand("ip", "link", "add", ax.tunnelIface, "type", "wireguard")
	if err != nil {
		logger.Errorf("failed to create the ip link interface: %v\n", err)
		return fmt.Errorf("%w", nexodus.InterfaceErr)
	}

	// start the wireguard listener
	_, err = nexodus.RunCommand("wg", "set", ax.tunnelIface, "listen-port", strconv.Itoa(ax.listenPort), "private-key", nexodus.LinuxPrivateKeyFile)
	if err != nil {
		logger.Errorf("failed to start the wireguard listener: %v\n", err)
		return fmt.Errorf("%w", nexodus.InterfaceErr)
	}

	// give the wg interface an address
	_, err = nexodus.RunCommand("ip", "address", "add", ax.wgLocalAddress, "dev", ax.tunnelIface)
	if err != nil {
		logger.Debugf("failed to assign an address to the local linux interface, attempting to flush the iface: %v\n", err)
		wgIP := nexodus.GetIPv4Iface(ax.tunnelIface)
		_, err = nexodus.RunCommand("ip", "address", "del", wgIP.To4().String(), "dev", ax.tunnelIface)
		if err != nil {
			logger.Errorf("failed to assign an address to the local linux interface: %v\n", err)
		}
		_, err = nexodus.RunCommand("ip", "address", "add", ax.wgLocalAddress, "dev", ax.tunnelIface)
		if err != nil {
			logger.Errorf("failed to assign an address to the local linux interface: %v\n", err)
			return fmt.Errorf("%w", nexodus.InterfaceErr)
		}
	}
	// bring the wg0 interface up
	_, err = nexodus.RunCommand("ip", "link", "set", ax.tunnelIface, "up")
	if err != nil {
		logger.Errorf("failed to bring up the wg interface: %v\n", err)
		return fmt.Errorf("%w", nexodus.InterfaceErr)
	}

	return nil
}

func (ax *Nexodus) removeExistingInterface() {
	if nexodus.LinkExists(ax.tunnelIface) {
		if err := nexodus.DelLink(ax.tunnelIface); err != nil {
			// not a fatal error since if this is on startup it could be absent
			ax.logger.Debugf("failed to delete netlink interface %s: %v", ax.tunnelIface, err)
		}
	}
}

func (ax *Nexodus) findLocalIP() (string, error) {

	// Linux network discovery
	linuxIP, err := nexodus.DiscoverLinuxAddress(ax.logger, 4)
	if err != nil {
		return "", err
	}
	return linuxIP.String(), nil
}
