//go:build linux

package nexrelay

import (
	"fmt"
	"strconv"

	"github.com/nexodus-io/nexodus/internal/nexodus"
)

// setupLinuxInterface TODO replace with netlink calls
// this is called if this is the first run or if the local node
// address got assigned a new address by the controller
func (nexr *Nexrelay) setupInterface() error {

	logger := nexr.logger
	// delete the wireguard ip link interface if it exists
	if nexodus.IfaceExists(logger, nexr.tunnelIface) {
		_, err := nexodus.RunCommand("ip", "link", "del", nexr.tunnelIface)
		if err != nil {
			logger.Debugf("failed to delete the ip link interface: %v\n", err)
		}
	}
	// create the wireguard ip link interface
	_, err := nexodus.RunCommand("ip", "link", "add", nexr.tunnelIface, "type", "wireguard")
	if err != nil {
		logger.Errorf("failed to create the ip link interface: %v\n", err)
		return fmt.Errorf("%w", nexodus.InterfaceErr)
	}
	// start the wireguard listener on a well-known port if it is the hub-router as all
	// nodes need to be able to reach this node for state distribution if hole punching.
	_, err = nexodus.RunCommand("wg", "set", nexr.tunnelIface, "listen-port", strconv.Itoa(nexodus.WgDefaultPort), "private-key", nexodus.LinuxPrivateKeyFile)
	if err != nil {
		logger.Errorf("failed to start the wireguard listener: %v\n", err)
		return fmt.Errorf("%w", nexodus.InterfaceErr)
	}

	// give the wg interface an address
	_, err = nexodus.RunCommand("ip", "address", "add", nexr.wgLocalAddress, "dev", nexr.tunnelIface)
	if err != nil {
		logger.Debugf("failed to assign an address to the local linux interface, attempting to flush the iface: %v\n", err)
		wgIP := nexodus.GetIPv4Iface(nexr.tunnelIface)
		_, err = nexodus.RunCommand("ip", "address", "del", wgIP.To4().String(), "dev", nexr.tunnelIface)
		if err != nil {
			logger.Errorf("failed to assign an address to the local linux interface: %v\n", err)
		}
		_, err = nexodus.RunCommand("ip", "address", "add", nexr.wgLocalAddress, "dev", nexr.tunnelIface)
		if err != nil {
			logger.Errorf("failed to assign an address to the local linux interface: %v\n", err)
			return fmt.Errorf("%w", nexodus.InterfaceErr)
		}
	}
	// bring the wg0 interface up
	_, err = nexodus.RunCommand("ip", "link", "set", nexr.tunnelIface, "up")
	if err != nil {
		logger.Errorf("failed to bring up the wg interface: %v\n", err)
		return fmt.Errorf("%w", nexodus.InterfaceErr)
	}

	return nil
}

func (nexr *Nexrelay) removeExistingInterface() {
	if nexodus.LinkExists(nexr.tunnelIface) {
		if err := nexodus.DelLink(nexr.tunnelIface); err != nil {
			// not a fatal error since if this is on startup it could be absent
			nexr.logger.Debugf("failed to delete netlink interface %s: %v", nexr.tunnelIface, err)
		}
	}
}

func (nexr *Nexrelay) findLocalIP() (string, error) {

	// Linux network discovery
	linuxIP, err := nexodus.DiscoverLinuxAddress(nexr.logger, 4)
	if err != nil {
		return "", err
	}
	return linuxIP.String(), nil
}
