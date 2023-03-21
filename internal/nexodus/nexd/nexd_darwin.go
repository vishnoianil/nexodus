//go:build darwin

package nexd

import (
	"fmt"
	"go.uber.org/zap"
	
	"github.com/nexodus-io/nexodus/internal/nexodus"
)

func (ax *Nexodus) setupInterface() error {

	logger := ax.logger
	localAddress := ax.wgLocalAddress
	dev := ax.tunnelIface

	if nexodus.IfaceExists(logger, dev) {
		deleteDarwinIface(logger, dev)
	}

	_, err := nexodus.RunCommand("wireguard-go", dev)
	if err != nil {
		logger.Errorf("failed to create the %s interface: %v\n", dev, err)
		return fmt.Errorf("%w", nexodus.InterfaceErr)
	}

	_, err = nexodus.RunCommand("ifconfig", dev, "inet", localAddress, localAddress, "alias")
	if err != nil {
		logger.Errorf("failed to assign an address to the local osx interface: %v\n", err)
		return fmt.Errorf("%w", nexodus.InterfaceErr)
	}

	_, err = nexodus.RunCommand("ifconfig", dev, "up")
	if err != nil {
		logger.Errorf("failed to bring up the %s interface: %v\n", dev, err)
		return fmt.Errorf("%w", nexodus.InterfaceErr)
	}

	_, err = nexodus.RunCommand("wg", "set", dev, "private-key", nexodus.DarwinPrivateKeyFile)
	if err != nil {
		logger.Errorf("failed to start the wireguard listener: %v\n", err)
		return fmt.Errorf("%w", nexodus.InterfaceErr)
	}

	return nil
}

func (ax *Nexodus) removeExistingInterface() {
	if nexodus.IfaceExists(ax.logger, ax.tunnelIface) {
		deleteDarwinIface(ax.logger, ax.tunnelIface)
	}
}

// deleteDarwinIface delete the darwin userspace wireguard interface
func deleteDarwinIface(logger *zap.SugaredLogger, dev string) {
	tunSock := fmt.Sprintf("/var/run/wireguard/%s.sock", dev)
	_, err := nexodus.RunCommand("rm", "-f", tunSock)
	if err != nil {
		logger.Debugf("failed to delete darwin interface: %v", err)
	}
	// /var/run/wireguard/wg0.name doesn't currently exist since utun8 isn't mapped to wg0 (fails silently)
	wgName := fmt.Sprintf("/var/run/wireguard/%s.name", dev)
	_, err = nexodus.RunCommand("rm", "-f", wgName)
	if err != nil {
		logger.Debugf("failed to delete darwin interface: %v", err)
	}
}

func (ax *Nexodus) findLocalIP() (string, error) {
	return nexodus.DiscoverGenericIPv4(ax.logger, ax.controllerURL.Host, "443")
}
