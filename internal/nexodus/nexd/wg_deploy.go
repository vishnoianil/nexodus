package nexd

import (
	"github.com/google/uuid"
	"github.com/nexodus-io/nexodus/internal/models"
	"github.com/nexodus-io/nexodus/internal/nexodus"
)

func (ax *Nexodus) DeployWireguardConfig(newPeers []models.Device, firstTime bool) error {
	cfg := &wgConfig{
		Interface: ax.wgConfig.Interface,
		Peers:     ax.wgConfig.Peers,
	}

	if ax.wgLocalAddress != nexodus.GetIPv4Iface(ax.tunnelIface).String() {
		if err := ax.setupInterface(); err != nil {
			return err
		}
	}

	// add routes and tunnels for all peer candidates without checking cache since it has not been built yet
	if firstTime {
		for _, peer := range cfg.Peers {
			nexodus.HandlePeerRoute(peer.AllowedIPs, ax.tunnelIface, ax.wgLocalAddress, ax.logger)
			nexodus.HandlePeerTunnel(peer, ax.tunnelIface, false, ax.logger)
		}
		return nil
	}

	// add routes and tunnels for the new peers only according to the cache diff
	for _, newPeer := range newPeers {
		if newPeer.ID != uuid.Nil {
			// add routes for each peer candidate (unless the key matches the local nodes key)
			for _, peer := range cfg.Peers {
				if peer.PublicKey == newPeer.PublicKey && newPeer.PublicKey != ax.wireguardPubKey {
					nexodus.HandlePeerRoute(peer.AllowedIPs, ax.tunnelIface, ax.wgLocalAddress, ax.logger)
					nexodus.HandlePeerTunnel(peer, ax.tunnelIface, false, ax.logger)
				}
			}
		}
	}

	ax.logger.Infof("Peer setup complete")
	return nil
}
