package nexrelay

import (
	"github.com/google/uuid"
	"github.com/nexodus-io/nexodus/internal/models"
	"github.com/nexodus-io/nexodus/internal/nexodus"
)

const (
	// wg keepalives are disabled and managed by the agent
	PersistentKeepalive    = "0"
	PersistentHubKeepalive = "0"
)

func (nexr *Nexrelay) DeployWireguardConfig(newPeers []models.Device, firstTime bool) error {
	cfg := &wgConfig{
		Interface: nexr.wgConfig.Interface,
		Peers:     nexr.wgConfig.Peers,
	}

	if nexr.wgLocalAddress != nexodus.GetIPv4Iface(nexr.tunnelIface).String() {
		if err := nexr.setupInterface(); err != nil {
			return err
		}
	}

	// add routes and tunnels for all peer candidates without checking cache since it has not been built yet
	if firstTime {
		for _, peer := range cfg.Peers {
			nexodus.HandlePeerRoute(peer.AllowedIPs, nexr.tunnelIface, nexr.wgLocalAddress, nexr.logger)
			nexodus.HandlePeerTunnel(peer, nexr.tunnelIface, true, nexr.logger)
		}
		return nil
	}

	// add routes and tunnels for the new peers only according to the cache diff
	for _, newPeer := range newPeers {
		if newPeer.ID != uuid.Nil {
			// add routes for each peer candidate (unless the key matches the local nodes key)
			for _, peer := range cfg.Peers {
				if peer.PublicKey == newPeer.PublicKey && newPeer.PublicKey != nexr.wireguardPubKey {
					nexodus.HandlePeerRoute(peer.AllowedIPs, nexr.tunnelIface, nexr.wgLocalAddress, nexr.logger)
					nexodus.HandlePeerTunnel(peer, nexr.tunnelIface, true, nexr.logger)
				}
			}
		}
	}

	nexr.logger.Infof("Peer setup complete")
	return nil
}
