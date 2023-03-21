package nexrelay

import (
	"net"
	"runtime"

	"github.com/nexodus-io/nexodus/internal/nexodus"
)

// buildPeersConfig builds the peer configuration based off peer cache and peer listings from the controller
func (nexr *Nexrelay) buildPeersConfig() {

	var peers []nexodus.WgPeerConfig
	var relayIP string
	//var localInterface wgLocalConfig
	var orgPrefix string
	var hubOrg bool
	var err error

	for _, device := range nexr.deviceCache {
		if device.PublicKey == nexr.wireguardPubKey {
			nexr.wireguardPubKeyInConfig = true
		}
		if device.Relay {
			relayIP = device.AllowedIPs[0]
			if nexr.organization == device.OrganizationID {
				orgPrefix = device.OrganizationPrefix
			}
		}
	}
	// orgPrefix will be empty if a hub-router is not defined in the organization
	if orgPrefix != "" {
		hubOrg = true
	}
	// if this is a org router but does not have a relay node joined yet throw an error
	if relayIP == "" && hubOrg {
		nexr.logger.Errorf("there is no hub router detected in this organization, please add one using `--hub-router`")
		return
	}

	if err != nil {
		nexr.logger.Errorf("invalid hub router network found: %v", err)
	}
	// map the peer list for the local node depending on the node's network
	for _, value := range nexr.deviceCache {
		_, peerPort, err := net.SplitHostPort(value.LocalIP)
		if err != nil {
			nexr.logger.Debugf("failed parse the endpoint address for node (likely still converging) : %v\n", err)
			continue
		}

		if value.PublicKey == nexr.wireguardPubKey {
			// we found ourself in the peer list
			continue
		}

		// Build the wg config for all peers if this node is the organization's hub-router.
		// Config if the node is a relay
		for _, prefix := range value.ChildPrefix {
			err = nexodus.AddChildPrefixRoute(prefix, nexr.tunnelIface); if err != nil {
				nexr.logger.Errorf("Error in adding child prefix route: %v\n", err)
			}
			value.AllowedIPs = append(value.AllowedIPs, prefix)
		}
		peer := nexodus.WgPeerConfig{
			PublicKey:           value.PublicKey,
			Endpoint:            value.LocalIP,
			AllowedIPs:          value.AllowedIPs,
			PersistentKeepAlive: nexodus.PersistentHubKeepalive,
		}
		peers = append(peers, peer)
		nexr.logger.Infof("Peer Node Configuration - Peer AllowedIPs [ %s ] Peer Endpoint IP [ %s ] Peer Public Key [ %s ] TunnelIP [ %s ] Organization [ %s ]",
			value.AllowedIPs,
			value.LocalIP,
			value.PublicKey,
			value.TunnelIP,
			value.OrganizationID)

		// If both nodes are local, peer them directly to one another via their local addresses (includes symmetric nat nodes)
		// The exception is if the peer is a relay node since that will get a peering with the org prefix supernet
		if nexr.nodeReflexiveAddress == value.ReflexiveIPv4 && !value.Relay {
			directLocalPeerEndpointSocket := net.JoinHostPort(value.EndpointLocalAddressIPv4, peerPort)
			nexr.logger.Debugf("ICE candidate match for local address peering is [ %s ] with a STUN Address of [ %s ]", directLocalPeerEndpointSocket, value.ReflexiveIPv4)
			// the symmetric NAT peer
			for _, prefix := range value.ChildPrefix {
				err = nexodus.AddChildPrefixRoute(prefix, nexr.tunnelIface); if err != nil {
					nexr.logger.Errorf("Error in adding child prefix route: %v\n", err)
				}
				value.AllowedIPs = append(value.AllowedIPs, prefix)
			}
			peer := nexodus.WgPeerConfig{
				PublicKey:           value.PublicKey,
				Endpoint:            directLocalPeerEndpointSocket,
				AllowedIPs:          value.AllowedIPs,
				PersistentKeepAlive: nexodus.PersistentKeepalive,
			}
			peers = append(peers, peer)
			nexr.logger.Infof("Peer Configuration - Peer AllowedIPs [ %s ] Peer Endpoint IP [ %s ] Peer Public Key [ %s ] TunnelIP [ %s ] Organization [ %s ]",
				value.AllowedIPs,
				directLocalPeerEndpointSocket,
				value.PublicKey,
				value.TunnelIP,
				value.OrganizationID)
		} else if !value.SymmetricNat && !value.Relay {
			// the bulk of the peers will be added here except for local address peers. Endpoint sockets added here are likely
			// to be changed from the state discovered by the relay node if peering with nodes with NAT in between.
			// if the node itself (nexr.symmetricNat) or the peer (value.SymmetricNat) is a
			// symmetric nat node, do not add peers as it will relay and not mesh
			for _, prefix := range value.ChildPrefix {
				err = nexodus.AddChildPrefixRoute(prefix, nexr.tunnelIface); if err != nil {
					nexr.logger.Errorf("Error in adding child prefix route: %v\n", err)
				}
				value.AllowedIPs = append(value.AllowedIPs, prefix)
			}
			peer := nexodus.WgPeerConfig{
				PublicKey:           value.PublicKey,
				Endpoint:            value.LocalIP,
				AllowedIPs:          value.AllowedIPs,
				PersistentKeepAlive: nexodus.PersistentKeepalive,
			}
			peers = append(peers, peer)
			nexr.logger.Infof("Peer Configuration - Peer AllowedIPs [ %s ] Peer Endpoint IP [ %s ] Peer Public Key [ %s ] TunnelIP [ %s ] Organization [ %s ]",
				value.AllowedIPs,
				value.LocalIP,
				value.PublicKey,
				value.TunnelIP,
				value.OrganizationID)
		}
	}
	nexr.wgConfig.Peers = peers
	nexr.buildLocalConfig()
}

// buildLocalConfig builds the configuration for the local interface
func (nexr *Nexrelay) buildLocalConfig() {
	var localInterface wgLocalConfig

	for _, value := range nexr.deviceCache {
		// build the local interface configuration if this node is a Organization router
		if value.PublicKey == nexr.wireguardPubKey {
			// if the local node address changed replace it on wg0
			if nexr.wgLocalAddress != value.TunnelIP {
				nexr.logger.Infof("New local Wireguard interface address assigned: %s", value.TunnelIP)
				if runtime.GOOS == nexodus.Linux.String() && nexodus.LinkExists(nexr.tunnelIface) {
					if err := nexodus.DelLink(nexr.tunnelIface); err != nil {
						nexr.logger.Infof("Failed to delete %s: %v", nexr.tunnelIface, err)
					}
				}
			}
			nexr.wgLocalAddress = value.TunnelIP
			localInterface = wgLocalConfig{
				nexr.wireguardPvtKey,
				nexr.listenPort,
			}
			nexr.logger.Debugf("Local Node Configuration - Wireguard IP [ %s ]", nexr.wgLocalAddress)
			// set the node unique local interface configuration
			nexr.wgConfig.Interface = localInterface
		}
	}
}
