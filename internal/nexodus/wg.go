package nexodus

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/nexodus-io/nexodus/internal/models"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	wgBinary          = "wg"
	wgGoBinary        = "wireguard-go"
	wgWinBinary       = "wireguard.exe"
	WgLinuxConfPath   = "/etc/wireguard/"
	WgDarwinConfPath  = "/usr/local/etc/wireguard/"
	darwinIface       = "utun8"
	WgDefaultPort     = 51820
	wgIface           = "wg0"
	WgWindowsConfPath = "C:/wireguard/"
	WindowsConfFilePermissions = 0644
	WindowsWgConfigFile        = "C:/wireguard/wg0.conf"


	// wg keepalives are disabled and managed by the agent
	PersistentKeepalive    = "0"
	PersistentHubKeepalive = "0"
)

// handlePeerTunnel build wg tunnels
func HandlePeerTunnel(wgPeerConfig WgPeerConfig, tunnelIface string, relay bool, logger *zap.SugaredLogger) {
	// validate the endpoint host:port pair parses.
	// temporary: currently if relay state has not converged the endpoint can be registered as (none)
	_, _, err := net.SplitHostPort(wgPeerConfig.Endpoint)
	if err != nil {
		logger.Debugf("failed parse the endpoint address for node [ %s ] (likely still converging) : %v\n", wgPeerConfig.PublicKey, err)
		return
	}

	if err := addPeer(wgPeerConfig, tunnelIface, relay, logger); err != nil {
		logger.Errorf("peer tunnel addition failed: %v\n", err)
	}
}

// addPeer add a wg peer
func addPeer(wgPeerConfig WgPeerConfig, tunnelIface string, relay bool, logger *zap.SugaredLogger) error {
	wgClient, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wgClient.Close()

	pubKey, err := wgtypes.ParseKey(wgPeerConfig.PublicKey)
	if err != nil {
		return err
	}

	allowedIP := make([]net.IPNet, len(wgPeerConfig.AllowedIPs))
	for i := range wgPeerConfig.AllowedIPs {
		_, ipNet, err := net.ParseCIDR(wgPeerConfig.AllowedIPs[i])
		if err != nil {
			return err
		}
		allowedIP[i] = *ipNet
	}

	LocalIP, endpointPort, err := net.SplitHostPort(wgPeerConfig.Endpoint)
	if err != nil {
		logger.Debugf("failed parse the endpoint address for node [ %s ] (likely still converging) : %v\n", wgPeerConfig.PublicKey, err)
		return err
	}

	port, err := strconv.Atoi(endpointPort)
	if err != nil {
		return err
	}

	udpAddr := &net.UDPAddr{
		IP:   net.ParseIP(LocalIP),
		Port: port,
	}

	interval := time.Second * 0

	// relay nodes do not set explicit endpoints
	cfg := wgtypes.Config{}
	if relay {
		cfg = wgtypes.Config{
			ReplacePeers: false,
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey:                   pubKey,
					Remove:                      false,
					AllowedIPs:                  allowedIP,
					PersistentKeepaliveInterval: &interval,
				},
			},
		}
	}
	// all other nodes set peer endpoints
	if !relay {
		cfg = wgtypes.Config{
			ReplacePeers: false,
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey:                   pubKey,
					Remove:                      false,
					Endpoint:                    udpAddr,
					AllowedIPs:                  allowedIP,
					PersistentKeepaliveInterval: &interval,
				},
			},
		}
	}

	return wgClient.ConfigureDevice(tunnelIface, cfg)
}

func HandlePeerDelete(peerListing []models.Device, deviceCache map[uuid.UUID]models.Device, tunnelIface string, logger *zap.SugaredLogger) error {
	// if the canonical peer listing does not contain a peer from cache, delete the peer
	for _, p := range deviceCache {
		if inPeerListing(peerListing, p) {
			continue
		}
		logger.Debugf("Deleting peer with key: %s\n", deviceCache[p.ID])
		if err := deletePeer(deviceCache[p.ID].PublicKey, tunnelIface); err != nil {
			return fmt.Errorf("failed to delete peer: %w", err)
		}
		logger.Infof("Removed peer with key %s", deviceCache[p.ID].PublicKey)
		// delete the peer route(s)
		HandlePeerRouteDelete(tunnelIface, p.AllowedIPs, logger)
		// remove peer from local peer and key cache
		delete(deviceCache, p.ID)
		delete(deviceCache, p.ID)

	}

	return nil
}

func deletePeer(publicKey, dev string) error {
	wgClient, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wgClient.Close()

	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key %s: %w", publicKey, err)
	}

	cfg := []wgtypes.PeerConfig{
		{
			PublicKey: key,
			Remove:    true,
		},
	}

	err = wgClient.ConfigureDevice(dev, wgtypes.Config{
		ReplacePeers: false,
		Peers:        cfg,
	})

	if err != nil {
		return fmt.Errorf("failed to remove peer with key %s: %w", key, err)
	}

	return nil
}

func inPeerListing(peers []models.Device, p models.Device) bool {
	for _, peer := range peers {
		if peer.ID == p.ID {
			return true
		}
	}
	return false
}

func GetWgListenPort() (int, error) {
	l, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return 0, err
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.LocalAddr().String())
	if err != nil {
		return 0, err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return 0, err
	}
	return p, nil
}

// RelayIpTables iptables for the relay node
func RelayIpTables(logger *zap.SugaredLogger, dev string) {
	_, err := RunCommand("iptables", "-A", "FORWARD", "-i", dev, "-j", "ACCEPT")
	if err != nil {
		logger.Debugf("the hub router iptables rule was not added: %v", err)
	}
}
