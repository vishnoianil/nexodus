package nexrelay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/nexodus-io/nexodus/internal/client"
	"github.com/nexodus-io/nexodus/internal/models"
	"github.com/nexodus-io/nexodus/internal/nexodus"
	"github.com/nexodus-io/nexodus/internal/util"
	"go.uber.org/zap"
	"golang.org/x/term"
)

const (
	pollInterval   = 5 * time.Second
	UnixSocketPath = "/run/nexrelay.sock"
)

const (
	// when nexd is first starting up
	NexdStatusStarting = iota
	// when nexd is waiting for auth and the user must complete the OTP auth flow
	NexdStatusAuth
	// nexd is up and running normally
	NexdStatusRunning
)

var (
	invalidTokenGrant = errors.New("invalid_grant")
)

type Nexrelay struct {
	wireguardPubKey         string
	wireguardPvtKey         string
	wireguardPubKeyInConfig bool
	tunnelIface             string
	controllerIP            string
	listenPort              int
	organization            uuid.UUID
	requestedIP             string
	userProvidedLocalIP     string
	LocalIP                 string
	stun                    bool
	wgConfig                wgConfig
	client                  *client.Client
	controllerURL           *url.URL
	deviceCache             map[uuid.UUID]models.Device
	wgLocalAddress          string
	endpointLocalAddress    string
	nodeReflexiveAddress    string
	hostname                string
	logger                  *zap.SugaredLogger
	// See the NexdStatus* constants
	status        int
	statusMsg     string
	version       string
	username      string
	password      string
	skipTlsVerify bool
}

type wgConfig struct {
	Interface wgLocalConfig
	Peers     []nexodus.WgPeerConfig `ini:"Peer,nonunique"`
}

type wgLocalConfig struct {
	PrivateKey string
	ListenPort int
}

func NewNexrelay(ctx context.Context,
	logger *zap.SugaredLogger,
	controller string,
	username string,
	password string,
	wgListenPort int,
	wireguardPubKey string,
	wireguardPvtKey string,
	requestedIP string,
	userProvidedLocalIP string,
	stun bool,
	insecureSkipTlsVerify bool,
	version string,
) (*Nexrelay, error) {
	if err := nexodus.BinaryChecks(); err != nil {
		return nil, err
	}

	controllerURL, err := url.Parse(controller)
	if err != nil {
		return nil, err
	}

	// Force controller URL be api.${DOMAIN}
	controllerURL.Host = "api." + controllerURL.Host
	controllerURL.Path = ""

	if err := nexodus.CheckOS(logger); err != nil {
		return nil, err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	if wgListenPort == 0 {
		wgListenPort, err = nexodus.GetWgListenPort()
		if err != nil {
			return nil, err
		}
	}

	nexr := &Nexrelay{
		wireguardPubKey:     wireguardPubKey,
		wireguardPvtKey:     wireguardPvtKey,
		controllerIP:        controller,
		listenPort:          wgListenPort,
		requestedIP:         requestedIP,
		userProvidedLocalIP: userProvidedLocalIP,
		stun:                stun,
		deviceCache:         make(map[uuid.UUID]models.Device),
		controllerURL:       controllerURL,
		hostname:            hostname,
		logger:              logger,
		status:              NexdStatusStarting,
		version:             version,
		username:            username,
		password:            password,
		skipTlsVerify:       insecureSkipTlsVerify,
	}

	nexr.tunnelIface = nexodus.DefaultTunnelDev()
	nexr.listenPort = nexodus.WgDefaultPort

	if err := nexr.checkUnsupportedConfigs(); err != nil {
		return nil, err
	}

	// remove an existing wg interfaces
	nexr.removeExistingInterface()

	return nexr, nil
}

func (nexr *Nexrelay) SetStatus(status int, msg string) {
	nexr.statusMsg = msg
	nexr.status = status
}

func (nexr *Nexrelay) Start(ctx context.Context, wg *sync.WaitGroup) error {
	var err error

	if err := nexodus.CtlServerStart(ctx, wg, nexr); err != nil {
		return fmt.Errorf("CtlServerStart(): %w", err)
	}

	var options []client.Option
	if nexr.username == "" {
		options = append(options, client.WithDeviceFlow())
	} else if nexr.username != "" && nexr.password == "" {
		fmt.Print("Enter nexodus account password: ")
		passwdInput, err := term.ReadPassword(int(syscall.Stdin))
		println()
		if err != nil {
			return fmt.Errorf("login aborted: %w", err)
		}
		nexr.password = string(passwdInput)
		options = append(options, client.WithPasswordGrant(nexr.username, nexr.password))
	} else {
		options = append(options, client.WithPasswordGrant(nexr.username, nexr.password))
	}
	if nexr.skipTlsVerify { // #nosec G402
		options = append(options, client.WithTLSConfig(&tls.Config{
			InsecureSkipVerify: true,
		}))
	}

	nexr.client, err = client.NewClient(ctx, nexr.controllerURL.String(), func(msg string) {
		nexr.SetStatus(NexdStatusAuth, msg)
	}, options...)
	if err != nil {
		return err
	}

	nexr.SetStatus(NexdStatusRunning, "")
	publicKey, privateKey, err := nexodus.CheckExistingKeys()
	if err != nil {
		nexr.logger.Infof("No existing public/private key pair found, generating a new pair")
		publicKey, privateKey, err = nexodus.GenerateNewKeys()
		if err != nil {
			return fmt.Errorf("Unable to locate or generate a key/pair: %w", err)
		}
	}
	nexr.wireguardPubKey = publicKey
	nexr.wireguardPvtKey = privateKey

	user, err := nexr.client.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("get organization error: %w", err)
	}

	if len(user.Organizations) == 0 {
		return fmt.Errorf("user does not belong to any organizations")
	}
	if len(user.Organizations) != 1 {
		return fmt.Errorf("user being in > 1 organization is not yet supported")
	}
	nexr.logger.Infof("Device belongs in organization: %s", user.Organizations[0])
	nexr.organization = user.Organizations[0]

	var localIP string
	var localEndpointPort int

	// User requested ip --request-ip takes precedent
	if nexr.userProvidedLocalIP != "" {
		localIP = nexr.userProvidedLocalIP
		localEndpointPort = nexr.listenPort
	}

	existingRelay, err := nexr.orgRelayCheck()
	if err != nil {
		return err
	}
	if existingRelay != uuid.Nil {
		return fmt.Errorf("the organization already contains a relay node, device %s needs to be deleted before adding a new relay", existingRelay)
	}

	// If we are behind a symmetricNat, the endpoint ip discovered by a stun server is useless
	if nexr.stun && localIP == "" {
		ipPort, err := nexodus.StunRequest(nexr.logger, nexodus.StunServer1, nexr.listenPort)
		if err != nil {
			nexr.logger.Warn("Unable to determine the public facing address, falling back to the local address")
		} else {
			localIP = ipPort.IP.String()
			localEndpointPort = ipPort.Port
		}
	}
	if localIP == "" {
		ip, err := nexr.findLocalIP()
		if err != nil {
			return fmt.Errorf("unable to determine the ip address of the host, please specify using --local-endpoint-ip: %w", err)
		}
		localIP = ip
		localEndpointPort = nexr.listenPort
	}
	nexr.LocalIP = localIP
	nexr.endpointLocalAddress = localIP
	endpointSocket := net.JoinHostPort(localIP, fmt.Sprintf("%d", localEndpointPort))
	device, err := nexr.client.CreateDevice(models.AddDevice{
		UserID:                   user.ID,
		OrganizationID:           nexr.organization,
		PublicKey:                nexr.wireguardPubKey,
		LocalIP:                  endpointSocket,
		TunnelIP:                 nexr.requestedIP,
		ReflexiveIPv4:            nexr.nodeReflexiveAddress,
		EndpointLocalAddressIPv4: nexr.endpointLocalAddress,
		SymmetricNat:             false,
		Hostname:                 nexr.hostname,
		Relay:                    true,
	})
	if err != nil {
		var conflict client.ErrConflict
		if errors.As(err, &conflict) {
			deviceID, err := uuid.Parse(conflict.ID)
			if err != nil {
				return fmt.Errorf("error parsing conflicting device id: %w", err)
			}
			device, err = nexr.client.UpdateDevice(deviceID, models.UpdateDevice{
				LocalIP:                  endpointSocket,
				ReflexiveIPv4:            nexr.nodeReflexiveAddress,
				EndpointLocalAddressIPv4: nexr.endpointLocalAddress,
				SymmetricNat:             false,
				Hostname:                 nexr.hostname,
			})
			if err != nil {
				return fmt.Errorf("error updating device: %w", err)
			}
		} else {
			return fmt.Errorf("error creating device: %w", err)
		}
	}
	nexr.logger.Debug(fmt.Sprintf("Device: %+v", device))
	nexr.logger.Infof("Successfully registered relay device with UUID: %+v", device.ID)

	// a hub router requires ip forwarding and iptables rules, OS type has already been checked
	if err := nexodus.EnableForwardingIPv4(nexr.logger); err != nil {
		return err
	}
	nexodus.RelayIpTables(nexr.logger, nexr.tunnelIface)

	if err := nexr.Reconcile(nexr.organization, true); err != nil {
		return err
	}

	// gather wireguard state from the relay node periodically
	util.GoWithWaitGroup(wg, func() {
		util.RunPeriodically(ctx, time.Second*30, func() {
			nexr.logger.Debugf("Reconciling peers from relay state")
			if err := nexr.relayStateReconcile(nexr.organization); err != nil {
				nexr.logger.Error(err)
			}
		})
	})

	util.GoWithWaitGroup(wg, func() {
		util.RunPeriodically(ctx, pollInterval, func() {
			if err := nexr.Reconcile(nexr.organization, false); err != nil {
				// TODO: Add smarter reconciliation logic
				nexr.logger.Errorf("Failed to reconcile state with the nexodus API server: %v", err)
				// if the token grant becomes invalid expires refresh or exit depending on the onboard method
				if strings.Contains(err.Error(), invalidTokenGrant.Error()) {
					if nexr.username != "" {
						c, err := client.NewClient(ctx, nexr.controllerURL.String(), func(msg string) {
							nexr.SetStatus(NexdStatusAuth, msg)
						}, options...)
						if err != nil {
							nexr.logger.Errorf("Failed to reconnect to the api-server, retrying in %v seconds: %v", pollInterval, err)
						} else {
							nexr.client = c
							nexr.SetStatus(NexdStatusRunning, "")
							nexr.logger.Infoln("Nexodus agent has re-established a connection to the api-server")
						}
					} else {
						nexr.logger.Fatalf("The token grant has expired due to an extended period offline, please " +
							"restart the agent for a one-time auth or login with --username --password to automatically reconnect")
					}
				}
			}
		})
	})

	return nil
}

func (nexr *Nexrelay) Keepalive() {
	nexr.logger.Debug("Sending Keepalive")
	var peerEndpoints []string

	_ = nexodus.ProbePeers(peerEndpoints, nexr.logger)
}

func (nexr *Nexrelay) Reconcile(orgID uuid.UUID, firstTime bool) error {
	peerListing, err := nexr.client.GetDeviceInOrganization(orgID)
	if err != nil {
		return err
	}
	var newPeers []models.Device
	if firstTime {
		// Initial peer list processing branches from here
		nexr.logger.Debugf("Initializing peers for the first time")
		for _, p := range peerListing {
			existing, ok := nexr.deviceCache[p.ID]
			if !ok {
				nexr.deviceCache[p.ID] = p
				newPeers = append(newPeers, p)
			}
			if !reflect.DeepEqual(existing, p) {
				nexr.deviceCache[p.ID] = p
				newPeers = append(newPeers, p)
			}
		}
		nexr.buildPeersConfig()
		if err := nexr.DeployWireguardConfig(newPeers, firstTime); err != nil {
			if errors.Is(err, nexodus.InterfaceErr) {
				nexr.logger.Fatal(err)
			}
			return err
		}
	}
	// all subsequent peer listings updates get branched from here
	changed := false
	for _, p := range peerListing {
		existing, ok := nexr.deviceCache[p.ID]
		if !ok {
			changed = true
			nexr.deviceCache[p.ID] = p
			newPeers = append(newPeers, p)
		}
		if !reflect.DeepEqual(existing, p) {
			changed = true
			nexr.deviceCache[p.ID] = p
			newPeers = append(newPeers, p)
		}
	}

	if changed {
		nexr.logger.Debugf("Peers listing has changed, recalculating configuration")
		nexr.buildPeersConfig()
		if err := nexr.DeployWireguardConfig(newPeers, false); err != nil {
			return err
		}
	}

	// check for any peer deletions
	if err := nexodus.HandlePeerDelete(peerListing, nexr.deviceCache, nexr.tunnelIface, nexr.logger); err != nil {
		nexr.logger.Error(err)
	}

	return nil
}

// relayStateReconcile collect state from the relay node and rejoin nodes with the dynamic state
func (nexr *Nexrelay) relayStateReconcile(orgID uuid.UUID) error {
	nexr.logger.Debugf("Reconciling peers from relay state")
	peerListing, err := nexr.client.GetDeviceInOrganization(orgID)
	if err != nil {
		return err
	}
	// get wireguard state from the relay node to learn the dynamic reflexive ip:port socket
	relayInfo, err := nexodus.DumpPeers(nexr.tunnelIface)
	if err != nil {
		nexr.logger.Errorf("error dumping wg peers")
	}
	relayData := make(map[string]nexodus.WgSessions)
	for _, peerRelay := range relayInfo {
		_, ok := relayData[peerRelay.PublicKey]
		if !ok {
			relayData[peerRelay.PublicKey] = peerRelay
		}
	}
	// re-join peers with updated state from the relay node
	for _, peer := range peerListing {
		// if the peer is behind a symmetric NAT, skip to the next peer
		if peer.SymmetricNat {
			nexr.logger.Debugf("skipping symmetric NAT node %s", peer.LocalIP)
			continue
		}
		_, ok := relayData[peer.PublicKey]
		if ok {
			if relayData[peer.PublicKey].Endpoint != "" {
				// test the reflexive address is valid and not still in a (none) state
				_, _, err := net.SplitHostPort(relayData[peer.PublicKey].Endpoint)
				if err != nil {
					// if the relay state was not yet established or the peer is offline the endpoint can be (none)
					nexr.logger.Debugf("failed to split host:port endpoint pair: %v", err)
					continue
				}
				endpointReflexiveAddress := relayData[peer.PublicKey].Endpoint
				// update the peer endpoint to the new reflexive address learned from the wg session
				_, err = nexr.client.UpdateDevice(peer.ID, models.UpdateDevice{
					LocalIP: endpointReflexiveAddress,
				})
				if err != nil {
					nexr.logger.Errorf("failed updating peer: %+v", err)
				}
			}
		}
	}
	return nil
}

// checkUnsupportedConfigs general matrix checks of required information or constraints to run the agent and join the mesh
func (nexr *Nexrelay) checkUnsupportedConfigs() error {
	if runtime.GOOS == nexodus.Darwin.String() {
		return fmt.Errorf("OSX nodes cannot be a hub-router, only Linux nodes")
	}
	if runtime.GOOS == nexodus.Windows.String() {
		return fmt.Errorf("Windows nodes cannot be a hub-router, only Linux nodes")
	}
	if nexr.userProvidedLocalIP != "" {
		if err := nexodus.ValidateIp(nexr.userProvidedLocalIP); err != nil {
			return fmt.Errorf("the IP address passed in --local-endpoint-ip %s was not valid: %w", nexr.userProvidedLocalIP, err)
		}
	}
	if nexr.requestedIP != "" {
		if err := nexodus.ValidateIp(nexr.requestedIP); err != nil {
			return fmt.Errorf("the IP address passed in --request-ip %s was not valid: %w", nexr.requestedIP, err)
		}
	}

	if nexr.requestedIP != "" {
		nexr.logger.Warnf("request-ip is currently unsupported for the hub-router, a dynamic address will be used instead")
		nexr.requestedIP = ""
	}

	return nil
}

// orgRelayCheck checks if there is an existing relay in the organization that does not match this devices pub key
func (nexr *Nexrelay) orgRelayCheck() (uuid.UUID, error) {
	var relayID uuid.UUID

	peerListing, err := nexr.client.GetDeviceInOrganization(nexr.organization)
	if err != nil {
		return relayID, err
	}

	for _, p := range peerListing {
		if p.Relay && nexr.wireguardPubKey != p.PublicKey {
			return p.ID, nil
		}
	}

	return relayID, nil
}

func (nexr *Nexrelay) GetSocketPath() string {
	return UnixSocketPath
}

func (nexr *Nexrelay) Logger() *zap.SugaredLogger {
	return nexr.logger
}

func (nexr *Nexrelay) GetReceiver() any {
	nrc := new(NexrelayCtl)
	nrc.nexr = nexr
	return nrc
}
