package nexd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
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
	UnixSocketPath = "/run/nexd.sock"
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

type Nexodus struct {
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
	childPrefix             []string
	stun                    bool
	relayWgIP               string
	wgConfig                wgConfig
	client                  *client.Client
	controllerURL           *url.URL
	deviceCache             map[uuid.UUID]models.Device
	wgLocalAddress          string
	endpointLocalAddress    string
	nodeReflexiveAddress    string
	hostname                string
	symmetricNat            bool
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

func NewNexodus(ctx context.Context,
	logger *zap.SugaredLogger,
	controller string,
	username string,
	password string,
	wgListenPort int,
	wireguardPubKey string,
	wireguardPvtKey string,
	requestedIP string,
	userProvidedLocalIP string,
	childPrefix []string,
	stun bool,
	relayOnly bool,
	insecureSkipTlsVerify bool,
	version string,
) (*Nexodus, error) {
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

	ax := &Nexodus{
		wireguardPubKey:     wireguardPubKey,
		wireguardPvtKey:     wireguardPvtKey,
		controllerIP:        controller,
		listenPort:          wgListenPort,
		requestedIP:         requestedIP,
		userProvidedLocalIP: userProvidedLocalIP,
		childPrefix:         childPrefix,
		stun:                stun,
		deviceCache:         make(map[uuid.UUID]models.Device),
		controllerURL:       controllerURL,
		hostname:            hostname,
		symmetricNat:        relayOnly,
		logger:              logger,
		status:              NexdStatusStarting,
		version:             version,
		username:            username,
		password:            password,
		skipTlsVerify:       insecureSkipTlsVerify,
	}

	ax.tunnelIface = nexodus.DefaultTunnelDev()

	if err := ax.checkUnsupportedConfigs(); err != nil {
		return nil, err
	}

	ax.nodePrep()

	return ax, nil
}

func (ax *Nexodus) SetStatus(status int, msg string) {
	ax.statusMsg = msg
	ax.status = status
}

func (ax *Nexodus) Start(ctx context.Context, wg *sync.WaitGroup) error {
	var err error

	if err := nexodus.CtlServerStart(ctx, wg, ax); err != nil {
		return fmt.Errorf("CtlServerStart(): %w", err)
	}

	var options []client.Option
	if ax.username == "" {
		options = append(options, client.WithDeviceFlow())
	} else if ax.username != "" && ax.password == "" {
		fmt.Print("Enter nexodus account password: ")
		passwdInput, err := term.ReadPassword(int(syscall.Stdin))
		println()
		if err != nil {
			return fmt.Errorf("login aborted: %w", err)
		}
		ax.password = string(passwdInput)
		options = append(options, client.WithPasswordGrant(ax.username, ax.password))
	} else {
		options = append(options, client.WithPasswordGrant(ax.username, ax.password))
	}
	if ax.skipTlsVerify { // #nosec G402
		options = append(options, client.WithTLSConfig(&tls.Config{
			InsecureSkipVerify: true,
		}))
	}

	ax.client, err = client.NewClient(ctx, ax.controllerURL.String(), func(msg string) {
		ax.SetStatus(NexdStatusAuth, msg)
	}, options...)
	if err != nil {
		return err
	}

	ax.SetStatus(NexdStatusRunning, "")

	publicKey, privateKey, err := nexodus.CheckExistingKeys()
	if err != nil {
		ax.logger.Infof("No existing public/private key pair found, generating a new pair")
		publicKey, privateKey, err = nexodus.GenerateNewKeys()
		if err != nil {
			return fmt.Errorf("Unable to locate or generate a key/pair: %w", err)
		}
	}
	ax.wireguardPubKey = publicKey
	ax.wireguardPvtKey = privateKey

	user, err := ax.client.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("get organization error: %w", err)
	}

	if len(user.Organizations) == 0 {
		return fmt.Errorf("user does not belong to any organizations")
	}
	if len(user.Organizations) != 1 {
		return fmt.Errorf("user being in > 1 organization is not yet supported")
	}
	ax.logger.Infof("Device belongs in organization: %s", user.Organizations[0])
	ax.organization = user.Organizations[0]

	var localIP string
	var localEndpointPort int

	// User requested ip --request-ip takes precedent
	if ax.userProvidedLocalIP != "" {
		localIP = ax.userProvidedLocalIP
		localEndpointPort = ax.listenPort
	}

	// If we are behind a symmetricNat, the endpoint ip discovered by a stun server is useless
	if !ax.symmetricNat && ax.stun && localIP == "" {
		ipPort, err := nexodus.StunRequest(ax.logger, nexodus.StunServer1, ax.listenPort)
		if err != nil {
			ax.logger.Warn("Unable to determine the public facing address, falling back to the local address")
		} else {
			localIP = ipPort.IP.String()
			localEndpointPort = ipPort.Port
		}
	}
	if localIP == "" {
		ip, err := ax.findLocalIP()
		if err != nil {
			return fmt.Errorf("unable to determine the ip address of the host, please specify using --local-endpoint-ip: %w", err)
		}
		localIP = ip
		localEndpointPort = ax.listenPort
	}
	ax.LocalIP = localIP
	ax.endpointLocalAddress = localIP
	endpointSocket := net.JoinHostPort(localIP, fmt.Sprintf("%d", localEndpointPort))
	device, err := ax.client.CreateDevice(models.AddDevice{
		UserID:                   user.ID,
		OrganizationID:           ax.organization,
		PublicKey:                ax.wireguardPubKey,
		LocalIP:                  endpointSocket,
		TunnelIP:                 ax.requestedIP,
		ChildPrefix:              ax.childPrefix,
		ReflexiveIPv4:            ax.nodeReflexiveAddress,
		EndpointLocalAddressIPv4: ax.endpointLocalAddress,
		SymmetricNat:             ax.symmetricNat,
		Hostname:                 ax.hostname,
		Relay:                    false,
	})
	if err != nil {
		var conflict client.ErrConflict
		if errors.As(err, &conflict) {
			deviceID, err := uuid.Parse(conflict.ID)
			if err != nil {
				return fmt.Errorf("error parsing conflicting device id: %w", err)
			}
			device, err = ax.client.UpdateDevice(deviceID, models.UpdateDevice{
				LocalIP:                  endpointSocket,
				ChildPrefix:              ax.childPrefix,
				ReflexiveIPv4:            ax.nodeReflexiveAddress,
				EndpointLocalAddressIPv4: ax.endpointLocalAddress,
				SymmetricNat:             ax.symmetricNat,
				Hostname:                 ax.hostname,
			})
			if err != nil {
				return fmt.Errorf("error updating device: %w", err)
			}
		} else {
			return fmt.Errorf("error creating device: %w", err)
		}
	}
	ax.logger.Debug(fmt.Sprintf("Device: %+v", device))
	ax.logger.Infof("Successfully registered device with UUID: %+v", device.ID)

	if err := ax.Reconcile(ax.organization, true); err != nil {
		return err
	}

	// send keepalives to all peers periodically
	util.GoWithWaitGroup(wg, func() {
		util.RunPeriodically(ctx, time.Second*10, func() {
			ax.Keepalive()
		})
	})

	util.GoWithWaitGroup(wg, func() {
		util.RunPeriodically(ctx, pollInterval, func() {
			if err := ax.Reconcile(ax.organization, false); err != nil {
				// TODO: Add smarter reconciliation logic
				ax.logger.Errorf("Failed to reconcile state with the nexodus API server: %v", err)
				// if the token grant becomes invalid expires refresh or exit depending on the onboard method
				if strings.Contains(err.Error(), invalidTokenGrant.Error()) {
					if ax.username != "" {
						c, err := client.NewClient(ctx, ax.controllerURL.String(), func(msg string) {
							ax.SetStatus(NexdStatusAuth, msg)
						}, options...)
						if err != nil {
							ax.logger.Errorf("Failed to reconnect to the api-server, retrying in %v seconds: %v", pollInterval, err)
						} else {
							ax.client = c
							ax.SetStatus(NexdStatusRunning, "")
							ax.logger.Infoln("Nexodus agent has re-established a connection to the api-server")
						}
					} else {
						ax.logger.Fatalf("The token grant has expired due to an extended period offline, please " +
							"restart the agent for a one-time auth or login with --username --password to automatically reconnect")
					}
				}
			}
		})
	})

	return nil
}

func (ax *Nexodus) Keepalive() {
	ax.logger.Debug("Sending Keepalive")
	var peerEndpoints []string
	for _, value := range ax.deviceCache {
		nodeAddr := value.TunnelIP
		// strip the /32 from the prefix if present
		if net.ParseIP(value.TunnelIP) == nil {
			nodeIP, _, err := net.ParseCIDR(value.TunnelIP)
			nodeAddr = nodeIP.String()
			if err != nil {
				ax.logger.Debugf("failed parsing an ip from the prefix %v", err)
			}
		}
		peerEndpoints = append(peerEndpoints, nodeAddr)
	}

	_ = nexodus.ProbePeers(peerEndpoints, ax.logger)
}

func (ax *Nexodus) Reconcile(orgID uuid.UUID, firstTime bool) error {
	peerListing, err := ax.client.GetDeviceInOrganization(orgID)
	if err != nil {
		return err
	}
	var newPeers []models.Device
	if firstTime {
		// Initial peer list processing branches from here
		ax.logger.Debugf("Initializing peers for the first time")
		for _, p := range peerListing {
			existing, ok := ax.deviceCache[p.ID]
			if !ok {
				ax.deviceCache[p.ID] = p
				newPeers = append(newPeers, p)
			}
			if !reflect.DeepEqual(existing, p) {
				ax.deviceCache[p.ID] = p
				newPeers = append(newPeers, p)
			}
		}
		ax.buildPeersConfig()
		if err := ax.DeployWireguardConfig(newPeers, firstTime); err != nil {
			if errors.Is(err, nexodus.InterfaceErr) {
				ax.logger.Fatal(err)
			}
			return err
		}
	}
	// all subsequent peer listings updates get branched from here
	changed := false
	for _, p := range peerListing {
		existing, ok := ax.deviceCache[p.ID]
		if !ok {
			changed = true
			ax.deviceCache[p.ID] = p
			newPeers = append(newPeers, p)
		}
		if !reflect.DeepEqual(existing, p) {
			changed = true
			ax.deviceCache[p.ID] = p
			newPeers = append(newPeers, p)
		}
	}

	if changed {
		ax.logger.Debugf("Peers listing has changed, recalculating configuration")
		ax.buildPeersConfig()
		if err := ax.DeployWireguardConfig(newPeers, false); err != nil {
			return err
		}
	}

	// check for any peer deletions
	if err := nexodus.HandlePeerDelete(peerListing, ax.deviceCache, ax.tunnelIface, ax.logger); err != nil {
		ax.logger.Error(err)
	}

	return nil
}

// checkUnsupportedConfigs general matrix checks of required information or constraints to run the agent and join the mesh
func (ax *Nexodus) checkUnsupportedConfigs() error {
	if ax.userProvidedLocalIP != "" {
		if err := nexodus.ValidateIp(ax.userProvidedLocalIP); err != nil {
			return fmt.Errorf("the IP address passed in --local-endpoint-ip %s was not valid: %w", ax.userProvidedLocalIP, err)
		}
	}
	if ax.requestedIP != "" {
		if err := nexodus.ValidateIp(ax.requestedIP); err != nil {
			return fmt.Errorf("the IP address passed in --request-ip %s was not valid: %w", ax.requestedIP, err)
		}
	}

	for _, prefix := range ax.childPrefix {
		if err := nexodus.ValidateCIDR(prefix); err != nil {
			return err
		}
	}
	return nil
}

// nodePrep add basic gathering and node condition checks here
func (ax *Nexodus) nodePrep() {

	// remove an existing wg interfaces
	ax.removeExistingInterface()

	// discover the server reflexive address per ICE RFC8445 = (lol public address)
	stunAddr, err := nexodus.StunRequest(ax.logger, nexodus.StunServer1, ax.listenPort)
	if err != nil {
		ax.logger.Infof("failed to query the stun server: %v", err)
	} else {
		ax.nodeReflexiveAddress = stunAddr.IP.String()
	}

	isSymmetric := false
	stunAddr2, err := nexodus.StunRequest(ax.logger, nexodus.StunServer2, ax.listenPort)
	if err != nil {
		ax.logger.Error(err)
	} else {
		isSymmetric = stunAddr.String() != stunAddr2.String()
	}

	if isSymmetric {
		ax.symmetricNat = true
		ax.logger.Infof("Symmetric NAT is detected, this node will be provisioned in relay mode only")
	}

}

func (nexd *Nexodus) GetSocketPath() string {
	return UnixSocketPath
}

func (nexd *Nexodus) Logger() *zap.SugaredLogger {
	return nexd.logger
}

func (nexd *Nexodus) GetReceiver() any {
	nrc := new(NexdCtl)
	nrc.ax = nexd
	return nrc
}
