package nexodus

type WgPeerConfig struct {
	PublicKey           string
	Endpoint            string
	AllowedIPs          []string
	PersistentKeepAlive string
}
