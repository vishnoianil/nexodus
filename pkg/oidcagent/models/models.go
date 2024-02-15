package models

import "time"

type UserInfoResponse struct {
	Subject           string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	UpdatedAt         int64  `json:"updated_at"`
	FamilyName        string `json:"family_name"`
	Picture           string `json:"picture"`
	EmailVerified     bool   `json:"email_verified"`
	Email             string `json:"email"`
}

type DeviceStartResponse struct {
	// TODO: Remove this once golang/oauth2 supports device flow
	// and when coreos/go-oidc adds device_authorization_endpoint discovery
	DeviceAuthURL string `json:"device_authorization_endpoint"`
	Issuer        string `json:"issuer"`
	ClientID      string `json:"client_id"`
	// the current time on the server, can be used by a client to get an idea of what the time skew is
	// in relation to the server.
	ServerTime *time.Time `json:"server_time" format:"date-time"`
}
