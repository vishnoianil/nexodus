package models

import (
	"encoding/json"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Organization contains Users and their Devices
type Organization struct {
	Base
	OwnerID     string  `gorm:"owner_id;"`
	Users       []*User `gorm:"many2many:user_organizations;"`
	Devices     []*Device
	Name        string `gorm:"uniqueIndex" sql:"index"`
	Description string
	IpCidr      string
	HubZone     bool
	Invitations []*Invitation
}

// Organization contains Users and their Devices
type OrganizationJSON struct {
	ID          uuid.UUID   `json:"id"`
	OwnerID     string      `json:"owner_id" example:"aa22666c-0f57-45cb-a449-16efecc04f2e"`
	Users       []string    `json:"users" example:"94deb404-c4eb-4097-b59d-76b024ff7867"`
	Devices     []uuid.UUID `json:"devices" example:"4902c991-3dd1-49a6-9f26-d82496c80aff"`
	Name        string      `json:"name" example:"zone-red"`
	Description string      `json:"description" example:"The Red Zone"`
	IpCidr      string      `json:"cidr" example:"172.16.42.0/24"`
	HubZone     bool        `json:"hub_zone"`
}

func (o Organization) MarshalJSON() ([]byte, error) {
	org := OrganizationJSON{
		ID:          o.ID,
		Users:       make([]string, 0),
		Devices:     make([]uuid.UUID, 0),
		Name:        o.Name,
		Description: o.Description,
		IpCidr:      o.IpCidr,
		HubZone:     o.HubZone,
	}
	for _, user := range o.Users {
		org.Users = append(org.Users, user.ID)
	}
	for _, device := range o.Devices {
		org.Devices = append(org.Devices, device.ID)
	}
	return json.Marshal(org)
}

func (z *Organization) BeforeCreate(tx *gorm.DB) error {
	if z.Devices == nil {
		z.Devices = make([]*Device, 0)
	}
	if z.Users == nil {
		z.Users = make([]*User, 0)
	}
	return z.Base.BeforeCreate(tx)
}

type AddOrganization struct {
	Name        string `json:"name" example:"zone-red"`
	Description string `json:"description" example:"The Red Zone"`
	IpCidr      string `json:"cidr" example:"172.16.42.0/24"`
	HubZone     bool   `json:"hub_zone"`
}
