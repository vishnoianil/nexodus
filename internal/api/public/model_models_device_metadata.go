/*
Nexodus API

This is the Nexodus API Server.

API version: 1.0
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package public

// ModelsDeviceMetadata struct for ModelsDeviceMetadata
type ModelsDeviceMetadata struct {
	DeviceId string                 `json:"device_id,omitempty"`
	Key      string                 `json:"key,omitempty"`
	Revision int32                  `json:"revision,omitempty"`
	Value    map[string]interface{} `json:"value,omitempty"`
}