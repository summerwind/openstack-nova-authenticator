package openstack

import "time"

// Instance represents the information of an openstack instance.
type Instance struct {
	ID        string
	Name      string
	ProjectID string
	UserID    string
	Addresses []string
	Metadata  map[string]string
	Status    string
	Created   time.Time
	Updated   time.Time
}
