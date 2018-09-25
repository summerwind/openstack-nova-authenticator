package openstack

import (
	"fmt"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/utils/openstack/clientconfig"
	"github.com/mitchellh/mapstructure"
)

// address represents a IP address information of the instance.
type address struct {
	Version int    `mapstructure:"version"`
	Address string `mapstructure:"addr"`
}

// Client is an interface representing the ability to retreve
// the information of a OpenStack instance.
type Client interface {
	GetInstance(string) (*Instance, error)
}

// DefaultClient is a default imlementation of the Client interface.
type DefaultClient struct {
	serviceClient *gophercloud.ServiceClient
}

// NewClient returns a DefaultClient. When creating DefaultClient,
// OpenStack's authentication information is requested.
func NewClient() (*DefaultClient, error) {
	opts := &clientconfig.ClientOpts{}
	authOpts, err := clientconfig.AuthOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("invalid openstack option: %s", err)
	}
	authOpts.AllowReauth = true

	provider, err := openstack.AuthenticatedClient(*authOpts)
	if err != nil {
		return nil, err
	}

	sc, err := openstack.NewComputeV2(provider, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}

	osc := &DefaultClient{
		serviceClient: sc,
	}

	return osc, nil
}

// GetInstance returns the instance information with specified instance ID.
func (c *DefaultClient) GetInstance(instanceID string) (*Instance, error) {
	s, err := servers.Get(c.serviceClient, instanceID).Extract()
	if err != nil {
		return nil, err
	}

	instance := &Instance{
		ID:        s.ID,
		Name:      s.Name,
		ProjectID: s.TenantID,
		UserID:    s.UserID,
		Metadata:  s.Metadata,
		Status:    s.Status,
		Created:   s.Created,
		Updated:   s.Updated,
	}

	addrMap := map[string]bool{}

	if s.AccessIPv4 != "" {
		addrMap[s.AccessIPv4] = true
	}
	if s.AccessIPv6 != "" {
		addrMap[s.AccessIPv6] = true
	}

	var addresses map[string][]address
	err = mapstructure.Decode(s.Addresses, &addresses)
	if err != nil {
		return nil, err
	}

	for _, addrs := range addresses {
		for _, val := range addrs {
			if val.Address != "" {
				addrMap[val.Address] = true
			}
		}
	}

	for addr, _ := range addrMap {
		instance.Addresses = append(instance.Addresses, addr)
	}

	return instance, nil
}
