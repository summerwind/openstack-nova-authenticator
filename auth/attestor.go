package auth

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/summerwind/openstack-nova-authenticator/config"
	"github.com/summerwind/openstack-nova-authenticator/openstack"
)

// AuthAttemt represents an authentication attempt.
type AuthAttempt struct {
	id       string
	count    int
	deadline time.Time
}

// Attestor represents the entity processing the attestation of
// the instance.
type Attestor struct {
	client     openstack.Client
	authPeriod time.Duration
	authLimit  int
	roles      map[string]config.Role
	attempts   map[string]*AuthAttempt
	m          sync.Mutex
}

// NewAttestor returns a Attestor with client.
func NewAttestor(c *config.Config) (*Attestor, error) {
	client, err := openstack.NewClient()
	if err != nil {
		return nil, err
	}

	authPeriod, err := time.ParseDuration(c.Auth.Period)
	if err != nil {
		return nil, err
	}

	at := &Attestor{
		client:     client,
		authPeriod: authPeriod,
		authLimit:  c.Auth.Limit,
		roles:      c.Roles,
		attempts:   map[string]*AuthAttempt{},
	}

	return at, nil
}

// Attest returns the result of attestation of the OpenStack instance.
func (at *Attestor) Attest(instanceID, roleName, remoteAddr string) (*openstack.Instance, error) {
	role, ok := at.roles[roleName]
	if !ok {
		return nil, fmt.Errorf("invalid role name: %s", roleName)
	}

	instance, err := at.client.GetInstance(instanceID)
	if err != nil {
		return nil, err
	}

	deadline, err := at.VerifyAuthPeriod(instance, at.authPeriod)
	if err != nil {
		return nil, err
	}

	_, err = at.VerifyAuthLimit(instance, at.authLimit, deadline)
	if err != nil {
		return nil, err
	}

	err = at.AttestStatus(instance)
	if err != nil {
		return nil, err
	}

	err = at.AttestAddr(instance, remoteAddr)
	if err != nil {
		return nil, err
	}

	err = at.AttestMetadata(instance, role.Metadata)
	if err != nil {
		return nil, err
	}

	err = at.AttestProjectID(instance, role.ProjectID)
	if err != nil {
		return nil, err
	}

	err = at.AttestUserID(instance, role.UserID)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

// VerifyAuthPeriod is used to verify the deadline of authentication.
// The deadline is calculated by the creation time of OpenStack instance and
// the authentication period specified by the configuration.
func (at *Attestor) VerifyAuthPeriod(instance *openstack.Instance, period time.Duration) (time.Time, error) {
	deadline := instance.Created.Add(period)
	if time.Now().After(deadline) {
		return deadline, errors.New("authentication deadline exceeded")
	}

	return deadline, nil
}

// VerifyAuthLimit is used to verify the number of attempts of authentication.
// The limit of authentication is specified by the configuration.
func (at *Attestor) VerifyAuthLimit(instance *openstack.Instance, limit int, deadline time.Time) (int, error) {
	at.m.Lock()
	defer at.m.Unlock()

	attempt, ok := at.attempts[instance.ID]
	if !ok {
		attempt = &AuthAttempt{
			id:       instance.ID,
			deadline: deadline,
			count:    0,
		}
	}

	attempt.count = attempt.count + 1
	at.attempts[instance.ID] = attempt

	if attempt.count > limit {
		return attempt.count, errors.New("too many authentication attempts")
	}

	return attempt.count, nil
}

// AttestStatus is used to attest the status of OpenStack instance.
// Currently only the ACTIVE state is allowed.
func (at *Attestor) AttestStatus(instance *openstack.Instance) error {
	if instance.Status != "ACTIVE" {
		return errors.New("instance is not active")
	}

	return nil
}

// AttestAddr is used to attest the IP address of OpenStack instance
// with remote IP address.
func (at *Attestor) AttestAddr(instance *openstack.Instance, remoteAddr string) error {
	for _, addr := range instance.Addresses {
		if addr == remoteAddr {
			return nil
		}
	}

	return errors.New("address mismatched")
}

// AttestMetadata is used to attest a OpenStack instance metadata.
func (at *Attestor) AttestMetadata(instance *openstack.Instance, metadata map[string]string) error {
	for key, val := range metadata {
		ival, ok := instance.Metadata[key]
		if !ok {
			return fmt.Errorf("metadata key '%s' not found", key)
		}

		if ival != val {
			return fmt.Errorf("metadata key '%s' mismatched", key)
		}
	}

	return nil
}

// AttestProjectID is used to attest the project ID of OpenStack instance.
func (at *Attestor) AttestProjectID(instance *openstack.Instance, projectID string) error {
	if projectID == "" {
		return nil
	}

	if instance.ProjectID != projectID {
		return errors.New("project ID mismatched")
	}

	return nil
}

// AttestUserID is used to attest the user ID of OpenStack instance.
func (at *Attestor) AttestUserID(instance *openstack.Instance, userID string) error {
	if UserID == "" {
		return nil
	}

	if instance.UserID != UserID {
		return errors.New("user ID mismatched")
	}

	return nil
}
