package auth

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"time"

	"github.com/summerwind/openstack-nova-authenticator/config"
	"github.com/summerwind/openstack-nova-authenticator/openstack"
	jose "gopkg.in/square/go-jose.v2"
)

// Token represents a payload of JWT.
type Token struct {
	Issuer       string   `json:"iss"`
	Subject      string   `json:"sub"`
	Audience     []string `json:"aud"`
	Expiry       int64    `json:"exp"`
	IssuedAt     int64    `json:"iat"`
	InstanceName string   `json:"instance_name,omitempty"`
}

// Issuer represents a token issuer.
type Issuer struct {
	tokenIssuer string
	tokenExpiry time.Duration
	signer      jose.Signer
}

// NewIssuer returns a new Issuer with signer.
func NewIssuer(c *config.Config) (*Issuer, error) {
	tokenExpiry, err := time.ParseDuration(c.Auth.TokenExpiry)
	if err != nil {
		return nil, err
	}

	buf, err := ioutil.ReadFile(c.Auth.SigningKeyFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(buf)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	signingKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       key,
	}

	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		return nil, err
	}

	iss := &Issuer{
		tokenIssuer: c.Auth.TokenIssuer,
		tokenExpiry: tokenExpiry,
		signer:      signer,
	}

	return iss, nil
}

// NewToken issues a new token with the specified instance information.
func (iss *Issuer) NewToken(instance *openstack.Instance, roleName string) (string, error) {
	t := Token{
		Issuer:       iss.tokenIssuer,
		Subject:      instance.ID,
		Audience:     []string{roleName},
		Expiry:       time.Now().Add(iss.tokenExpiry).Unix(),
		IssuedAt:     time.Now().Unix(),
		InstanceName: instance.Name,
	}

	payload, err := json.Marshal(t)
	if err != nil {
		return "", err
	}

	sig, err := iss.signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return sig.CompactSerialize()
}
