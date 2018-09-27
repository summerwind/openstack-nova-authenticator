package auth

import (
	"testing"
	"time"

	"github.com/summerwind/openstack-nova-authenticator/openstack"
)

func TestVerifyAuthPeriod(t *testing.T) {
	var tests = []struct {
		period time.Duration
		result bool
	}{
		{time.Duration(10) * time.Second, true},
		{time.Duration(0) * time.Second, false},
	}

	attestor := Attestor{}
	for _, test := range tests {
		instance := &openstack.Instance{
			Created: time.Now(),
		}

		_, err := attestor.VerifyAuthPeriod(instance, test.period)
		if (err == nil) != test.result {
			t.Errorf("unexpected result: %v - %v", test, err)
		}
	}
}

func TestVerifyAuthLimit(t *testing.T) {
	deadline := time.Now().Add(10 * time.Second)

	var tests = []struct {
		limit    int
		deadline time.Time
		result   bool
	}{
		{2, deadline, true},
		{2, deadline, true},
		{2, deadline, false},
	}

	attestor := Attestor{
		attempts: map[string]*AuthAttempt{},
	}

	for _, test := range tests {
		instance := &openstack.Instance{
			ID: "fdeffcae-6ada-4908-8ef6-a4a9a69eab59",
		}

		_, err := attestor.VerifyAuthLimit(instance, test.limit, test.deadline)
		if (err == nil) != test.result {
			t.Errorf("unexpected result: %v - %v", test, err)
		}
	}
}

func TestAttestStatus(t *testing.T) {
	var tests = []struct {
		status string
		result bool
	}{
		{"ACTIVE", true},
		{"STOPPED", false},
	}

	attestor := Attestor{}
	for _, test := range tests {
		instance := &openstack.Instance{
			Status: test.status,
		}

		err := attestor.AttestStatus(instance)
		if (err == nil) != test.result {
			t.Errorf("unexpected result: %v - %v", test, err)
		}
	}
}

func TestAttestAddr(t *testing.T) {
	var tests = []struct {
		addr   string
		result bool
	}{
		{"192.168.1.10", true},
		{"2001:db8:85a3:8d3:1319:8a2e:370:7348", true},
		{"192.168.1.20", false},
	}

	attestor := Attestor{}
	for _, test := range tests {
		instance := &openstack.Instance{
			Addresses: []string{"192.168.1.10", "2001:db8:85a3:8d3:1319:8a2e:370:7348"},
		}

		err := attestor.AttestAddr(instance, test.addr)
		if (err == nil) != test.result {
			t.Errorf("unexpected result: %v - %v", test, err)
		}
	}
}

func TestAttestMetadata(t *testing.T) {
	var tests = []struct {
		metadata map[string]string
		result   bool
	}{
		{map[string]string{}, true},
		{map[string]string{"test": "yes"}, true},
		{map[string]string{"test": "yes", "name": "node"}, false},
		{map[string]string{"test": "no"}, false},
	}

	attestor := Attestor{}
	for _, test := range tests {
		instance := &openstack.Instance{
			Metadata: map[string]string{"test": "yes"},
		}

		err := attestor.AttestMetadata(instance, test.metadata)
		if (err == nil) != test.result {
			t.Errorf("unexpected result: %v - %v", test, err)
		}
	}
}

func TestAttestProjectID(t *testing.T) {
	var tests = []struct {
		projectID string
		result    bool
	}{
		{"", true},
		{"fdeffcae-6ada-4908-8ef6-a4a9a69eab59", true},
		{"b0558ddf-8365-44b8-9181-065243a00b17", false},
	}

	attestor := Attestor{}
	for _, test := range tests {
		instance := &openstack.Instance{
			ProjectID: "fdeffcae-6ada-4908-8ef6-a4a9a69eab59",
		}

		err := attestor.AttestProjectID(instance, test.projectID)
		if (err == nil) != test.result {
			t.Errorf("unexpected result: %v - %v", test, err)
		}
	}
}

func TestAttestUserID(t *testing.T) {
	var tests = []struct {
		userID string
		result bool
	}{
		{"", true},
		{"afbd2ec0-87aa-4ffa-a477-9552392def8f", true},
		{"f3dc9fc5-c32f-4f32-9bf9-c1b729f0085a", false},
	}

	attestor := Attestor{}
	for _, test := range tests {
		instance := &openstack.Instance{
			UserID: "afbd2ec0-87aa-4ffa-a477-9552392def8f",
		}

		err := attestor.AttestUserID(instance, test.userID)
		if (err == nil) != test.result {
			t.Errorf("unexpected result: %v - %v", test, err)
		}
	}
}
