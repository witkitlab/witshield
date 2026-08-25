package agent

import (
	"context"
	"errors"
	"net"
	"testing"
)

func authenticatedTestClient(t *testing.T, rawURL, token string) *Client {
	t.Helper()
	client, err := NewClient(rawURL, token)
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err = client.SetIdentity("dev_test", privateKey); err != nil {
		t.Fatal(err)
	}
	return client
}

type fixedResolver struct {
	addresses []net.IPAddr
	err       error
}

func (r fixedResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return r.addresses, r.err
}

func TestNewClientAllowsPrivateServiceNameButRejectsPublicLiteral(t *testing.T) {
	if _, err := NewClient("http://controller:8080", "token"); err != nil {
		t.Fatalf("private service name: %v", err)
	}
	if _, err := NewClient("http://8.8.8.8", "token"); err == nil {
		t.Fatal("public HTTP literal was accepted")
	}
}

func TestPrivateControllerDialContextPinsValidatedAddress(t *testing.T) {
	var dialed string
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	dial := privateControllerDialContext("controller", fixedResolver{addresses: []net.IPAddr{{IP: net.ParseIP("10.23.4.5")}}}, func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			t.Fatalf("network=%q", network)
		}
		dialed = address
		return left, nil
	})
	conn, err := dial(context.Background(), "tcp", "controller:8080")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if dialed != "10.23.4.5:8080" {
		t.Fatalf("dialed=%q", dialed)
	}
}

func TestPrivateControllerDialContextRejectsPublicMixedAndChangedTargets(t *testing.T) {
	tests := []struct {
		name      string
		resolver  fixedResolver
		address   string
		wantError string
	}{
		{name: "public", resolver: fixedResolver{addresses: []net.IPAddr{{IP: net.ParseIP("203.0.113.9")}}}, address: "controller:8080", wantError: "outside"},
		{name: "mixed", resolver: fixedResolver{addresses: []net.IPAddr{{IP: net.ParseIP("10.0.0.2")}, {IP: net.ParseIP("203.0.113.9")}}}, address: "controller:8080", wantError: "outside"},
		{name: "no addresses", resolver: fixedResolver{}, address: "controller:8080", wantError: "no addresses"},
		{name: "lookup failure", resolver: fixedResolver{err: errors.New("dns unavailable")}, address: "controller:8080", wantError: "resolve"},
		{name: "changed host", resolver: fixedResolver{addresses: []net.IPAddr{{IP: net.ParseIP("10.0.0.2")}}}, address: "attacker:8080", wantError: "changed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			dial := privateControllerDialContext("controller", tc.resolver, func(context.Context, string, string) (net.Conn, error) {
				called = true
				return nil, errors.New("unexpected dial")
			})
			_, err := dial(context.Background(), "tcp", tc.address)
			if err == nil || !contains(err.Error(), tc.wantError) {
				t.Fatalf("err=%v, want substring %q", err, tc.wantError)
			}
			if called {
				t.Fatal("dial called before validation finished")
			}
		})
	}
}

func contains(text, part string) bool {
	for i := 0; i+len(part) <= len(text); i++ {
		if text[i:i+len(part)] == part {
			return true
		}
	}
	return part == ""
}
