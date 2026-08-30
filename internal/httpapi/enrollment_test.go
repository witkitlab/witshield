package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/agent"
	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/identity"
	"github.com/witkitlab/witshield/internal/secret"
)

func createEnrollmentCredential(t *testing.T, api *testAPI, suffix string) string {
	t.Helper()
	raw := "wse_test_" + suffix + "_012345678901234567890123456789"
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	item := domain.EnrollmentToken{ID: "enr_" + suffix, Name: "test", Hint: "hidden", MaxUses: 1, ExpiresAt: &expires, CreatedAt: now}
	if err := api.store.CreateEnrollmentToken(context.Background(), item, secret.Hash(raw)); err != nil {
		t.Fatal(err)
	}
	return raw
}

func newEnrollmentClient(t *testing.T, api *testAPI) *agent.Client {
	t.Helper()
	client, err := agent.NewObserverClient(api.server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func enrollmentRequest(raw, pub, priv string) agent.EnrollRequest {
	return agent.EnrollRequest{EnrollmentToken: raw, Name: "node", Hostname: "node.example", OS: "linux", Arch: "amd64", AgentVersion: "test", IdentityPublicKey: pub, IdentityPrivateKey: priv, ScanInterval: "24h0m0s"}
}

func TestEnrollmentResponseLossRecoversSameDeviceCredential(t *testing.T) {
	api := newTestAPI(t)
	raw := createEnrollmentCredential(t, api, "response_loss")
	pub, priv, err := agent.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client := newEnrollmentClient(t, api)
	firstDevice, firstToken, err := client.Enroll(context.Background(), enrollmentRequest(raw, pub, priv))
	if err != nil {
		t.Fatal(err)
	}
	// This is the request an Agent makes after the first response was lost. The
	// one-use token is already consumed, but the persistent private key proves
	// that this is the same Agent.
	secondDevice, secondToken, err := client.Enroll(context.Background(), enrollmentRequest(raw, pub, priv))
	if err != nil {
		t.Fatal(err)
	}
	if secondDevice.ID != firstDevice.ID || secondToken != firstToken {
		t.Fatalf("recovery created divergent identity: first=(%s,%s) second=(%s,%s)", firstDevice.ID, secret.Hash(firstToken), secondDevice.ID, secret.Hash(secondToken))
	}
	if count, err := api.store.DeviceCount(context.Background()); err != nil || count != 1 {
		t.Fatalf("device count=%d err=%v, want 1", count, err)
	}
	items, err := api.store.ListEnrollmentTokens(context.Background())
	if err != nil || len(items) != 1 || items[0].Uses != 1 {
		t.Fatalf("enrollment uses=%#v err=%v", items, err)
	}
	if _, err = api.store.AgentDevice(context.Background(), secret.Hash(secondToken)); err != nil {
		t.Fatalf("recovered credential is not valid: %v", err)
	}
}

func TestEnrollmentRejectsBadSignatureKeySwapAndChallengeReplay(t *testing.T) {
	api := newTestAPI(t)
	raw := createEnrollmentCredential(t, api, "proof")
	pub, priv, _ := agent.NewIdentity()
	otherPub, otherPriv, _ := agent.NewIdentity()
	status, body := request(t, http.DefaultClient, http.MethodPost, api.server.URL+"/agent/v1/enroll/challenge", map[string]any{"enrollmentToken": raw, "identityPublicKey": pub}, nil)
	if status != http.StatusCreated {
		t.Fatalf("challenge=%d %s", status, body)
	}
	challenge := decodeMap(t, body)
	challengeID, challengeValue := challenge["id"].(string), challenge["challenge"].(string)

	makePayload := func(publicKey, privateKey string) map[string]any {
		proof := identity.EnrollmentProof{ChallengeID: challengeID, Challenge: challengeValue, EnrollmentToken: raw, Name: "node", Hostname: "node.example", OS: "linux", Arch: "amd64", AgentVersion: "test", IdentityPublicKey: publicKey, ScanInterval: "24h0m0s"}
		signature, err := identity.SignEnrollmentProof(privateKey, proof)
		if err != nil {
			t.Fatal(err)
		}
		return map[string]any{"enrollmentToken": raw, "name": proof.Name, "hostname": proof.Hostname, "os": proof.OS, "arch": proof.Arch, "agentVersion": proof.AgentVersion, "identityPublicKey": publicKey, "scanInterval": proof.ScanInterval, "challengeId": challengeID, "challenge": challengeValue, "identitySignature": signature}
	}

	bad := makePayload(pub, priv)
	bad["identitySignature"] = "not-a-valid-signature"
	status, body = request(t, http.DefaultClient, http.MethodPost, api.server.URL+"/agent/v1/enroll", bad, nil)
	if status != http.StatusUnauthorized || strings.Contains(string(body), raw) {
		t.Fatalf("bad signature=%d %s", status, body)
	}

	// A different key can make a mathematically valid signature, but it cannot
	// use a challenge issued for the original identity.
	swapped := makePayload(otherPub, otherPriv)
	status, body = request(t, http.DefaultClient, http.MethodPost, api.server.URL+"/agent/v1/enroll", swapped, nil)
	if status != http.StatusUnauthorized || strings.Contains(string(body), raw) {
		t.Fatalf("key swap=%d %s", status, body)
	}

	valid := makePayload(pub, priv)
	status, body = request(t, http.DefaultClient, http.MethodPost, api.server.URL+"/agent/v1/enroll", valid, nil)
	if status != http.StatusCreated {
		t.Fatalf("valid proof=%d %s", status, body)
	}
	status, body = request(t, http.DefaultClient, http.MethodPost, api.server.URL+"/agent/v1/enroll", valid, nil)
	if status != http.StatusUnauthorized || strings.Contains(string(body), raw) {
		t.Fatalf("challenge replay=%d %s", status, body)
	}

	// Knowing the original public key and consumed enrollment token still does
	// not let an attacker recover the device credential with another private key.
	_, _, err := newEnrollmentClient(t, api).Enroll(context.Background(), enrollmentRequest(raw, pub, otherPriv))
	if err == nil {
		t.Fatal("different private key recovered a device credential")
	}
}

func TestLegacyUnsignedEnrollmentFailsWithUpgradeInstruction(t *testing.T) {
	api := newTestAPI(t)
	raw := createEnrollmentCredential(t, api, "legacy")
	pub, _, _ := agent.NewIdentity()
	status, body := request(t, http.DefaultClient, http.MethodPost, api.server.URL+"/agent/v1/enroll", map[string]any{"enrollmentToken": raw, "name": "old-node", "hostname": "old-node", "os": "linux", "arch": "amd64", "agentVersion": "old", "identityPublicKey": pub}, nil)
	if status != http.StatusUpgradeRequired || !strings.Contains(string(body), "enrollment_protocol_upgrade_required") || strings.Contains(string(body), raw) {
		t.Fatalf("legacy enrollment=%d %s", status, body)
	}
}

func TestConcurrentEnrollmentRetriesAreTransactionallyIdempotent(t *testing.T) {
	api := newTestAPI(t)
	raw := createEnrollmentCredential(t, api, "concurrent")
	pub, priv, _ := agent.NewIdentity()
	client := newEnrollmentClient(t, api)
	const attempts = 12
	type result struct {
		DeviceID string `json:"deviceId"`
		Token    string `json:"deviceToken"`
		Err      error  `json:"-"`
	}
	results := make(chan result, attempts)
	var start sync.WaitGroup
	start.Add(1)
	for range attempts {
		go func() {
			start.Wait()
			device, token, err := client.Enroll(context.Background(), enrollmentRequest(raw, pub, priv))
			results <- result{DeviceID: device.ID, Token: token, Err: err}
		}()
	}
	start.Done()
	var expected result
	for i := 0; i < attempts; i++ {
		got := <-results
		if got.Err != nil {
			t.Fatalf("concurrent retry %d: %v", i, got.Err)
		}
		if i == 0 {
			expected = got
		} else if got.DeviceID != expected.DeviceID || got.Token != expected.Token {
			t.Fatalf("retry %d diverged: %s/%s vs %s/%s", i, got.DeviceID, secret.Hash(got.Token), expected.DeviceID, secret.Hash(expected.Token))
		}
	}
	if count, err := api.store.DeviceCount(context.Background()); err != nil || count != 1 {
		t.Fatalf("device count=%d err=%v", count, err)
	}
	items, err := api.store.ListEnrollmentTokens(context.Background())
	if err != nil || len(items) != 1 || items[0].Uses != 1 {
		t.Fatalf("token consumption not idempotent: %s", fmt.Sprint(items))
	}
	// Ensure no raw credential appears in the serializable device model.
	encoded, _ := json.Marshal(expected)
	if strings.Contains(string(encoded), raw) {
		t.Fatal("enrollment token appeared in result serialization")
	}
}
