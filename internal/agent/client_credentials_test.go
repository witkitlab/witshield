package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/identity"
)

type requestCredential struct {
	deviceID, token, publicKey string
}

func TestConcurrentEnrollmentRequestsRemainUnauthenticated(t *testing.T) {
	publicA, privateA, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	publicB, privateB, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	credentialA := requestCredential{deviceID: "dev_a", token: strings.Repeat("a", 32), publicKey: publicA}
	credentialB := requestCredential{deviceID: "dev_b", token: strings.Repeat("b", 32), publicKey: publicB}
	byPublicKey := map[string]requestCredential{publicA: credentialA, publicB: credentialB}

	secondChallengeSeen := make(chan struct{})
	releaseSecondChallenge := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseSecondChallenge) }) })
	var violationsMu sync.Mutex
	var violations []string
	recordViolation := func(value string) {
		violationsMu.Lock()
		violations = append(violations, value)
		violationsMu.Unlock()
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, "read request", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/agent/v1/enroll/challenge":
			if hasPostEnrollmentHeaders(r) {
				recordViolation("challenge request used post-enrollment credentials")
			}
			var in struct {
				IdentityPublicKey string `json:"identityPublicKey"`
			}
			if json.Unmarshal(body, &in) != nil {
				http.Error(w, "invalid challenge", http.StatusBadRequest)
				return
			}
			if in.IdentityPublicKey == publicB {
				close(secondChallengeSeen)
				select {
				case <-releaseSecondChallenge:
				case <-r.Context().Done():
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "challenge", "challenge": "proof-value"})
		case "/agent/v1/enroll":
			if hasPostEnrollmentHeaders(r) {
				recordViolation("final enrollment request used post-enrollment credentials")
			}
			var in struct {
				IdentityPublicKey string `json:"identityPublicKey"`
			}
			if json.Unmarshal(body, &in) != nil {
				http.Error(w, "invalid enrollment", http.StatusBadRequest)
				return
			}
			credential, ok := byPublicKey[in.IdentityPublicKey]
			if !ok {
				http.Error(w, "unknown identity", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device":      domain.Device{ID: credential.deviceID},
				"deviceToken": credential.token,
			})
		case "/agent/v1/heartbeat":
			if verifyErr := verifyAgentCredential(r, body, credentialB); verifyErr != nil {
				http.Error(w, verifyErr.Error(), http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client, err := NewObserverClient(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type enrollmentResult struct {
		device domain.Device
		token  string
		err    error
	}
	secondResult := make(chan enrollmentResult, 1)
	go func() {
		device, token, enrollErr := client.Enroll(ctx, testEnrollRequest("node-b", publicB, privateB))
		secondResult <- enrollmentResult{device: device, token: token, err: enrollErr}
	}()
	select {
	case <-secondChallengeSeen:
	case <-ctx.Done():
		t.Fatal("second enrollment did not reach its challenge")
	}
	deviceA, tokenA, err := client.Enroll(ctx, testEnrollRequest("node-a", publicA, privateA))
	if err != nil || deviceA.ID != credentialA.deviceID || tokenA != credentialA.token {
		t.Fatalf("first enrollment: device=%q token=%q err=%v", deviceA.ID, tokenA, err)
	}
	releaseOnce.Do(func() { close(releaseSecondChallenge) })
	var resultB enrollmentResult
	select {
	case resultB = <-secondResult:
	case <-ctx.Done():
		t.Fatal("second enrollment did not finish")
	}
	if resultB.err != nil || resultB.device.ID != credentialB.deviceID || resultB.token != credentialB.token {
		t.Fatalf("second enrollment: device=%q token=%q err=%v", resultB.device.ID, resultB.token, resultB.err)
	}
	if err = client.Heartbeat(ctx, map[string]string{"status": "ready"}); err != nil {
		t.Fatalf("published enrollment credentials were unusable: %v", err)
	}
	violationsMu.Lock()
	defer violationsMu.Unlock()
	if len(violations) != 0 {
		t.Fatalf("enrollment credential boundary violated: %v", violations)
	}
}

func TestConcurrentEnrollmentPublishesAtomicCredentialSnapshots(t *testing.T) {
	oldPublic, oldPrivate, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	newPublic, newPrivate, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	oldCredential := requestCredential{deviceID: "dev_old", token: strings.Repeat("o", 32), publicKey: oldPublic}
	newCredential := requestCredential{deviceID: "dev_new", token: strings.Repeat("n", 32), publicKey: newPublic}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, "read request", http.StatusBadRequest)
			return
		}
		switch r.URL.Path {
		case "/agent/v1/enroll/challenge":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "challenge", "challenge": "proof-value"})
		case "/agent/v1/enroll":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device":      domain.Device{ID: newCredential.deviceID},
				"deviceToken": newCredential.token,
			})
		case "/agent/v1/heartbeat":
			verifyErr := verifyAgentCredential(r, body, oldCredential)
			if verifyErr != nil {
				verifyErr = verifyAgentCredential(r, body, newCredential)
			}
			if verifyErr != nil {
				http.Error(w, "credential tuple was inconsistent", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client, err := NewObserverClient(server.URL, oldCredential.token)
	if err != nil {
		t.Fatal(err)
	}
	if err = client.SetIdentity(oldCredential.deviceID, oldPrivate); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := make(chan struct{})
	errorsFound := make(chan error, 5)
	var workers sync.WaitGroup
	workers.Add(5)
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 64; i++ {
			if _, _, enrollErr := client.Enroll(ctx, testEnrollRequest("new-node", newPublic, newPrivate)); enrollErr != nil {
				errorsFound <- fmt.Errorf("enrollment %d: %w", i, enrollErr)
				return
			}
		}
	}()
	for i := 0; i < 4; i++ {
		go func() {
			defer workers.Done()
			<-start
			for requestIndex := 0; requestIndex < 128; requestIndex++ {
				if heartbeatErr := client.Heartbeat(ctx, map[string]string{"status": "ready"}); heartbeatErr != nil {
					errorsFound <- heartbeatErr
					return
				}
			}
		}()
	}
	close(start)
	workers.Wait()
	close(errorsFound)
	for workerErr := range errorsFound {
		t.Fatal(workerErr)
	}
}

func testEnrollRequest(name, publicKey, privateKey string) EnrollRequest {
	return EnrollRequest{
		EnrollmentToken: "enrollment-token", Name: name, Hostname: name, OS: "linux", Arch: "amd64",
		AgentVersion: "test", IdentityPublicKey: publicKey, IdentityPrivateKey: privateKey,
	}
}

func hasPostEnrollmentHeaders(r *http.Request) bool {
	return r.Header.Get("Authorization") != "" || r.Header.Get("X-WitShield-Timestamp") != "" ||
		r.Header.Get("X-WitShield-Nonce") != "" || r.Header.Get("X-WitShield-Signature") != ""
}

func verifyAgentCredential(r *http.Request, body []byte, credential requestCredential) error {
	if r.Header.Get("Authorization") != "Bearer "+credential.token {
		return errors.New("unexpected bearer token")
	}
	return identity.VerifyAgentRequest(credential.publicKey, r.Header.Get("X-WitShield-Signature"), identity.AgentRequestProof{
		DeviceID: credential.deviceID, Method: r.Method, RequestURI: r.URL.RequestURI(),
		Timestamp: r.Header.Get("X-WitShield-Timestamp"), Nonce: r.Header.Get("X-WitShield-Nonce"), Body: body,
	})
}
