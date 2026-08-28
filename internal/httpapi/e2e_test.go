package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/agent"
	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/identity"
	"github.com/witkitlab/witshield/internal/secret"
	"github.com/witkitlab/witshield/internal/store"
)

type testAPI struct {
	server       *httptest.Server
	api          *Server
	store        *store.Store
	admin        *http.Client
	bootstrap    string
	identityKeys map[string]string
}

type testAgentIdentity struct {
	deviceID   string
	privateKey string
}

var testAgentIdentities sync.Map

func newTestAPI(t *testing.T) *testAPI {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	vault, err := secret.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	web := t.TempDir()
	if err = os.WriteFile(filepath.Join(web, "index.html"), []byte("INDEX"), 0o600); err != nil {
		t.Fatal(err)
	}
	bootstrap := "bootstrap-token-01234567890123456789"
	api, err := New(Config{Store: db, Vault: vault, Version: "v0.0.0-test", BootstrapToken: bootstrap, WebDir: web})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(api.LocalHTTPHandler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	return &testAPI{server: srv, api: api, store: db, admin: client, bootstrap: bootstrap, identityKeys: map[string]string{}}
}
func request(t *testing.T, c *http.Client, method, url string, body any, headers map[string]string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	var encoded []byte
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if auth := req.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") && req.Header.Get("X-WitShield-Signature") == "" && req.Header.Get("X-Test-Unsigned-Agent-Request") == "" {
		if value, ok := testAgentIdentities.Load(strings.TrimPrefix(auth, "Bearer ")); ok {
			registered := value.(testAgentIdentity)
			nonceBytes := make([]byte, 18)
			if _, err = rand.Read(nonceBytes); err != nil {
				t.Fatal(err)
			}
			timestamp := fmt.Sprintf("%d", time.Now().UTC().UnixMilli())
			nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
			signature, signErr := identity.SignAgentRequest(registered.privateKey, identity.AgentRequestProof{DeviceID: registered.deviceID, Method: method, RequestURI: req.URL.RequestURI(), Timestamp: timestamp, Nonce: nonce, Body: encoded})
			if signErr != nil {
				t.Fatal(signErr)
			}
			req.Header.Set("X-WitShield-Timestamp", timestamp)
			req.Header.Set("X-WitShield-Nonce", nonce)
			req.Header.Set("X-WitShield-Signature", signature)
		}
	}
	req.Header.Del("X-Test-Unsigned-Agent-Request")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}
func decodeMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return out
}

func parametersDigest(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return action.ParametersDigest(raw)
}

func signedActionResult(t *testing.T, x *testAPI, deviceID, commandID string, value map[string]any) map[string]any {
	t.Helper()
	if audit, ok := value["auditReceipt"].(map[string]any); ok && audit["success"] == true {
		if _, exists := audit["steps"]; !exists {
			receiptStarted := time.Now().UTC().Add(-time.Second)
			operation, _ := audit["operation"].(string)
			operations := []string{operation}
			if operation == "execute" {
				operations = []string{"precheck", "preview", "apply", "verify"}
			}
			steps := make([]map[string]any, 0, len(operations))
			for index, stepOperation := range operations {
				startedAt := receiptStarted.Add(time.Duration(index) * time.Millisecond)
				steps = append(steps, map[string]any{"operation": stepOperation, "startedAt": startedAt, "finishedAt": startedAt.Add(time.Millisecond), "success": true, "result": map[string]any{"details": map[string]any{}}})
			}
			audit["startedAt"] = receiptStarted
			audit["finishedAt"] = receiptStarted.Add(time.Duration(len(operations)+1) * time.Millisecond)
			audit["steps"] = steps
		}
	}
	if rollback, ok := value["rollbackPayload"]; ok {
		rollbackJSON, marshalErr := json.Marshal(rollback)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if audit, ok := value["auditReceipt"].(map[string]any); ok {
			if _, exists := audit["rollbackStateDigest"]; !exists {
				digest := sha256.Sum256(rollbackJSON)
				audit["rollbackStateDigest"] = "sha256:" + fmt.Sprintf("%x", digest[:])
			}
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		OK              bool            `json:"ok"`
		Result          json.RawMessage `json:"result,omitempty"`
		RollbackPayload json.RawMessage `json:"rollbackPayload,omitempty"`
		AuditReceipt    json.RawMessage `json:"auditReceipt,omitempty"`
		Error           string          `json:"error,omitempty"`
	}
	if err = json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	signature, err := identity.SignCommandResult(x.identityKeys[deviceID], identity.CommandResultProof{
		DeviceID: deviceID, CommandID: commandID, OK: result.OK, Result: result.Result,
		RollbackPayload: result.RollbackPayload, AuditReceipt: result.AuditReceipt, Error: result.Error,
	})
	if err != nil {
		t.Fatal(err)
	}
	value["identitySignature"] = signature
	return value
}

func signedEventBatch(t *testing.T, x *testAPI, deviceID string, value map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value["events"])
	if err != nil {
		t.Fatal(err)
	}
	var events []domain.SecurityEvent
	if err = json.Unmarshal(encoded, &events); err != nil {
		t.Fatal(err)
	}
	signature, err := identity.SignSecurityEventBatch(x.identityKeys[deviceID], identity.SecurityEventBatchProof{DeviceID: deviceID, Events: events})
	if err != nil {
		t.Fatal(err)
	}
	value["identitySignature"] = signature
	return value
}
func (x *testAPI) bootstrapAdmin(t *testing.T) {
	status, body := request(t, x.admin, "POST", x.server.URL+"/api/v1/admin/bootstrap", map[string]any{"username": "admin", "password": "correct horse battery staple", "bootstrapToken": x.bootstrap}, nil)
	if status != 201 {
		t.Fatalf("bootstrap=%d %s", status, body)
	}
}
func (x *testAPI) enroll(t *testing.T) (string, string) {
	return x.enrollMode(t, false)
}

func (x *testAPI) enrollMode(t *testing.T, observerOnly bool) (string, string) {
	status, body := request(t, x.admin, "POST", x.server.URL+"/api/v1/enrollment-tokens", map[string]any{"name": "test-agent"}, nil)
	if status != 201 {
		t.Fatalf("token=%d %s", status, body)
	}
	raw := decodeMap(t, body)["token"].(string)
	pub, priv, err := agent.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client, err := agent.NewClient(x.server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	device, deviceToken, err := client.Enroll(context.Background(), agent.EnrollRequest{EnrollmentToken: raw, Name: "node-1", Hostname: "node-1", OS: "linux", Arch: "amd64", AgentVersion: "test", IdentityPublicKey: pub, IdentityPrivateKey: priv, ObserverOnly: observerOnly})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := x.store.AgentDevice(context.Background(), secret.Hash(deviceToken)); err != nil {
		t.Fatalf("new device credential is not persisted: %v", err)
	}
	x.identityKeys[device.ID] = priv
	testAgentIdentities.Store(deviceToken, testAgentIdentity{deviceID: device.ID, privateKey: priv})
	t.Cleanup(func() { testAgentIdentities.Delete(deviceToken) })
	return device.ID, deviceToken
}

func TestStatusExposesConfiguredBuildVersion(t *testing.T) {
	x := newTestAPI(t)
	status, body := request(t, http.DefaultClient, http.MethodGet, x.server.URL+"/api/v1/status", nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"version":"v0.0.0-test"`) {
		t.Fatalf("status=%d body=%s", status, body)
	}
}

func TestExpiredCommandResultIsTerminalGoneForAgentQueue(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	_, deviceToken := x.enroll(t)
	status, body := request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/commands/cmd_expired_result/result", map[string]any{"ok": true, "result": map[string]any{}}, map[string]string{"Authorization": "Bearer " + deviceToken})
	if status != http.StatusGone || !strings.Contains(string(body), `"code":"command_result_expired"`) {
		t.Fatalf("expired result was not a terminal queue outcome: status=%d body=%s", status, body)
	}
}

func TestObserverEnrollmentPersistsCapabilityAndBlocksMutatingPolicies(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, _ := x.enrollMode(t, true)
	status, body := request(t, x.admin, http.MethodGet, x.server.URL+"/api/v1/devices", nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"observerOnly":true`) {
		t.Fatalf("signed observer capability was not persisted=%d %s", status, body)
	}
	status, body = request(t, x.admin, http.MethodPost, x.server.URL+"/api/v1/actions", map[string]any{
		"deviceId": deviceID, "type": "package_security_upgrade", "parameters": map[string]any{"packages": []string{"openssl"}},
	}, nil)
	if status != http.StatusConflict || !strings.Contains(string(body), "observer_only_device") {
		t.Fatalf("observer accepted manual action=%d %s", status, body)
	}
	policy := map[string]any{"enabled": true, "emergencyStop": false, "autoBan": true, "failureThreshold": 3, "window": "5m", "banDuration": "15m", "maxBansPerHour": 10, "allowlist": []string{"1.1.1.10"}}
	status, body = request(t, x.admin, http.MethodPut, x.server.URL+"/api/v1/devices/"+deviceID+"/defense-policy", policy, nil)
	if status != http.StatusConflict || !strings.Contains(string(body), "observer_only_device") {
		t.Fatalf("observer accepted automatic containment=%d %s", status, body)
	}
}

func TestEndToEndAdminAgentActionAndReport(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, deviceToken := x.enroll(t)
	auth := map[string]string{"Authorization": "Bearer " + deviceToken}
	status, body := request(t, x.admin, "GET", x.server.URL+"/api/v1/devices", nil, nil)
	if status != 200 || strings.Contains(string(body), "PUBLIC-KEY") || strings.Contains(string(body), deviceToken) {
		t.Fatalf("device leak/status: %d %s", status, body)
	}
	now := time.Now().UTC()
	report := domain.Report{ID: "rpt_e2e", DeviceID: "attacker-controlled", StartedAt: now.Add(-time.Second), CompletedAt: now, Score: 70, Summary: json.RawMessage(`{"checks":1,"completedChecks":1,"coveragePercent":100,"findingCount":1,"checkErrors":[],"mode":"native"}`), Findings: []domain.Finding{{Fingerprint: "1234567890abcdef1234567890abcdef", Category: "ssh", Severity: domain.SeverityHigh, Title: "Password login", Description: "enabled", Status: domain.FindingResolved}}}
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/reports", report, auth)
	if status != 201 {
		t.Fatalf("report=%d %s", status, body)
	}
	malformed := report
	malformed.ID = "rpt_e2e_malformed"
	malformed.Summary = json.RawMessage(`{"checks":1,"completedChecks":0,"coveragePercent":0,"findingCount":1,"checkErrors":"oops","mode":{}}`)
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/reports", malformed, auth)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "invalid_report") {
		t.Fatalf("malformed report summary=%d %s", status, body)
	}
	status, body = request(t, x.admin, "GET", x.server.URL+"/api/v1/findings?deviceId="+deviceID, nil, nil)
	if status != 200 || !strings.Contains(string(body), `"status":"open"`) {
		t.Fatalf("finding status not server-controlled: %d %s", status, body)
	}
	status, body = request(t, x.admin, "POST", x.server.URL+"/api/v1/devices/"+deviceID+"/scan", map[string]any{}, nil)
	if status != 202 {
		t.Fatalf("trigger=%d %s", status, body)
	}
	commandID := decodeMap(t, body)["id"].(string)
	status, body = request(t, http.DefaultClient, "GET", x.server.URL+"/agent/v1/sync?wait=0s", nil, auth)
	if status != 200 || !strings.Contains(string(body), commandID) {
		t.Fatalf("sync=%d %s", status, body)
	}
	result := map[string]any{"ok": true, "result": map[string]any{"reportId": "r"}}
	status, _ = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+commandID+"/result", result, auth)
	if status != 204 {
		t.Fatalf("result=%d", status)
	}
	status, _ = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+commandID+"/result", result, auth)
	if status != 204 {
		t.Fatalf("idempotent result=%d", status)
	}
	status, body = request(t, x.admin, "POST", x.server.URL+"/api/v1/actions", map[string]any{"deviceId": deviceID, "type": "package_security_upgrade", "parameters": map[string]any{"packages": []string{"openssl"}}}, nil)
	if status != 201 {
		t.Fatalf("action=%d %s", status, body)
	}
	created := decodeMap(t, body)
	actionMap := created["action"].(map[string]any)
	actionID := actionMap["id"].(string)
	nonce := created["approvalNonce"].(string)
	status, body = request(t, x.admin, "POST", x.server.URL+"/api/v1/actions/"+actionID+"/approve", map[string]any{"approvalNonce": nonce}, nil)
	if status != 202 {
		t.Fatalf("approve=%d %s", status, body)
	}
	actionCommand := decodeMap(t, body)["commandId"].(string)
	status, _ = request(t, http.DefaultClient, "GET", x.server.URL+"/agent/v1/sync?wait=0s", nil, auth)
	if status != 200 {
		t.Fatal(status)
	}
	actionResult := signedActionResult(t, x, deviceID, actionCommand, map[string]any{"ok": true, "result": map[string]any{"summary": "done"}, "rollbackPayload": map[string]any{"signed": "rollback"}, "auditReceipt": map[string]any{"actionId": actionID, "type": "package_security_upgrade", "operation": "execute", "parametersDigest": parametersDigest(t, map[string]any{"packages": []string{"openssl"}}), "success": true}})
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+actionCommand+"/result", actionResult, auth)
	if status != http.StatusConflict {
		t.Fatalf("result bypassed final authorization gate=%d %s", status, body)
	}
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+actionCommand+"/start", map[string]any{}, auth)
	if status != 200 || !strings.Contains(string(body), `"authorized":true`) {
		t.Fatalf("action start=%d %s", status, body)
	}
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+actionCommand+"/result", actionResult, auth)
	if status != 204 {
		t.Fatalf("action result=%d %s", status, body)
	}
	status, body = request(t, x.admin, "GET", x.server.URL+"/api/v1/actions/"+actionID, nil, nil)
	if status != 200 || !strings.Contains(string(body), `"status":"succeeded"`) {
		t.Fatalf("action state=%d %s", status, body)
	}
	status, body = request(t, x.admin, http.MethodPost, x.server.URL+"/api/v1/actions/"+actionID+"/rollback", map[string]any{}, nil)
	if status != http.StatusAccepted {
		t.Fatalf("rollback request=%d %s", status, body)
	}
	rollbackCommand := decodeMap(t, body)["commandId"].(string)
	status, body = request(t, http.DefaultClient, http.MethodGet, x.server.URL+"/agent/v1/sync?wait=0s", nil, auth)
	if status != http.StatusOK || !strings.Contains(string(body), rollbackCommand) {
		t.Fatalf("rollback sync=%d %s", status, body)
	}
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/commands/"+rollbackCommand+"/start", map[string]any{}, auth)
	if status != http.StatusOK || !strings.Contains(string(body), `"authorized":true`) {
		t.Fatalf("rollback start=%d %s", status, body)
	}
	rollbackResult := signedActionResult(t, x, deviceID, rollbackCommand, map[string]any{"ok": true, "result": map[string]any{"summary": "restored"}, "auditReceipt": map[string]any{"actionId": actionID, "type": "package_security_upgrade", "operation": "rollback", "parametersDigest": parametersDigest(t, map[string]any{"packages": []string{"openssl"}}), "success": true}})
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/commands/"+rollbackCommand+"/result", rollbackResult, auth)
	if status != http.StatusNoContent {
		t.Fatalf("rollback result=%d %s", status, body)
	}
	status, body = request(t, x.admin, http.MethodGet, x.server.URL+"/api/v1/actions/"+actionID, nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"status":"rolled_back"`) {
		t.Fatalf("rollback state=%d %s", status, body)
	}
}

func TestSSHActionFailsClosedWithoutConfirmationProof(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, deviceToken := x.enroll(t)
	auth := map[string]string{"Authorization": "Bearer " + deviceToken}
	status, body := request(t, x.admin, "POST", x.server.URL+"/api/v1/actions", map[string]any{"deviceId": deviceID, "type": "ssh_password_hardening", "parameters": map[string]any{"rollbackAfterSeconds": 300}}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create=%d %s", status, body)
	}
	created := decodeMap(t, body)
	actionID := created["action"].(map[string]any)["id"].(string)
	status, body = request(t, x.admin, "POST", x.server.URL+"/api/v1/actions/"+actionID+"/approve", map[string]any{"approvalNonce": created["approvalNonce"]}, nil)
	if status != http.StatusAccepted {
		t.Fatalf("approve=%d %s", status, body)
	}
	commandID := decodeMap(t, body)["commandId"].(string)
	_, _ = request(t, http.DefaultClient, "GET", x.server.URL+"/agent/v1/sync?wait=0s", nil, auth)
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+commandID+"/start", map[string]any{}, auth)
	if status != http.StatusOK || !strings.Contains(string(body), `"authorized":true`) {
		t.Fatalf("start=%d %s", status, body)
	}
	invalid := signedActionResult(t, x, deviceID, commandID, map[string]any{
		"ok": true, "result": map[string]any{"summary": "claimed success"}, "rollbackPayload": map[string]any{"signed": "state"},
		"auditReceipt": map[string]any{"actionId": actionID, "type": "ssh_password_hardening", "operation": "execute", "parametersDigest": parametersDigest(t, map[string]any{"rollbackAfterSeconds": 300}), "success": true},
	})
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+commandID+"/result", invalid, auth)
	if status != http.StatusNoContent {
		t.Fatalf("result=%d %s", status, body)
	}
	status, body = request(t, x.admin, "GET", x.server.URL+"/api/v1/actions/"+actionID, nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"status":"failed"`) || !strings.Contains(string(body), "did not prove whether the configuration changed") {
		t.Fatalf("unsafe receipt was not failed closed=%d %s", status, body)
	}
}

func TestActionReceiptMustMatchApprovedParameters(t *testing.T) {
	x := newTestAPI(t)
	notifications := make(chan domain.NotificationEvent, 1)
	x.api.notifyObserver = func(event domain.NotificationEvent) { notifications <- event }
	x.bootstrapAdmin(t)
	deviceID, deviceToken := x.enroll(t)
	auth := map[string]string{"Authorization": "Bearer " + deviceToken}
	status, body := request(t, x.admin, http.MethodPost, x.server.URL+"/api/v1/actions", map[string]any{"deviceId": deviceID, "type": "package_security_upgrade", "parameters": map[string]any{"packages": []string{"openssl"}}}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create=%d %s", status, body)
	}
	created := decodeMap(t, body)
	actionID := created["action"].(map[string]any)["id"].(string)
	status, body = request(t, x.admin, http.MethodPost, x.server.URL+"/api/v1/actions/"+actionID+"/approve", map[string]any{"approvalNonce": created["approvalNonce"]}, nil)
	if status != http.StatusAccepted {
		t.Fatalf("approve=%d %s", status, body)
	}
	commandID := decodeMap(t, body)["commandId"].(string)
	_, _ = request(t, http.DefaultClient, http.MethodGet, x.server.URL+"/agent/v1/sync?wait=0s", nil, auth)
	premature := signedActionResult(t, x, deviceID, commandID, map[string]any{"ok": true, "result": map[string]any{"summary": "claimed success"}, "rollbackPayload": map[string]any{"signed": "state"}, "auditReceipt": map[string]any{"actionId": actionID, "type": "package_security_upgrade", "operation": "execute", "parametersDigest": parametersDigest(t, map[string]any{"packages": []string{"openssl"}}), "success": true}})
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/commands/"+commandID+"/result", premature, auth)
	if status != http.StatusConflict {
		t.Fatalf("action result bypassed the final start gate=%d %s", status, body)
	}
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/commands/"+commandID+"/start", map[string]any{}, auth)
	if status != http.StatusOK || !strings.Contains(string(body), `"authorized":true`) {
		t.Fatalf("start=%d %s", status, body)
	}
	unsigned := map[string]any{"ok": true, "result": map[string]any{"summary": "claimed success"}, "rollbackPayload": map[string]any{"signed": "state"}, "auditReceipt": map[string]any{"actionId": actionID, "type": "package_security_upgrade", "operation": "execute", "parametersDigest": parametersDigest(t, map[string]any{"packages": []string{"openssl"}}), "success": true}}
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/commands/"+commandID+"/result", unsigned, auth)
	if status != http.StatusUnauthorized || !strings.Contains(string(body), "invalid_device_proof") {
		t.Fatalf("bearer-only result was accepted=%d %s", status, body)
	}
	tampered := signedActionResult(t, x, deviceID, commandID, map[string]any{"ok": true, "result": map[string]any{"summary": "original"}, "rollbackPayload": map[string]any{"signed": "state"}, "auditReceipt": map[string]any{"actionId": actionID, "type": "package_security_upgrade", "operation": "execute", "parametersDigest": parametersDigest(t, map[string]any{"packages": []string{"openssl"}}), "success": true}})
	tampered["result"] = map[string]any{"summary": "changed after signing"}
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/commands/"+commandID+"/result", tampered, auth)
	if status != http.StatusUnauthorized || !strings.Contains(string(body), "invalid_device_proof") {
		t.Fatalf("tampered signed result was accepted=%d %s", status, body)
	}
	forged := signedActionResult(t, x, deviceID, commandID, map[string]any{"ok": true, "result": map[string]any{"summary": "claimed success"}, "rollbackPayload": map[string]any{"signed": "state"}, "auditReceipt": map[string]any{"actionId": actionID, "type": "package_security_upgrade", "operation": "execute", "parametersDigest": parametersDigest(t, map[string]any{"packages": []string{"different-package"}}), "success": true}})
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/commands/"+commandID+"/result", forged, auth)
	if status != http.StatusNoContent {
		t.Fatalf("forged result=%d %s", status, body)
	}
	status, body = request(t, x.admin, http.MethodGet, x.server.URL+"/api/v1/actions/"+actionID, nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"status":"failed"`) || !strings.Contains(string(body), "did not match the approved action") {
		t.Fatalf("mismatched receipt was not failed closed=%d %s", status, body)
	}
	select {
	case event := <-notifications:
		if event.Type != "action_failure" || !strings.Contains(event.Message, "did not match the approved action") {
			t.Fatalf("unexpected failure notification: %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("Controller-side receipt rejection did not emit an action failure notification")
	}
}

func TestSSHActionRequiresExplicitSafetyConfirmation(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, deviceToken := x.enroll(t)
	auth := map[string]string{"Authorization": "Bearer " + deviceToken}
	status, body := request(t, x.admin, "POST", x.server.URL+"/api/v1/actions", map[string]any{"deviceId": deviceID, "type": "ssh_password_hardening", "parameters": map[string]any{"rollbackAfterSeconds": 300}}, nil)
	if status != 201 {
		t.Fatalf("action=%d %s", status, body)
	}
	created := decodeMap(t, body)
	actionID := created["action"].(map[string]any)["id"].(string)
	status, body = request(t, x.admin, "POST", x.server.URL+"/api/v1/actions/"+actionID+"/approve", map[string]any{"approvalNonce": created["approvalNonce"]}, nil)
	if status != 202 {
		t.Fatalf("approve=%d %s", status, body)
	}
	commandID := decodeMap(t, body)["commandId"].(string)
	status, body = request(t, http.DefaultClient, "GET", x.server.URL+"/agent/v1/sync?wait=0s", nil, auth)
	if status != 200 || !strings.Contains(string(body), commandID) {
		t.Fatalf("sync=%d %s", status, body)
	}
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+commandID+"/start", map[string]any{}, auth)
	if status != 200 || !strings.Contains(string(body), `"authorized":true`) {
		t.Fatalf("start=%d %s", status, body)
	}
	confirmBy := time.Now().UTC().Add(5 * time.Minute)
	executed := signedActionResult(t, x, deviceID, commandID, map[string]any{"ok": true, "result": map[string]any{"summary": "SSH hardened"}, "rollbackPayload": map[string]any{"signed": "ssh-state"}, "auditReceipt": map[string]any{
		"actionId": actionID, "type": "ssh_password_hardening", "operation": "execute", "parametersDigest": parametersDigest(t, map[string]any{"rollbackAfterSeconds": 300}), "success": true, "confirmBy": confirmBy,
		"steps": []map[string]any{
			{"operation": "precheck", "success": true, "result": map[string]any{"details": map[string]any{}}},
			{"operation": "preview", "success": true, "result": map[string]any{"details": map[string]any{}}},
			{"operation": "apply", "success": true, "result": map[string]any{"details": map[string]any{}}},
			{"operation": "verify", "success": true, "result": map[string]any{"details": map[string]any{"confirmationPending": true}}},
		},
	}})
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+commandID+"/result", executed, auth)
	if status != 204 {
		t.Fatalf("result=%d %s", status, body)
	}
	status, body = request(t, x.admin, "GET", x.server.URL+"/api/v1/actions/"+actionID, nil, nil)
	if status != 200 || !strings.Contains(string(body), `"status":"awaiting_confirmation"`) || !strings.Contains(string(body), `"confirmBy"`) {
		t.Fatalf("awaiting confirmation=%d %s", status, body)
	}
	status, body = request(t, x.admin, "POST", x.server.URL+"/api/v1/actions/"+actionID+"/confirm", map[string]any{}, nil)
	if status != 202 {
		t.Fatalf("confirm request=%d %s", status, body)
	}
	confirmCommandID := decodeMap(t, body)["commandId"].(string)
	_, body = request(t, http.DefaultClient, "GET", x.server.URL+"/agent/v1/sync?wait=0s", nil, auth)
	if !strings.Contains(string(body), confirmCommandID) {
		t.Fatalf("confirm command missing: %s", body)
	}
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+confirmCommandID+"/start", map[string]any{}, auth)
	if status != 200 || !strings.Contains(string(body), `"authorized":true`) {
		t.Fatalf("confirm start=%d %s", status, body)
	}
	confirmed := signedActionResult(t, x, deviceID, confirmCommandID, map[string]any{"ok": true, "result": map[string]any{"summary": "timed rollback disarmed"}, "auditReceipt": map[string]any{"actionId": actionID, "type": "ssh_password_hardening", "operation": "confirm", "parametersDigest": parametersDigest(t, map[string]any{"rollbackAfterSeconds": 300}), "success": true}})
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+confirmCommandID+"/result", confirmed, auth)
	if status != 204 {
		t.Fatalf("confirm result=%d %s", status, body)
	}
	_, body = request(t, x.admin, "GET", x.server.URL+"/api/v1/actions/"+actionID, nil, nil)
	if !strings.Contains(string(body), `"status":"succeeded"`) {
		t.Fatalf("confirmed action not successful: %s", body)
	}
}

func TestSSHCompletionExactReplayRemainsIdempotentAfterConfirmDeadline(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, deviceToken := x.enroll(t)
	auth := map[string]string{"Authorization": "Bearer " + deviceToken}
	status, body := request(t, x.admin, http.MethodPost, x.server.URL+"/api/v1/actions", map[string]any{"deviceId": deviceID, "type": "ssh_password_hardening", "parameters": map[string]any{"rollbackAfterSeconds": 300}}, nil)
	if status != http.StatusCreated {
		t.Fatalf("action=%d %s", status, body)
	}
	created := decodeMap(t, body)
	actionID := created["action"].(map[string]any)["id"].(string)
	status, body = request(t, x.admin, http.MethodPost, x.server.URL+"/api/v1/actions/"+actionID+"/approve", map[string]any{"approvalNonce": created["approvalNonce"]}, nil)
	if status != http.StatusAccepted {
		t.Fatalf("approve=%d %s", status, body)
	}
	commandID := decodeMap(t, body)["commandId"].(string)
	_, _ = request(t, http.DefaultClient, http.MethodGet, x.server.URL+"/agent/v1/sync?wait=0s", nil, auth)
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/commands/"+commandID+"/start", map[string]any{}, auth)
	if status != http.StatusOK {
		t.Fatalf("start=%d %s", status, body)
	}
	confirmBy := time.Now().UTC().Add(750 * time.Millisecond)
	executed := signedActionResult(t, x, deviceID, commandID, map[string]any{"ok": true, "result": map[string]any{"summary": "SSH hardened"}, "rollbackPayload": map[string]any{"signed": "ssh-state"}, "auditReceipt": map[string]any{
		"actionId": actionID, "type": "ssh_password_hardening", "operation": "execute", "parametersDigest": parametersDigest(t, map[string]any{"rollbackAfterSeconds": 300}), "success": true, "confirmBy": confirmBy,
		"steps": []map[string]any{
			{"operation": "precheck", "success": true, "result": map[string]any{"details": map[string]any{}}},
			{"operation": "preview", "success": true, "result": map[string]any{"details": map[string]any{}}},
			{"operation": "apply", "success": true, "result": map[string]any{"details": map[string]any{}}},
			{"operation": "verify", "success": true, "result": map[string]any{"details": map[string]any{"confirmationPending": true}}},
		},
	}})
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/commands/"+commandID+"/result", executed, auth)
	if status != http.StatusNoContent {
		t.Fatalf("first result=%d %s", status, body)
	}
	time.Sleep(time.Until(confirmBy) + 50*time.Millisecond)
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/commands/"+commandID+"/result", executed, auth)
	if status != http.StatusNoContent {
		t.Fatalf("exact result replay after deadline=%d %s", status, body)
	}
	changedReceipts := []map[string]any{
		{"ok": true, "result": map[string]any{"summary": "different"}, "rollbackPayload": map[string]any{"signed": "ssh-state"}, "auditReceipt": map[string]any{"different": "result"}},
		{"ok": true, "result": map[string]any{"summary": "SSH hardened"}, "rollbackPayload": map[string]any{"signed": "different-state"}, "auditReceipt": map[string]any{"different": "rollback"}},
		{"ok": true, "result": map[string]any{"summary": "SSH hardened"}, "rollbackPayload": map[string]any{"signed": "ssh-state"}, "auditReceipt": map[string]any{"different": "audit"}},
		{"ok": true, "result": map[string]any{"summary": "SSH hardened"}, "rollbackPayload": map[string]any{"signed": "ssh-state"}, "auditReceipt": map[string]any{"different": "error"}, "error": "different error"},
		{"ok": false, "result": map[string]any{"summary": "SSH hardened"}, "rollbackPayload": map[string]any{"signed": "ssh-state"}, "auditReceipt": map[string]any{"different": "ok"}},
	}
	for index, changed := range changedReceipts {
		changed = signedActionResult(t, x, deviceID, commandID, changed)
		status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/commands/"+commandID+"/result", changed, auth)
		if status != http.StatusConflict {
			t.Fatalf("changed signed receipt %d was incorrectly acknowledged=%d %s", index, status, body)
		}
	}
}

func TestSecurityBoundariesAndUnknownAPI(t *testing.T) {
	x := newTestAPI(t)
	status, body := request(t, http.DefaultClient, "GET", x.server.URL+"/api/v1/does-not-exist", nil, nil)
	if status != 404 || !strings.Contains(http.DetectContentType(body), "text/plain") && !strings.Contains(string(body), `"error"`) {
		t.Fatalf("unknown API=%d %s", status, body)
	}
	x.bootstrapAdmin(t)
	status, body = request(t, x.admin, "POST", x.server.URL+"/api/v1/enrollment-tokens", map[string]any{"name": "csrf"}, map[string]string{"Origin": "https://evil.example"})
	if status != 403 {
		t.Fatalf("cross-origin cookie mutation=%d %s", status, body)
	}
	status, _ = request(t, x.admin, "POST", x.server.URL+"/api/v1/admin/bootstrap", map[string]any{"username": "other", "password": "correct horse battery staple", "bootstrapToken": x.bootstrap}, nil)
	if status != 409 {
		t.Fatalf("second bootstrap=%d", status)
	}
}

func TestCookieOriginCheckIsSchemeful(t *testing.T) {
	x := newTestAPI(t)
	req := httptest.NewRequest(http.MethodPost, "http://example.test/api/v1/actions", nil)
	req.Host = "example.test"
	req.Header.Set("Origin", "https://example.test")
	if x.api.validSameOrigin(req) {
		t.Fatal("HTTPS origin was accepted for an HTTP cookie request")
	}
	req.Header.Set("Origin", "http://example.test")
	if !x.api.validSameOrigin(req) {
		t.Fatal("matching HTTP origin was rejected")
	}
	req.TLS = &tls.ConnectionState{}
	if x.api.validSameOrigin(req) {
		t.Fatal("HTTP origin was accepted for an HTTPS cookie request")
	}
	req.Header.Set("Origin", "https://example.test")
	if !x.api.validSameOrigin(req) {
		t.Fatal("matching HTTPS origin was rejected")
	}
}

func TestAISettingsOmissionPreservesEncryptedCustomHeaders(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	first := map[string]any{
		"protocol": "openai_responses", "baseUrl": "https://ai.example/v1", "model": "model-a",
		"customHeaders": map[string]string{"X-Tenant": "tenant-secret"},
	}
	status, body := request(t, x.admin, http.MethodPut, x.server.URL+"/api/v1/ai/settings", first, nil)
	if status != http.StatusOK {
		t.Fatalf("first settings update=%d %s", status, body)
	}
	status, body = request(t, x.admin, http.MethodPut, x.server.URL+"/api/v1/ai/settings", map[string]any{
		"protocol": "openai_responses", "baseUrl": "https://ai.example/v1", "model": "model-b",
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("second settings update=%d %s", status, body)
	}
	stored, err := x.store.AISettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := x.api.vault.Decrypt(stored.EncryptedHeaders)
	if err != nil || !strings.Contains(plain, "tenant-secret") {
		t.Fatalf("omitted custom headers were lost: plain=%q err=%v", plain, err)
	}
}

func TestAISecretsCannotBeReboundToAnotherEndpointOrigin(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"content":"first"}}]}`)
	}))
	defer first.Close()
	var secondRequests int
	var secondAuthorization string
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondRequests++
		secondAuthorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"content":"second"}}]}`)
	}))
	defer second.Close()

	status, body := request(t, x.admin, http.MethodPut, x.server.URL+"/api/v1/ai/settings", map[string]any{
		"protocol": "openai_chat", "baseUrl": first.URL + "/v1", "model": "model-a", "apiKey": "first-provider-secret",
		"customHeaders": map[string]string{"X-Tenant": "tenant-secret"},
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("initial settings=%d %s", status, body)
	}

	// A path/model update on the same origin retains encrypted credentials.
	status, body = request(t, x.admin, http.MethodPut, x.server.URL+"/api/v1/ai/settings", map[string]any{
		"protocol": "openai_chat", "baseUrl": first.URL + "/v2", "model": "model-b",
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("same-origin update=%d %s", status, body)
	}
	stored, err := x.store.AISettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	key, err := x.api.vault.Decrypt(stored.EncryptedAPIKey)
	if err != nil || key != "first-provider-secret" {
		t.Fatalf("same-origin key=%q err=%v", key, err)
	}
	headers, err := decryptAIHeaders(stored.EncryptedHeaders, x.api.vault)
	if err != nil || headers["X-Tenant"] != "tenant-secret" {
		t.Fatalf("same-origin headers=%v err=%v", headers, err)
	}

	// Neither a saved update nor a one-shot test may send a retained secret to
	// another scheme/host/effective-port.
	status, body = request(t, x.admin, http.MethodPut, x.server.URL+"/api/v1/ai/settings", map[string]any{
		"protocol": "openai_chat", "baseUrl": second.URL + "/v1", "model": "model-c",
	}, nil)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "endpoint_credentials_required") {
		t.Fatalf("cross-origin preserved key=%d %s", status, body)
	}
	status, body = request(t, x.admin, http.MethodPost, x.server.URL+"/api/v1/ai/test", map[string]any{
		"settings": map[string]any{"protocol": "openai_chat", "baseUrl": second.URL + "/v1", "model": "model-c"},
	}, nil)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "API key must be supplied") || secondRequests != 0 {
		t.Fatalf("cross-origin test=%d requests=%d %s", status, secondRequests, body)
	}

	// Re-entering the key is still insufficient while retained custom headers
	// are implicit. An explicit empty object clears them for the new origin.
	status, body = request(t, x.admin, http.MethodPut, x.server.URL+"/api/v1/ai/settings", map[string]any{
		"protocol": "openai_chat", "baseUrl": second.URL + "/v1", "model": "model-c", "apiKey": "second-provider-secret",
	}, nil)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "custom headers") {
		t.Fatalf("implicit cross-origin headers=%d %s", status, body)
	}
	status, body = request(t, x.admin, http.MethodPut, x.server.URL+"/api/v1/ai/settings", map[string]any{
		"protocol": "openai_chat", "baseUrl": second.URL + "/v1", "model": "model-c", "apiKey": "second-provider-secret",
		"customHeaders": map[string]string{},
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("explicit cross-origin credentials=%d %s", status, body)
	}
	status, body = request(t, x.admin, http.MethodPost, x.server.URL+"/api/v1/ai/test", map[string]any{
		"settings": map[string]any{"protocol": "openai_chat", "baseUrl": second.URL + "/v2", "model": "model-c"},
	}, nil)
	if status != http.StatusOK || secondRequests != 1 || secondAuthorization != "Bearer second-provider-secret" {
		t.Fatalf("new-origin test=%d requests=%d authorization=%q %s", status, secondRequests, secondAuthorization, body)
	}
}

func TestLegacyAIEndpointCanBeReplacedWithoutRetainingSecrets(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	encryptedKey, err := x.api.vault.Encrypt("legacy-provider-secret")
	if err != nil {
		t.Fatal(err)
	}
	encryptedHeaders, err := x.api.vault.Encrypt(`{"X-Legacy":"legacy-header-secret"}`)
	if err != nil {
		t.Fatal(err)
	}
	if err = x.store.PutAISettings(context.Background(), store.StoredAISettings{
		Settings: domain.AISettings{
			Protocol:      domain.AIProtocolOpenAIChat,
			BaseURL:       "https://legacy.example/v1?",
			Model:         "legacy-model",
			KeyConfigured: true,
			UpdatedAt:     time.Now().UTC(),
		},
		EncryptedAPIKey:  encryptedKey,
		EncryptedHeaders: encryptedHeaders,
	}); err != nil {
		t.Fatal(err)
	}

	status, body := request(t, x.admin, http.MethodPut, x.server.URL+"/api/v1/ai/settings", map[string]any{
		"protocol": "openai_chat", "baseUrl": "https://replacement.example/v1", "model": "replacement-model",
	}, nil)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "endpoint_credentials_required") {
		t.Fatalf("legacy secret retention was not rejected=%d %s", status, body)
	}

	status, body = request(t, x.admin, http.MethodPut, x.server.URL+"/api/v1/ai/settings", map[string]any{
		"protocol": "openai_chat", "baseUrl": "https://replacement.example/v1", "model": "replacement-model",
		"apiKey": "replacement-provider-secret", "customHeaders": map[string]string{},
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("explicit legacy replacement=%d %s", status, body)
	}
	stored, err := x.store.AISettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	key, err := x.api.vault.Decrypt(stored.EncryptedAPIKey)
	if err != nil || key != "replacement-provider-secret" {
		t.Fatalf("replacement key=%q err=%v", key, err)
	}
	headers, err := decryptAIHeaders(stored.EncryptedHeaders, x.api.vault)
	if err != nil || len(headers) != 0 {
		t.Fatalf("legacy headers survived replacement: %v err=%v", headers, err)
	}
}

func TestContentSecurityPolicyAllowsOnlyBuiltInlineScripts(t *testing.T) {
	body := []byte("self.__next_f.push(['safe bootstrap'])")
	web := t.TempDir()
	html := append([]byte(`<html><script src="/app.js"></script><script>`), body...)
	html = append(html, []byte(`</script></html>`)...)
	if err := os.WriteFile(filepath.Join(web, "index.html"), html, 0o600); err != nil {
		t.Fatal(err)
	}
	hashes, err := inlineScriptHashes(web)
	if err != nil || len(hashes) != 1 {
		t.Fatalf("hashes=%v err=%v", hashes, err)
	}
	digest := sha256.Sum256(body)
	want := base64.StdEncoding.EncodeToString(digest[:])
	if hashes[0] != want {
		t.Fatalf("hash=%q want=%q", hashes[0], want)
	}
	recorder := httptest.NewRecorder()
	securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), hashes).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	policy := recorder.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "'sha256-"+want+"'") || strings.Contains(policy, "script-src 'self' 'unsafe-inline'") {
		t.Fatalf("unsafe or incomplete script policy: %s", policy)
	}
}

func TestEvidenceRedaction(t *testing.T) {
	raw := "password=hunter2 token:abcde eyJabcdefgh.ijklmnop.qrstuvwx"
	got := redactEvidence(raw)
	if strings.Contains(got, "hunter2") || strings.Contains(got, "abcde") || strings.Contains(got, "eyJabcdefgh") {
		t.Fatalf("evidence secret was not redacted: %s", got)
	}
}

func TestApprovalNonceExpires(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, _ := x.enroll(t)
	createdAt := time.Now().UTC()
	x.api.now = func() time.Time { return createdAt }
	status, body := request(t, x.admin, "POST", x.server.URL+"/api/v1/actions", map[string]any{"deviceId": deviceID, "type": "package_security_upgrade", "parameters": map[string]any{"packages": []string{"openssl"}}}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create=%d %s", status, body)
	}
	created := decodeMap(t, body)
	actionID := created["action"].(map[string]any)["id"].(string)
	nonce := created["approvalNonce"].(string)
	x.api.now = func() time.Time { return createdAt.Add(10*time.Minute + time.Nanosecond) }
	status, body = request(t, x.admin, "POST", x.server.URL+"/api/v1/actions/"+actionID+"/approve", map[string]any{"approvalNonce": nonce}, nil)
	if status != http.StatusConflict {
		t.Fatalf("expired approval=%d %s", status, body)
	}
}

func TestApprovedActionCommandExpiresWhileDeviceOffline(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, deviceToken := x.enroll(t)
	approvedAt := time.Now().UTC()
	x.api.now = func() time.Time { return approvedAt }
	status, body := request(t, x.admin, http.MethodPost, x.server.URL+"/api/v1/actions", map[string]any{"deviceId": deviceID, "type": "package_security_upgrade", "parameters": map[string]any{"packages": []string{"openssl"}}}, nil)
	if status != http.StatusCreated {
		t.Fatalf("create=%d %s", status, body)
	}
	created := decodeMap(t, body)
	actionID := created["action"].(map[string]any)["id"].(string)
	nonce := created["approvalNonce"].(string)
	status, body = request(t, x.admin, http.MethodPost, x.server.URL+"/api/v1/actions/"+actionID+"/approve", map[string]any{"approvalNonce": nonce}, nil)
	if status != http.StatusAccepted {
		t.Fatalf("approve=%d %s", status, body)
	}
	if err := x.store.ExpireStaleActionCommands(context.Background(), approvedAt.Add(domain.ActionCommandTTL+time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	status, body = request(t, http.DefaultClient, http.MethodGet, x.server.URL+"/agent/v1/sync?wait=0s", nil, map[string]string{"Authorization": "Bearer " + deviceToken})
	if status != http.StatusOK || !strings.Contains(string(body), `"commands":[]`) {
		t.Fatalf("stale command delivered=%d %s", status, body)
	}
	status, body = request(t, x.admin, http.MethodGet, x.server.URL+"/api/v1/actions/"+actionID, nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"status":"failed"`) || !strings.Contains(string(body), "expired_before_delivery") {
		t.Fatalf("stale action projection=%d %s", status, body)
	}
}

func TestTrustedProxyParsingAndSecureRequest(t *testing.T) {
	x := newTestAPI(t)
	x.api.trustedProxies, _ = parseTrustedProxies([]string{"10.0.0.0/8"})
	req := httptest.NewRequest(http.MethodGet, "http://example.test", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.8, 10.0.0.3")
	req.Header.Set("X-Forwarded-Proto", "https")
	if got := x.api.remoteIP(req).String(); got != "198.51.100.8" {
		t.Fatalf("client IP=%s", got)
	}
	if !x.api.secureRequest(req) {
		t.Fatal("trusted HTTPS proxy was not recognized")
	}
	req.RemoteAddr = "198.51.100.9:1234"
	if got := x.api.remoteIP(req).String(); got != "198.51.100.9" {
		t.Fatalf("untrusted peer spoofed client IP: %s", got)
	}
	if x.api.secureRequest(req) {
		t.Fatal("untrusted peer spoofed forwarded protocol")
	}
}

func TestAdministratorCookieTransportPolicyAndAttributes(t *testing.T) {
	x := newTestAPI(t)

	// A remote/public plaintext deployment must fail before bootstrap mutates
	// either administrator or session state, even if the caller spoofs a
	// loopback Host header.
	remoteBootstrap := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/admin/bootstrap", strings.NewReader(fmt.Sprintf(`{"username":"admin","password":"correct horse battery staple","bootstrapToken":%q}`, x.bootstrap)))
	remoteBootstrap.Header.Set("Content-Type", "application/json")
	remoteBootstrap.Host = "127.0.0.1"
	remoteBootstrap.RemoteAddr = "198.51.100.9:1234"
	remoteBootstrapRecorder := httptest.NewRecorder()
	x.api.Handler().ServeHTTP(remoteBootstrapRecorder, remoteBootstrap)
	if remoteBootstrapRecorder.Code != http.StatusForbidden || !strings.Contains(remoteBootstrapRecorder.Body.String(), "insecure_admin_transport") {
		t.Fatalf("plaintext bootstrap=%d %s", remoteBootstrapRecorder.Code, remoteBootstrapRecorder.Body.String())
	}
	if count, err := x.store.AdminCount(context.Background()); err != nil || count != 0 {
		t.Fatalf("plaintext bootstrap mutated administrators: count=%d err=%v", count, err)
	}

	// A separately selected local listener preserves documented localhost and
	// container-loopback usability and omits only Secure.
	x.bootstrapAdmin(t)
	localLogin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/auth/login", strings.NewReader(`{"Username":"admin","Password":"correct horse battery staple"}`))
	localLogin.Header.Set("Content-Type", "application/json")
	localLogin.Host = "127.0.0.1"
	localRecorder := httptest.NewRecorder()
	x.api.LocalHTTPHandler().ServeHTTP(localRecorder, localLogin)
	if localRecorder.Code != http.StatusOK {
		t.Fatalf("local login=%d %s", localRecorder.Code, localRecorder.Body.String())
	}
	localCookie := cookieByName(t, localRecorder.Result(), sessionCookie)
	if localCookie.Secure || !localCookie.HttpOnly || localCookie.SameSite != http.SameSiteStrictMode || localCookie.Path != "/" {
		t.Fatalf("local cookie attributes=%+v", localCookie)
	}

	localLogout := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/auth/logout", nil)
	localLogout.Host = "127.0.0.1"
	localLogout.AddCookie(localCookie)
	localLogoutRecorder := httptest.NewRecorder()
	x.api.LocalHTTPHandler().ServeHTTP(localLogoutRecorder, localLogout)
	if localLogoutRecorder.Code != http.StatusNoContent {
		t.Fatalf("local logout=%d %s", localLogoutRecorder.Code, localLogoutRecorder.Body.String())
	}
	localDeletion := cookieByName(t, localLogoutRecorder.Result(), sessionCookie)
	if localDeletion.Secure || localDeletion.MaxAge >= 0 || !localDeletion.HttpOnly || localDeletion.SameSite != http.SameSiteStrictMode {
		t.Fatalf("local deletion attributes=%+v", localDeletion)
	}

	// The same loopback Host on the ordinary listener is not sufficient.
	spoofedLogin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/auth/login", strings.NewReader(`{"Username":"admin","Password":"correct horse battery staple"}`))
	spoofedLogin.Header.Set("Content-Type", "application/json")
	spoofedLogin.Host = "127.0.0.1"
	spoofedLogin.RemoteAddr = "198.51.100.9:1234"
	spoofedRecorder := httptest.NewRecorder()
	x.api.Handler().ServeHTTP(spoofedRecorder, spoofedLogin)
	if spoofedRecorder.Code != http.StatusForbidden {
		t.Fatalf("spoofed host selected local cookie transport=%d %s", spoofedRecorder.Code, spoofedRecorder.Body.String())
	}

	// A trusted direct proxy asserting HTTPS receives the secure variant.
	x.api.trustedProxies, _ = parseTrustedProxies([]string{"10.0.0.2/32"})
	proxyLogin := httptest.NewRequest(http.MethodPost, "http://console.example/api/v1/auth/login", strings.NewReader(`{"Username":"admin","Password":"correct horse battery staple"}`))
	proxyLogin.Header.Set("Content-Type", "application/json")
	proxyLogin.Header.Set("X-Forwarded-Proto", "https")
	proxyLogin.RemoteAddr = "10.0.0.2:1234"
	proxyLogin.Host = "console.example"
	proxyRecorder := httptest.NewRecorder()
	x.api.Handler().ServeHTTP(proxyRecorder, proxyLogin)
	if proxyRecorder.Code != http.StatusOK {
		t.Fatalf("proxy login=%d %s", proxyRecorder.Code, proxyRecorder.Body.String())
	}
	secureCookie := cookieByName(t, proxyRecorder.Result(), sessionCookie)
	if !secureCookie.Secure || !secureCookie.HttpOnly || secureCookie.SameSite != http.SameSiteStrictMode || secureCookie.Path != "/" {
		t.Fatalf("secure cookie attributes=%+v", secureCookie)
	}

	untrustedLogin := httptest.NewRequest(http.MethodPost, "http://console.example/api/v1/auth/login", strings.NewReader(`{"Username":"admin","Password":"correct horse battery staple"}`))
	untrustedLogin.Header.Set("Content-Type", "application/json")
	untrustedLogin.Header.Set("X-Forwarded-Proto", "https")
	untrustedLogin.RemoteAddr = "198.51.100.9:1234"
	untrustedLogin.Host = "console.example"
	untrustedRecorder := httptest.NewRecorder()
	x.api.Handler().ServeHTTP(untrustedRecorder, untrustedLogin)
	if untrustedRecorder.Code != http.StatusForbidden {
		t.Fatalf("untrusted proxy selected cookie security=%d %s", untrustedRecorder.Code, untrustedRecorder.Body.String())
	}
}

func TestExistingHTTPAdminSessionStopsOutsideLocalMode(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	login := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/auth/login", strings.NewReader(`{"Username":"admin","Password":"correct horse battery staple"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Host = "127.0.0.1"
	loginRecorder := httptest.NewRecorder()
	x.api.LocalHTTPHandler().ServeHTTP(loginRecorder, login)
	cookie := cookieByName(t, loginRecorder.Result(), sessionCookie)

	statusRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/status", nil)
	statusRequest.Host = "127.0.0.1"
	statusRequest.AddCookie(cookie)
	statusRecorder := httptest.NewRecorder()
	x.api.Handler().ServeHTTP(statusRecorder, statusRequest)
	if statusRecorder.Code != http.StatusOK || !strings.Contains(statusRecorder.Body.String(), `"authenticated":false`) {
		t.Fatalf("insecure status=%d %s", statusRecorder.Code, statusRecorder.Body.String())
	}
	meRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/auth/me", nil)
	meRequest.Host = "127.0.0.1"
	meRequest.AddCookie(cookie)
	meRecorder := httptest.NewRecorder()
	x.api.Handler().ServeHTTP(meRecorder, meRequest)
	if meRecorder.Code != http.StatusForbidden || !strings.Contains(meRecorder.Body.String(), "insecure_admin_transport") {
		t.Fatalf("insecure existing session=%d %s", meRecorder.Code, meRecorder.Body.String())
	}
}

func cookieByName(t *testing.T, response *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("response did not set cookie %q: %v", name, response.Header.Values("Set-Cookie"))
	return nil
}

func TestLoginLimiterBoundsAndExpiresSourceKeys(t *testing.T) {
	limiter := newLoginLimiter()
	limiter.maxKeys = 3
	now := time.Now().UTC()
	for _, key := range []string{"one", "two", "three"} {
		if !limiter.allow(key, now) {
			t.Fatalf("initial key %q rejected", key)
		}
	}
	if limiter.allow("four", now) {
		t.Fatal("source-key capacity was not enforced")
	}
	if !limiter.allow("four", now.Add(11*time.Minute)) {
		t.Fatal("expired keys were not swept")
	}
	if len(limiter.attempts) != 1 {
		t.Fatalf("expired limiter keys retained: %d", len(limiter.attempts))
	}
}

func TestAutomaticDefenseOnlyActivatesAfterSuccessfulReceipt(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, token := x.enroll(t)
	agentHeaders := map[string]string{"Authorization": "Bearer " + token}
	policy := map[string]any{"enabled": true, "emergencyStop": false, "autoBan": true, "failureThreshold": 3, "window": "5m", "banDuration": "15m", "maxBansPerHour": 10, "allowlist": []string{"1.1.1.10"}}
	status, body := request(t, x.admin, "PUT", x.server.URL+"/api/v1/devices/"+deviceID+"/defense-policy", policy, nil)
	if status != 200 {
		t.Fatalf("policy=%d %s", status, body)
	}
	source := "8.8.8.55"
	for i := 0; i < 3; i++ {
		event := signedEventBatch(t, x, deviceID, map[string]any{"events": []map[string]any{{"id": fmt.Sprintf("evt-%d", i), "type": "ssh_auth_failure", "sourceIp": source, "occurredAt": time.Now().UTC()}}})
		status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/events", event, agentHeaders)
		if status != 202 {
			t.Fatalf("event=%d %s", status, body)
		}
	}
	status, body = request(t, http.DefaultClient, "GET", x.server.URL+"/agent/v1/sync?wait=0s", nil, agentHeaders)
	if status != 200 {
		t.Fatal(status)
	}
	var syncOut struct {
		Commands []domain.DeviceCommand `json:"commands"`
	}
	if json.Unmarshal(body, &syncOut) != nil || len(syncOut.Commands) != 1 {
		t.Fatalf("commands %s", body)
	}
	cmd := syncOut.Commands[0]
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+cmd.ID+"/start", map[string]any{}, agentHeaders)
	if status != 200 || !strings.Contains(string(body), `"authorized":true`) {
		t.Fatalf("failure action start=%d %s", status, body)
	}
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+cmd.ID+"/result", signedActionResult(t, x, deviceID, cmd.ID, map[string]any{"ok": false, "error": "nft unavailable"}), agentHeaders)
	if status != 204 {
		t.Fatalf("failure=%d %s", status, body)
	}
	if _, err := x.store.ActiveBan(context.Background(), deviceID, source, time.Now()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("failed action activated ban: %v", err)
	}
	source = "8.8.8.56"
	for i := 0; i < 3; i++ {
		event := signedEventBatch(t, x, deviceID, map[string]any{"events": []map[string]any{{"id": fmt.Sprintf("evt-success-%d", i), "type": "ssh_auth_failure", "sourceIp": source, "occurredAt": time.Now().UTC()}}})
		status, _ = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/events", event, agentHeaders)
		if status != 202 {
			t.Fatal(status)
		}
	}
	_, body = request(t, http.DefaultClient, "GET", x.server.URL+"/agent/v1/sync?wait=0s", nil, agentHeaders)
	_ = json.Unmarshal(body, &syncOut)
	cmd = syncOut.Commands[0]
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+cmd.ID+"/start", map[string]any{}, agentHeaders)
	if status != 200 || !strings.Contains(string(body), `"authorized":true`) {
		t.Fatalf("successful action start=%d %s", status, body)
	}
	var actionPayload struct {
		ActionID   string          `json:"actionId"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if json.Unmarshal(cmd.Payload, &actionPayload) != nil || actionPayload.ActionID == "" {
		t.Fatalf("invalid action command payload: %s", cmd.Payload)
	}
	okResult := signedActionResult(t, x, deviceID, cmd.ID, map[string]any{"ok": true, "result": map[string]any{"summary": "banned"}, "rollbackPayload": map[string]any{"signed": "state"}, "auditReceipt": map[string]any{"actionId": actionPayload.ActionID, "type": "temporary_ip_ban", "operation": "execute", "parametersDigest": action.ParametersDigest(actionPayload.Parameters), "success": true}})
	status, _ = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+cmd.ID+"/result", okResult, agentHeaders)
	if status != 204 {
		t.Fatal(status)
	}
	status, _ = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+cmd.ID+"/result", okResult, agentHeaders)
	if status != 204 {
		t.Fatalf("idempotent auto result=%d", status)
	}
	if _, err := x.store.ActiveBan(context.Background(), deviceID, source, time.Now()); err != nil {
		t.Fatalf("successful ban inactive: %v", err)
	}
}

func TestUntrustedFlatLogEventsNeverAuthorizeAutomaticDefense(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, token := x.enroll(t)
	agentHeaders := map[string]string{"Authorization": "Bearer " + token}
	policy := map[string]any{"enabled": true, "emergencyStop": false, "autoBan": true, "failureThreshold": 3, "window": "5m", "banDuration": "15m", "maxBansPerHour": 10, "allowlist": []string{"198.51.100.10"}}
	status, body := request(t, x.admin, http.MethodPut, x.server.URL+"/api/v1/devices/"+deviceID+"/defense-policy", policy, nil)
	if status != http.StatusOK {
		t.Fatalf("policy=%d %s", status, body)
	}
	unsigned := map[string]any{"events": []map[string]any{
		{"id": "evt-untrusted-flat-log-1", "type": "ssh_auth_failure_untrusted", "sourceIp": "203.0.113.88", "occurredAt": time.Now().UTC(), "payload": map[string]any{"source": "auth.log"}},
		{"id": "evt-untrusted-flat-log-2", "type": "ssh_auth_failure_untrusted", "sourceIp": "203.0.113.88", "occurredAt": time.Now().UTC(), "payload": map[string]any{"source": "auth.log"}},
		{"id": "evt-untrusted-flat-log-3", "type": "ssh_auth_failure_untrusted", "sourceIp": "203.0.113.88", "occurredAt": time.Now().UTC(), "payload": map[string]any{"source": "auth.log"}},
	}}
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/events", unsigned, agentHeaders)
	if status != http.StatusUnauthorized || !strings.Contains(string(body), "invalid_device_proof") {
		t.Fatalf("bearer-only events were accepted=%d %s", status, body)
	}
	event := signedEventBatch(t, x, deviceID, unsigned)
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/events", event, agentHeaders)
	if status != http.StatusAccepted {
		t.Fatalf("event=%d %s", status, body)
	}
	status, body = request(t, http.DefaultClient, http.MethodGet, x.server.URL+"/agent/v1/sync?wait=0s", nil, agentHeaders)
	if status != http.StatusOK || !strings.Contains(string(body), `"commands":[]`) || strings.Contains(string(body), "temporary_ip_ban") {
		t.Fatalf("untrusted flat-log event authorized a command=%d %s", status, body)
	}
}

func TestAdminSecurityEventsExposeUnverifiedObservationsWithPagination(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, token := x.enroll(t)
	status, body := request(t, http.DefaultClient, http.MethodGet, x.server.URL+"/api/v1/security-events", nil, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("security event history was not admin-only: %d %s", status, body)
	}
	now := time.Now().UTC()
	payload := signedEventBatch(t, x, deviceID, map[string]any{"events": []map[string]any{
		{"id": "evt-visible-flat-log", "type": "ssh_auth_failure_untrusted", "sourceIp": "8.8.8.8", "occurredAt": now, "payload": map[string]any{"source": "auth.log", "trust": "unverified", "automaticActionEligible": false}},
		{"id": "evt-visible-oversized-line", "type": "ssh_auth_log_line_oversized_untrusted", "occurredAt": now.Add(time.Second), "payload": map[string]any{"source": "auth.log", "trust": "unverified", "automaticActionEligible": false, "reason": "line exceeded 256 KiB and was discarded"}},
	}})
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/events", payload, map[string]string{"Authorization": "Bearer " + token})
	if status != http.StatusAccepted || !strings.Contains(string(body), `"accepted":2`) || !strings.Contains(string(body), `"decisions":[]`) {
		t.Fatalf("unverified observations were rejected or influenced defense=%d %s", status, body)
	}

	status, body = request(t, x.admin, http.MethodGet, x.server.URL+"/api/v1/security-events?deviceId="+deviceID+"&limit=1", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("first security event page=%d %s", status, body)
	}
	first := decodeMap(t, body)
	items, ok := first["items"].([]any)
	if !ok || len(items) != 1 || first["nextCursor"] == "" {
		t.Fatalf("first page was not bounded/paginated: %s", body)
	}
	firstItem := items[0].(map[string]any)
	if firstItem["type"] != "ssh_auth_log_line_oversized_untrusted" {
		t.Fatalf("unexpected first event: %s", body)
	}
	cursor := first["nextCursor"].(string)
	status, body = request(t, x.admin, http.MethodGet, x.server.URL+"/api/v1/security-events?deviceId="+deviceID+"&limit=1&cursor="+cursor, nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), "evt-visible-flat-log") || !strings.Contains(string(body), `"nextCursor":""`) {
		t.Fatalf("second security event page=%d %s", status, body)
	}
	status, body = request(t, x.admin, http.MethodGet, x.server.URL+"/api/v1/security-events?deviceId="+deviceID+"&type=ssh_auth_log_line_oversized_untrusted&limit=100", nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), "evt-visible-oversized-line") || strings.Contains(string(body), "evt-visible-flat-log") {
		t.Fatalf("security event filters failed=%d %s", status, body)
	}
	inserted, err := x.store.AddSecurityEvent(context.Background(), domain.SecurityEvent{ID: "evt-visible-correlation-health", DeviceID: deviceID, Type: store.SecurityEventTypeCorrelationCapacityDegraded, OccurredAt: now.Add(2 * time.Second), Payload: json.RawMessage(`{"severity":"critical","status":"degraded","automaticActionEligible":false}`)})
	if err != nil || !inserted {
		t.Fatalf("insert degraded health signal: inserted=%v err=%v", inserted, err)
	}
	status, body = request(t, x.admin, http.MethodGet, x.server.URL+"/api/v1/security-events?deviceId="+deviceID+"&type="+store.SecurityEventTypeCorrelationCapacityDegraded, nil, nil)
	if status != http.StatusOK || !strings.Contains(string(body), "evt-visible-correlation-health") || !strings.Contains(string(body), `"severity":"critical"`) {
		t.Fatalf("critical correlation health was not admin-visible=%d %s", status, body)
	}
	for _, suffix := range []string{"?limit=101", "?cursor=not-base64!", "?type=unsupported"} {
		status, body = request(t, x.admin, http.MethodGet, x.server.URL+"/api/v1/security-events"+suffix, nil, nil)
		if status != http.StatusBadRequest {
			t.Fatalf("invalid security event query accepted: %s => %d %s", suffix, status, body)
		}
	}
}

func TestEveryAgentSensorEventPassesSignedAdmission(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, token := x.enroll(t)
	eventTypes := []string{
		"ssh_auth_failure", "ssh_auth_success", "ssh_auth_failure_untrusted", "ssh_auth_log_line_oversized_untrusted",
		"identity_state_changed", "access_trust_changed", "file_integrity_changed", "schedule_definition_changed",
		"service_definition_changed", "startup_definition_changed", "library_injection_changed", "kernel_policy_changed",
		"container_configuration_changed", "network_listener_opened", "network_listener_closed",
		"network_sensor_capacity_degraded", "network_sensor_capacity_restored",
		"suspicious_privileged_process_started", "deleted_executable_process_running",
		"process_sensor_capacity_degraded", "process_sensor_capacity_restored",
	}
	now := time.Now().UTC()
	events := make([]map[string]any, 0, len(eventTypes))
	for index, eventType := range eventTypes {
		events = append(events, map[string]any{
			"id":         fmt.Sprintf("evt-admission-%02d", index),
			"type":       eventType,
			"occurredAt": now.Add(time.Duration(index) * time.Millisecond),
			"payload":    map[string]any{"automaticActionEligible": false},
		})
	}
	payload := signedEventBatch(t, x, deviceID, map[string]any{"events": events})
	status, body := request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/events", payload, map[string]string{"Authorization": "Bearer " + token})
	if status != http.StatusAccepted || !strings.Contains(string(body), fmt.Sprintf(`"accepted":%d`, len(events))) {
		t.Fatalf("one or more Agent sensor event types were rejected=%d %s", status, body)
	}
}

func TestSignedAgentPayloadLargerThanLegacyOneMiBLimitIsAccepted(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, token := x.enroll(t)
	events := make([]map[string]any, 500)
	now := time.Now().UTC()
	for i := range events {
		events[i] = map[string]any{
			"id": fmt.Sprintf("evt_large_%03d", i), "type": "ssh_auth_failure_untrusted",
			"sourceIp": "8.8.8.8", "occurredAt": now,
			"payload": map[string]any{"source": "structured-journal", "padding": strings.Repeat("x", 2200)},
		}
	}
	payload := signedEventBatch(t, x, deviceID, map[string]any{"events": events})
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) <= 1<<20 || len(encoded) >= maxJSONRequestBody {
		t.Fatalf("test payload size %d does not exercise the aligned request window", len(encoded))
	}
	status, body := request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/events", payload, map[string]string{"Authorization": "Bearer " + token})
	if status != http.StatusAccepted {
		t.Fatalf("valid signed payload was rejected at %d bytes: status=%d body=%s", len(encoded), status, body)
	}
}

func TestSecurityEventBatchValidationIsAtomicAndExpiredHeadIsAcknowledged(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, token := x.enroll(t)
	auth := map[string]string{"Authorization": "Bearer " + token}
	now := time.Now().UTC()
	invalid := signedEventBatch(t, x, deviceID, map[string]any{"events": []map[string]any{
		{"id": "evt_atomic_valid", "type": "ssh_auth_failure_untrusted", "sourceIp": "8.8.8.8", "occurredAt": now},
		{"id": "evt_atomic_invalid", "type": "unsupported", "sourceIp": "8.8.8.8", "occurredAt": now},
	}})
	status, body := request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/events", invalid, auth)
	if status != http.StatusBadRequest {
		t.Fatalf("invalid batch=%d %s", status, body)
	}
	stored, err := x.store.CountSecurityEvents(context.Background(), deviceID, "ssh_auth_failure_untrusted", "8.8.8.8", now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Fatalf("invalid batch committed a valid prefix: %d", stored)
	}

	expired := signedEventBatch(t, x, deviceID, map[string]any{"events": []map[string]any{{
		"id": "evt_expired_queue_head", "type": "ssh_auth_failure_untrusted", "sourceIp": "8.8.8.8", "occurredAt": now.Add(-8 * 24 * time.Hour),
	}}})
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/events", expired, auth)
	if status != http.StatusAccepted || !strings.Contains(string(body), `"droppedExpired":1`) {
		t.Fatalf("expired authenticated event poisoned FIFO=%d %s", status, body)
	}
	future := signedEventBatch(t, x, deviceID, map[string]any{"events": []map[string]any{{
		"id": "evt_future_queue_head", "type": "ssh_auth_failure_untrusted", "sourceIp": "8.8.8.8", "occurredAt": now.Add(24 * time.Hour),
	}}})
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/events", future, auth)
	if status != http.StatusAccepted || !strings.Contains(string(body), `"droppedFuture":1`) {
		t.Fatalf("future clock-skewed event poisoned FIFO=%d %s", status, body)
	}
	fresh := signedEventBatch(t, x, deviceID, map[string]any{"events": []map[string]any{{
		"id": "evt_after_expired", "type": "ssh_auth_failure_untrusted", "sourceIp": "8.8.8.8", "occurredAt": now,
	}}})
	status, body = request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/events", fresh, auth)
	if status != http.StatusAccepted {
		t.Fatalf("fresh event after expired head=%d %s", status, body)
	}
}

func TestEveryAgentRequestRequiresProofAndNonceReplayIsRejected(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, token := x.enroll(t)
	body := map[string]any{"Name": "node", "Hostname": "host", "OS": "linux", "Arch": "amd64", "AgentVersion": "test"}
	status, response := request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/heartbeat", body, map[string]string{
		"Authorization": "Bearer " + token, "X-Test-Unsigned-Agent-Request": "1",
	})
	if status != http.StatusUnauthorized || !strings.Contains(string(response), "invalid_device_proof") {
		t.Fatalf("bearer-only heartbeat was accepted=%d %s", status, response)
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := fmt.Sprintf("%d", time.Now().UTC().UnixMilli())
	nonce := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdefgh"))
	signature, err := identity.SignAgentRequest(x.identityKeys[deviceID], identity.AgentRequestProof{
		DeviceID: deviceID, Method: http.MethodPost, RequestURI: "/agent/v1/heartbeat", Timestamp: timestamp, Nonce: nonce, Body: encoded,
	})
	if err != nil {
		t.Fatal(err)
	}
	send := func() (int, []byte) {
		req, requestErr := http.NewRequest(http.MethodPost, x.server.URL+"/agent/v1/heartbeat", bytes.NewReader(encoded))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-WitShield-Timestamp", timestamp)
		req.Header.Set("X-WitShield-Nonce", nonce)
		req.Header.Set("X-WitShield-Signature", signature)
		resp, requestErr := http.DefaultClient.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		defer resp.Body.Close()
		data, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		return resp.StatusCode, data
	}
	if status, response = send(); status != http.StatusOK {
		t.Fatalf("valid signed heartbeat=%d %s", status, response)
	}
	if status, response = send(); status != http.StatusUnauthorized || !strings.Contains(string(response), "replayed_device_proof") {
		t.Fatalf("signed nonce replay was accepted=%d %s", status, response)
	}
}

func TestBearerOnlyFloodCannotConsumeAuthenticatedDeviceBudget(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	_, token := x.enroll(t)
	body := map[string]any{"Name": "node", "Hostname": "host", "OS": "linux", "Arch": "amd64", "AgentVersion": "test"}
	for attempt := 0; attempt < 120; attempt++ {
		status, response := request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/heartbeat", body, map[string]string{
			"Authorization": "Bearer " + token, "X-Test-Unsigned-Agent-Request": "1",
		})
		if status != http.StatusUnauthorized {
			t.Fatalf("unsigned flood attempt %d=%d %s", attempt, status, response)
		}
	}
	status, response := request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/heartbeat", body, map[string]string{"Authorization": "Bearer " + token})
	if status != http.StatusOK {
		t.Fatalf("unsigned bearer holder exhausted real device budget=%d %s", status, response)
	}
}

func TestAuthenticatedAgentGlobalBudgetPrecedesNonceAndHeartbeatWrites(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	_, firstToken := x.enroll(t)
	_, secondToken := x.enroll(t)
	now := time.Now().UTC()
	// Fill all but two global request units using the same per-device ceiling
	// production uses. This models a large fleet, not one oversized synthetic
	// attempt, and exercises the atomic device+global accounting path.
	remaining := agentGlobalRequestsPerMinute - 2
	for index := 0; remaining > 0; index++ {
		cost := min(agentDeviceRequestsPerMinute, remaining)
		if !x.api.agentRequestLimiter.allowDeviceAndGlobal(fmt.Sprintf("preseed_%d", index), now, cost, agentDeviceRequestsPerMinute, agentGlobalRequestsPerMinute) {
			t.Fatalf("could not preseed global request budget at remaining=%d", remaining)
		}
		remaining -= cost
	}
	body := map[string]any{"Name": "node", "Hostname": "host", "OS": "linux", "Arch": "amd64", "AgentVersion": "test"}
	for index, token := range []string{firstToken, secondToken} {
		status, response := request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/heartbeat", body, map[string]string{"Authorization": "Bearer " + token})
		if status != http.StatusOK {
			t.Fatalf("final allowed global request %d=%d %s", index, status, response)
		}
	}
	before, err := x.store.CountAgentRequestNonces(context.Background())
	if err != nil || before != 2 {
		t.Fatalf("unexpected nonce count before global rejection: count=%d err=%v", before, err)
	}
	status, response := request(t, http.DefaultClient, http.MethodPost, x.server.URL+"/agent/v1/heartbeat", body, map[string]string{"Authorization": "Bearer " + firstToken})
	if status != http.StatusTooManyRequests || !strings.Contains(string(response), "agent_rate_limited") {
		t.Fatalf("global authenticated request budget was bypassed=%d %s", status, response)
	}
	after, err := x.store.CountAgentRequestNonces(context.Background())
	if err != nil || after != before {
		t.Fatalf("global rejection performed a nonce write: before=%d after=%d err=%v", before, after, err)
	}
}

func TestEmergencyStopCancelsQueuedPolicyActionsAndPendingCountsTowardLimit(t *testing.T) {
	x := newTestAPI(t)
	x.bootstrapAdmin(t)
	deviceID, token := x.enroll(t)
	auth := map[string]string{"Authorization": "Bearer " + token}
	policy := map[string]any{"enabled": true, "emergencyStop": false, "autoBan": true, "failureThreshold": 3, "window": "5m", "banDuration": "15m", "maxBansPerHour": 1, "allowlist": []string{"1.1.1.10"}}
	status, body := request(t, x.admin, "PUT", x.server.URL+"/api/v1/devices/"+deviceID+"/defense-policy", policy, nil)
	if status != 200 {
		t.Fatalf("policy=%d %s", status, body)
	}
	first := signedEventBatch(t, x, deviceID, map[string]any{"events": []map[string]any{
		{"id": "evt-first-1", "type": "ssh_auth_failure", "sourceIp": "8.8.8.60", "occurredAt": time.Now().UTC()},
		{"id": "evt-first-2", "type": "ssh_auth_failure", "sourceIp": "8.8.8.60", "occurredAt": time.Now().UTC()},
		{"id": "evt-first-3", "type": "ssh_auth_failure", "sourceIp": "8.8.8.60", "occurredAt": time.Now().UTC()},
	}})
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/events", first, auth)
	if status != 202 {
		t.Fatalf("first=%d %s", status, body)
	}
	// Replaying an already persisted event must not create another action.
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/events", first, auth)
	if status != 202 {
		t.Fatalf("duplicate=%d %s", status, body)
	}
	second := signedEventBatch(t, x, deviceID, map[string]any{"events": []map[string]any{
		{"id": "evt-second-1", "type": "ssh_auth_failure", "sourceIp": "8.8.8.61", "occurredAt": time.Now().UTC()},
		{"id": "evt-second-2", "type": "ssh_auth_failure", "sourceIp": "8.8.8.61", "occurredAt": time.Now().UTC()},
		{"id": "evt-second-3", "type": "ssh_auth_failure", "sourceIp": "8.8.8.61", "occurredAt": time.Now().UTC()},
	}})
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/events", second, auth)
	if status != 202 || !strings.Contains(string(body), "hourly ban safety limit reached") {
		t.Fatalf("pending ban did not consume rate budget: %d %s", status, body)
	}
	status, body = request(t, http.DefaultClient, "GET", x.server.URL+"/agent/v1/sync?wait=0s", nil, auth)
	var syncOut struct {
		Commands []domain.DeviceCommand `json:"commands"`
	}
	if status != 200 || json.Unmarshal(body, &syncOut) != nil || len(syncOut.Commands) != 1 {
		t.Fatalf("queued commands=%d %s", status, body)
	}
	commandID := syncOut.Commands[0].ID
	status, body = request(t, x.admin, "POST", x.server.URL+"/api/v1/devices/"+deviceID+"/emergency-stop", map[string]any{"active": true}, nil)
	if status != 200 || !strings.Contains(string(body), `"cancelledQueuedActions":1`) {
		t.Fatalf("emergency=%d %s", status, body)
	}
	status, body = request(t, http.DefaultClient, "POST", x.server.URL+"/agent/v1/commands/"+commandID+"/start", map[string]any{}, auth)
	if status != 200 || !strings.Contains(string(body), `"authorized":false`) {
		t.Fatalf("cancelled command was authorized: %d %s", status, body)
	}
}
