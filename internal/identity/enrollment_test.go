package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

func TestEnrollmentProofAuthenticatesEveryField(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicEncoded := base64.RawStdEncoding.EncodeToString(pub)
	privateEncoded := base64.RawStdEncoding.EncodeToString(priv)
	proof := EnrollmentProof{ChallengeID: "challenge-id", Challenge: "challenge-value", EnrollmentToken: "secret-enrollment-token", Name: "node", Hostname: "host", OS: "linux", Arch: "amd64", AgentVersion: "test", IdentityPublicKey: publicEncoded, ScanInterval: "24h0m0s"}
	signature, err := SignEnrollmentProof(privateEncoded, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyEnrollmentProof(publicEncoded, signature, proof); err != nil {
		t.Fatal(err)
	}
	proof.Hostname = "different"
	if err = VerifyEnrollmentProof(publicEncoded, signature, proof); err == nil {
		t.Fatal("metadata mutation unexpectedly preserved a valid signature")
	}
}

func TestValidateKeyPairRejectsDifferentPrivateKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	if err := ValidateKeyPair(base64.RawStdEncoding.EncodeToString(pub), base64.RawStdEncoding.EncodeToString(otherPriv)); err == nil {
		t.Fatal("different private key accepted")
	}
}

func TestCommandResultProofAuthenticatesEveryField(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicEncoded := base64.RawStdEncoding.EncodeToString(pub)
	privateEncoded := base64.RawStdEncoding.EncodeToString(priv)
	proof := CommandResultProof{
		DeviceID:        "dev_1",
		CommandID:       "cmd_1",
		OK:              true,
		Result:          []byte(`{"summary":"applied"}`),
		RollbackPayload: []byte(`{"state":"before"}`),
		AuditReceipt:    []byte(`{"success":true}`),
	}
	signature, err := SignCommandResult(privateEncoded, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyCommandResult(publicEncoded, signature, proof); err != nil {
		t.Fatal(err)
	}

	mutations := []CommandResultProof{
		{DeviceID: "dev_2", CommandID: proof.CommandID, OK: proof.OK, Result: proof.Result, RollbackPayload: proof.RollbackPayload, AuditReceipt: proof.AuditReceipt},
		{DeviceID: proof.DeviceID, CommandID: "cmd_2", OK: proof.OK, Result: proof.Result, RollbackPayload: proof.RollbackPayload, AuditReceipt: proof.AuditReceipt},
		{DeviceID: proof.DeviceID, CommandID: proof.CommandID, OK: false, Result: proof.Result, RollbackPayload: proof.RollbackPayload, AuditReceipt: proof.AuditReceipt},
		{DeviceID: proof.DeviceID, CommandID: proof.CommandID, OK: proof.OK, Result: []byte(`{"summary":"forged"}`), RollbackPayload: proof.RollbackPayload, AuditReceipt: proof.AuditReceipt},
		{DeviceID: proof.DeviceID, CommandID: proof.CommandID, OK: proof.OK, Result: proof.Result, RollbackPayload: []byte(`{"state":"forged"}`), AuditReceipt: proof.AuditReceipt},
		{DeviceID: proof.DeviceID, CommandID: proof.CommandID, OK: proof.OK, Result: proof.Result, RollbackPayload: proof.RollbackPayload, AuditReceipt: []byte(`{"success":false}`)},
		{DeviceID: proof.DeviceID, CommandID: proof.CommandID, OK: proof.OK, Result: proof.Result, RollbackPayload: proof.RollbackPayload, AuditReceipt: proof.AuditReceipt, Error: "forged"},
	}
	for i, mutation := range mutations {
		if err = VerifyCommandResult(publicEncoded, signature, mutation); err == nil {
			t.Fatalf("mutation %d unexpectedly preserved a valid signature", i)
		}
	}
}

func TestSecurityEventBatchProofAuthenticatesOrderAndFields(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicEncoded := base64.RawStdEncoding.EncodeToString(pub)
	privateEncoded := base64.RawStdEncoding.EncodeToString(priv)
	now := time.Now().UTC().Truncate(time.Microsecond)
	proof := SecurityEventBatchProof{DeviceID: "dev_1", Events: []domain.SecurityEvent{
		{ID: "evt_1", Type: "ssh_auth_failure", SourceIP: "203.0.113.1", OccurredAt: now, Payload: []byte(`{"source":"journald"}`)},
		{ID: "evt_2", Type: "ssh_auth_failure", SourceIP: "203.0.113.2", OccurredAt: now.Add(time.Second), Payload: []byte(`{"source":"journald"}`)},
	}}
	signature, err := SignSecurityEventBatch(privateEncoded, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifySecurityEventBatch(publicEncoded, signature, proof); err != nil {
		t.Fatal(err)
	}

	mutated := proof
	mutated.Events = append([]domain.SecurityEvent(nil), proof.Events...)
	mutated.Events[0].SourceIP = "203.0.113.99"
	if err = VerifySecurityEventBatch(publicEncoded, signature, mutated); err == nil {
		t.Fatal("event field mutation unexpectedly preserved a valid signature")
	}
	reordered := SecurityEventBatchProof{DeviceID: proof.DeviceID, Events: []domain.SecurityEvent{proof.Events[1], proof.Events[0]}}
	if err = VerifySecurityEventBatch(publicEncoded, signature, reordered); err == nil {
		t.Fatal("event reorder unexpectedly preserved a valid signature")
	}
	wrongDevice := proof
	wrongDevice.DeviceID = "dev_2"
	if err = VerifySecurityEventBatch(publicEncoded, signature, wrongDevice); err == nil {
		t.Fatal("device mutation unexpectedly preserved a valid signature")
	}
}

func TestAgentRequestProofAuthenticatesEveryField(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicEncoded := base64.RawStdEncoding.EncodeToString(pub)
	privateEncoded := base64.RawStdEncoding.EncodeToString(priv)
	proof := AgentRequestProof{DeviceID: "dev_1", Method: "POST", RequestURI: "/agent/v1/reports?mode=full", Timestamp: "1787702400000", Nonce: "nonce-value", Body: []byte(`{"id":"rpt_1"}`)}
	signature, err := SignAgentRequest(privateEncoded, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyAgentRequest(publicEncoded, signature, proof); err != nil {
		t.Fatal(err)
	}
	mutations := []AgentRequestProof{
		{DeviceID: "dev_2", Method: proof.Method, RequestURI: proof.RequestURI, Timestamp: proof.Timestamp, Nonce: proof.Nonce, Body: proof.Body},
		{DeviceID: proof.DeviceID, Method: "PUT", RequestURI: proof.RequestURI, Timestamp: proof.Timestamp, Nonce: proof.Nonce, Body: proof.Body},
		{DeviceID: proof.DeviceID, Method: proof.Method, RequestURI: "/agent/v1/reports?mode=other", Timestamp: proof.Timestamp, Nonce: proof.Nonce, Body: proof.Body},
		{DeviceID: proof.DeviceID, Method: proof.Method, RequestURI: proof.RequestURI, Timestamp: "1787702400001", Nonce: proof.Nonce, Body: proof.Body},
		{DeviceID: proof.DeviceID, Method: proof.Method, RequestURI: proof.RequestURI, Timestamp: proof.Timestamp, Nonce: "other-nonce", Body: proof.Body},
		{DeviceID: proof.DeviceID, Method: proof.Method, RequestURI: proof.RequestURI, Timestamp: proof.Timestamp, Nonce: proof.Nonce, Body: []byte(`{"id":"rpt_2"}`)},
	}
	for index, mutation := range mutations {
		if err = VerifyAgentRequest(publicEncoded, signature, mutation); err == nil {
			t.Fatalf("request mutation %d unexpectedly preserved a valid signature", index)
		}
	}
}

func TestCheckedUint32RejectsOverflow(t *testing.T) {
	value, err := checkedUint32(maxUint32Value)
	if err != nil || uint64(value) != maxUint32Value {
		t.Fatalf("maximum uint32 was not preserved: value=%d err=%v", value, err)
	}
	if _, err = checkedUint32(maxUint32Value + 1); err == nil {
		t.Fatal("overflowing proof length was accepted")
	}
}
