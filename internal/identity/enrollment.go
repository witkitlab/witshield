package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

const enrollmentProofVersion = "witshield-enrollment-proof-v1"
const commandResultProofVersion = "witshield-command-result-v1"
const securityEventProofVersion = "witshield-security-event-batch-v1"
const agentRequestProofVersion = "witshield-agent-request-v1"

// EnrollmentProof contains the exact values authenticated by the Agent's
// persistent Ed25519 identity. The enrollment token itself is never included
// in the signed message; its fixed-size digest binds the proof without making
// accidental diagnostic output disclose the credential.
type EnrollmentProof struct {
	ChallengeID       string
	Challenge         string
	EnrollmentToken   string
	Name              string
	Hostname          string
	OS                string
	Arch              string
	AgentVersion      string
	IdentityPublicKey string
	ScanInterval      string
	ObserverOnly      bool
}

func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

func DecodePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	return ed25519.PrivateKey(raw), nil
}

func ValidateKeyPair(publicEncoded, privateEncoded string) error {
	pub, err := DecodePublicKey(publicEncoded)
	if err != nil {
		return err
	}
	priv, err := DecodePrivateKey(privateEncoded)
	if err != nil {
		return err
	}
	if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
		return errors.New("Ed25519 public and private keys do not match")
	}
	return nil
}

func SignEnrollmentProof(privateEncoded string, proof EnrollmentProof) (string, error) {
	priv, err := DecodePrivateKey(privateEncoded)
	if err != nil {
		return "", err
	}
	message, err := enrollmentProofMessage(proof)
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(priv, message)
	return base64.RawStdEncoding.EncodeToString(signature), nil
}

func VerifyEnrollmentProof(publicEncoded, signatureEncoded string, proof EnrollmentProof) error {
	pub, err := DecodePublicKey(publicEncoded)
	if err != nil {
		return err
	}
	signature, err := base64.RawStdEncoding.DecodeString(signatureEncoded)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature")
	}
	message, err := enrollmentProofMessage(proof)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, message, signature) {
		return errors.New("invalid enrollment proof")
	}
	return nil
}

func enrollmentProofMessage(proof EnrollmentProof) ([]byte, error) {
	tokenDigest := sha256.Sum256([]byte(proof.EnrollmentToken))
	observerOnly := []byte{0}
	if proof.ObserverOnly {
		observerOnly[0] = 1
	}
	fields := [][]byte{
		[]byte(enrollmentProofVersion),
		[]byte(proof.ChallengeID),
		[]byte(proof.Challenge),
		tokenDigest[:],
		[]byte(proof.Name),
		[]byte(proof.Hostname),
		[]byte(proof.OS),
		[]byte(proof.Arch),
		[]byte(proof.AgentVersion),
		[]byte(proof.IdentityPublicKey),
		[]byte(proof.ScanInterval),
		observerOnly,
	}
	return encodeLengthPrefixedFields(fields)
}

// AgentRequestProof authenticates every post-enrollment HTTP request. The
// bearer token locates a device, while its durable Ed25519 identity proves the
// exact method, route and body and a persistent nonce prevents replay.
type AgentRequestProof struct {
	DeviceID   string
	Method     string
	RequestURI string
	Timestamp  string
	Nonce      string
	Body       []byte
}

func SignAgentRequest(privateEncoded string, proof AgentRequestProof) (string, error) {
	priv, err := DecodePrivateKey(privateEncoded)
	if err != nil {
		return "", err
	}
	message, err := agentRequestProofMessage(proof)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, message)), nil
}

func VerifyAgentRequest(publicEncoded, signatureEncoded string, proof AgentRequestProof) error {
	pub, err := DecodePublicKey(publicEncoded)
	if err != nil {
		return err
	}
	signature, err := base64.RawStdEncoding.DecodeString(signatureEncoded)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature")
	}
	message, err := agentRequestProofMessage(proof)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, message, signature) {
		return errors.New("invalid agent request proof")
	}
	return nil
}

func agentRequestProofMessage(proof AgentRequestProof) ([]byte, error) {
	bodyDigest := sha256.Sum256(proof.Body)
	return encodeLengthPrefixedFields([][]byte{
		[]byte(agentRequestProofVersion), []byte(proof.DeviceID), []byte(proof.Method),
		[]byte(proof.RequestURI), []byte(proof.Timestamp), []byte(proof.Nonce), bodyDigest[:],
	})
}

// CommandResultProof binds an action result to the durable device identity and
// exact command. The Controller verifies it before accepting any privileged
// action transition, so possession of a bearer device token alone cannot forge
// a successful (or failed) Helper result.
type CommandResultProof struct {
	DeviceID        string
	CommandID       string
	OK              bool
	Result          []byte
	RollbackPayload []byte
	AuditReceipt    []byte
	Error           string
}

func SignCommandResult(privateEncoded string, proof CommandResultProof) (string, error) {
	priv, err := DecodePrivateKey(privateEncoded)
	if err != nil {
		return "", err
	}
	message, err := commandResultProofMessage(proof)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, message)), nil
}

func VerifyCommandResult(publicEncoded, signatureEncoded string, proof CommandResultProof) error {
	pub, err := DecodePublicKey(publicEncoded)
	if err != nil {
		return err
	}
	signature, err := base64.RawStdEncoding.DecodeString(signatureEncoded)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature")
	}
	message, err := commandResultProofMessage(proof)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, message, signature) {
		return errors.New("invalid command result proof")
	}
	return nil
}

func commandResultProofMessage(proof CommandResultProof) ([]byte, error) {
	ok := []byte{0}
	if proof.OK {
		ok[0] = 1
	}
	fields := [][]byte{
		[]byte(commandResultProofVersion), []byte(proof.DeviceID), []byte(proof.CommandID), ok,
		proof.Result, proof.RollbackPayload, proof.AuditReceipt, []byte(proof.Error),
	}
	return encodeLengthPrefixedFields(fields)
}

// SecurityEventBatchProof authenticates every ordered event field before an
// event is allowed to participate in automatic defense. This is deliberately
// separate from bearer transport authentication: stealing a device token must
// not be enough to manufacture a policy trigger.
type SecurityEventBatchProof struct {
	DeviceID string
	Events   []domain.SecurityEvent
}

func SignSecurityEventBatch(privateEncoded string, proof SecurityEventBatchProof) (string, error) {
	priv, err := DecodePrivateKey(privateEncoded)
	if err != nil {
		return "", err
	}
	message, err := securityEventBatchProofMessage(proof)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, message)), nil
}

func VerifySecurityEventBatch(publicEncoded, signatureEncoded string, proof SecurityEventBatchProof) error {
	pub, err := DecodePublicKey(publicEncoded)
	if err != nil {
		return err
	}
	signature, err := base64.RawStdEncoding.DecodeString(signatureEncoded)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature")
	}
	message, err := securityEventBatchProofMessage(proof)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, message, signature) {
		return errors.New("invalid security event proof")
	}
	return nil
}

func securityEventBatchProofMessage(proof SecurityEventBatchProof) ([]byte, error) {
	fields := [][]byte{[]byte(securityEventProofVersion), []byte(proof.DeviceID)}
	var count [4]byte
	eventCount, err := checkedUint32(uint64(len(proof.Events)))
	if err != nil {
		return nil, errors.New("security event batch is too large")
	}
	binary.BigEndian.PutUint32(count[:], eventCount)
	fields = append(fields, count[:])
	for _, event := range proof.Events {
		fields = append(fields,
			[]byte(event.ID), []byte(event.Type), []byte(event.SourceIP),
			[]byte(event.OccurredAt.UTC().Format(time.RFC3339Nano)), event.Payload,
		)
	}
	return encodeLengthPrefixedFields(fields)
}

const maxUint32Value = uint64(1<<32 - 1)

func checkedUint32(value uint64) (uint32, error) {
	if value > maxUint32Value {
		return 0, errors.New("value exceeds uint32")
	}
	return uint32(value), nil
}

func encodeLengthPrefixedFields(fields [][]byte) ([]byte, error) {
	var out bytes.Buffer
	for _, field := range fields {
		length, err := checkedUint32(uint64(len(field)))
		if err != nil {
			return nil, errors.New("signed proof field is too large")
		}
		var encodedLength [4]byte
		binary.BigEndian.PutUint32(encodedLength[:], length)
		_, _ = out.Write(encodedLength[:])
		_, _ = out.Write(field)
	}
	return out.Bytes(), nil
}
