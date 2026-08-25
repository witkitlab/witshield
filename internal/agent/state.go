package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/witkitlab/witshield/internal/identity"
)

type State struct {
	DeviceID           string `json:"deviceId"`
	DeviceToken        string `json:"deviceToken"`
	IdentityPublicKey  string `json:"identityPublicKey"`
	IdentityPrivateKey string `json:"identityPrivateKey"`
	ObserverOnly       bool   `json:"observerOnly"`
}

// PendingEnrollment persists the identity before the first network request.
// It intentionally does not contain the enrollment token: native installers
// keep that separately until the final state has been committed.
type PendingEnrollment struct {
	IdentityPublicKey  string `json:"identityPublicKey"`
	IdentityPrivateKey string `json:"identityPrivateKey"`
}

func NewIdentity() (string, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.RawStdEncoding.EncodeToString(pub), base64.RawStdEncoding.EncodeToString(priv), nil
}
func LoadState(path string) (State, error) {
	var x State
	b, err := readPrivateJSON(path)
	if err != nil {
		return x, err
	}
	if err = decodeStrictJSON(b, &x); err != nil {
		return x, errors.New("invalid agent state")
	}
	if x.DeviceID == "" || len(x.DeviceToken) < 20 {
		return x, errors.New("agent state is incomplete")
	}
	if err = identity.ValidateKeyPair(x.IdentityPublicKey, x.IdentityPrivateKey); err != nil {
		return x, errors.New("agent state identity is invalid")
	}
	return x, nil
}
func SaveState(path string, x State) error {
	if x.DeviceID == "" || len(x.DeviceToken) < 20 {
		return errors.New("agent state is incomplete")
	}
	if err := identity.ValidateKeyPair(x.IdentityPublicKey, x.IdentityPrivateKey); err != nil {
		return errors.New("agent state identity is invalid")
	}
	return writePrivateJSONAtomic(path, x)
}

func LoadPendingEnrollment(path string) (PendingEnrollment, error) {
	var pending PendingEnrollment
	b, err := readPrivateJSON(path)
	if err != nil {
		return pending, err
	}
	if err = decodeStrictJSON(b, &pending); err != nil {
		return pending, errors.New("invalid pending enrollment state")
	}
	if err = identity.ValidateKeyPair(pending.IdentityPublicKey, pending.IdentityPrivateKey); err != nil {
		return pending, errors.New("pending enrollment identity is invalid")
	}
	return pending, nil
}

func SavePendingEnrollment(path string, pending PendingEnrollment) error {
	if err := identity.ValidateKeyPair(pending.IdentityPublicKey, pending.IdentityPrivateKey); err != nil {
		return errors.New("pending enrollment identity is invalid")
	}
	return writePrivateJSONAtomic(path, pending)
}

func readPrivateJSON(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("private agent state must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private agent state permissions must be 0600 or stricter")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > 64*1024 {
		return nil, errors.New("private agent state is too large")
	}
	return b, nil
}

func decodeStrictJSON(b []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func writePrivateJSONAtomic(path string, value any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".witshield-private-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return err
	}
	if n, writeErr := f.Write(b); writeErr != nil || n != len(b) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		return writeErr
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	if err = syncDirectory(dir); err != nil {
		return err
	}
	ok = true
	return nil
}

// syncDirectory makes an already durable file rename or removal survive a
// sudden power loss. File Sync alone does not persist the containing directory
// entry on Unix filesystems.
func syncDirectory(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}
