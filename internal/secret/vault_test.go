package secret

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestVaultRoundTripAndTamper(t *testing.T) {
	v, err := New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := v.Encrypt("sk-super-secret")
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext == "sk-super-secret" {
		t.Fatal("secret was not encrypted")
	}
	plain, err := v.Decrypt(ciphertext)
	if err != nil || plain != "sk-super-secret" {
		t.Fatalf("round trip: %q, %v", plain, err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(ciphertext[3:])
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	tampered := "v1:" + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := v.Decrypt(tampered); err == nil {
		t.Fatal("tamper should fail")
	}
}

func TestLoadOrCreateKeyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "master.key")
	a, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("key did not persist")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestLoadKeyRejectsSymlinkAndWidePermissions(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(link); err == nil {
		t.Fatal("symlink accepted")
	}
	path := filepath.Join(dir, "wide")
	v := bytes.Repeat([]byte{2}, 32)
	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(v)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("wide permissions accepted")
	}
}
