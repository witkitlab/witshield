package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPendingEnrollmentIsPrivateAndReusable(t *testing.T) {
	pub, priv, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nested", "pending-enrollment.json")
	if err = SavePendingEnrollment(path, PendingEnrollment{IdentityPublicKey: pub, IdentityPrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("pending state mode=%#o, want 0600", got)
	}
	loaded, err := LoadPendingEnrollment(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.IdentityPublicKey != pub || loaded.IdentityPrivateKey != priv {
		t.Fatal("pending identity did not round-trip")
	}
}

func TestPendingEnrollmentRejectsLoosePermissions(t *testing.T) {
	pub, priv, _ := NewIdentity()
	path := filepath.Join(t.TempDir(), "pending-enrollment.json")
	if err := os.WriteFile(path, []byte(`{"identityPublicKey":"`+pub+`","identityPrivateKey":"`+priv+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPendingEnrollment(path); err == nil {
		t.Fatal("world-readable pending private key accepted")
	}
}
