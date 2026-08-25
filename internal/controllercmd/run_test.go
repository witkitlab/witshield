package controllercmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/witkitlab/witshield/internal/store"
)

func TestSeedEnrollmentConsumesControllerTokenCopy(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	path := filepath.Join(dir, "initial-enrollment.token")
	if err = os.WriteFile(path, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = seedEnrollment(context.Background(), db, path); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("controller token copy still exists: %v", err)
	}
	items, err := db.ListEnrollmentTokens(context.Background())
	if err != nil || len(items) != 1 || items[0].MaxUses != 1 {
		t.Fatalf("tokens=%v err=%v", items, err)
	}
}

func TestLoopbackListenAddress(t *testing.T) {
	tests := map[string]bool{
		"127.0.0.1:8080":  true,
		"127.42.0.1:8080": true,
		"[::1]:8080":      true,
		"localhost:8080":  true,
		"LOCALHOST.:8080": true,
		"0.0.0.0:8080":    false,
		":8080":           false,
		"10.0.0.2:8080":   false,
		"invalid":         false,
	}
	for address, want := range tests {
		if got := loopbackListenAddress(address); got != want {
			t.Errorf("loopbackListenAddress(%q)=%v want=%v", address, got, want)
		}
	}
}

func TestIsolatedLocalListenAddress(t *testing.T) {
	tests := map[string]bool{
		"admin-listener:8081": true,
		"127.0.0.1:8081":      true,
		"[::1]:8081":          true,
		"0.0.0.0:8081":        false,
		"[::]:8081":           false,
		":8081":               false,
		"admin-listener":      false,
	}
	for address, want := range tests {
		if got := isolatedLocalListenAddress(address); got != want {
			t.Errorf("isolatedLocalListenAddress(%q)=%v want=%v", address, got, want)
		}
	}
}
