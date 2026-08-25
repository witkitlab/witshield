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
