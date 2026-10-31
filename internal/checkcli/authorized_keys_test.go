package checkcli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAuthorizedKeyRejectsSymlinksNonregularAndOversizedFiles(t *testing.T) {
	for _, kind := range []string{"escape-relative", "escape-absolute", "internal-symlink", "directory", "fifo", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			keyDir := filepath.Join(dir, "keys")
			if err := os.Mkdir(keyDir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(keyDir, "authorized_keys")
			key := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest fixture\n")
			switch kind {
			case "escape-relative", "escape-absolute":
				outside := filepath.Join(dir, "outside-key")
				if err := os.WriteFile(outside, key, 0o600); err != nil {
					t.Fatal(err)
				}
				target := outside
				if kind == "escape-relative" {
					target = "../outside-key"
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "internal-symlink":
				if err := os.WriteFile(filepath.Join(keyDir, "another-key"), key, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("another-key", path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				data := append(key, []byte(strings.Repeat("#", maxAuthorizedKeyBytes-len(key)+1))...)
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			result := make(chan bool, 1)
			go func() { result <- HasAuthorizedKey(path) }()
			select {
			case ready := <-result:
				if ready {
					t.Fatalf("%s counted as an authorized key", kind)
				}
			case <-time.After(time.Second):
				t.Fatalf("checking %s blocked", kind)
			}
		})
	}
}

func TestAuthorizedKeyAcceptsOrdinaryOwnerAtSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	key := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest fixture\n")
	data := append(key, []byte(strings.Repeat("#", maxAuthorizedKeyBytes-len(key)))...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		// Root scans also need to accept the sudo user's own public-key file.
		if err := os.Chown(path, 1000, 1000); err != nil {
			t.Fatal(err)
		}
	}
	if !HasAuthorizedKey(path) {
		t.Fatal("ordinary account's bounded regular public-key file was rejected")
	}
}
