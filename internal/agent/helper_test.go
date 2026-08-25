package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadHelperTokenModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	token := strings.Repeat("a", 64)
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadHelperToken(path); err != nil || got != token {
		t.Fatalf("%q %v", got, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHelperToken(path); err != nil {
		t.Fatalf("0640 rejected: %v", err)
	}
	for _, mode := range []os.FileMode{0o660, 0o644, 0o400} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadHelperToken(path); err == nil {
			t.Fatalf("mode %o accepted", mode)
		}
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadHelperToken(link); err == nil {
		t.Fatal("symlink accepted")
	}
}
