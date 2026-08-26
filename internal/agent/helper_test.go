package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/witkitlab/witshield/internal/action"
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

func TestHelperClientMarksLostResponseAfterRequestAsIndeterminate(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "witshield-helper-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "helper.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer connection.Close()
		_, readErr := bufio.NewReader(connection).ReadString('\n')
		serverErr <- readErr
	}()

	client := HelperClient{Socket: socket, Token: "local-token"}
	_, err = client.Run(context.Background(), "cmd-lost-response", "act-lost-response", action.TypePackageSecurityUpgrade, action.OperationExecute, json.RawMessage(`{"packages":["openssl"]}`), nil)
	if !errors.Is(err, ErrHelperExecutionIndeterminate) {
		t.Fatalf("lost post-request response was not indeterminate: %v", err)
	}
	if err = <-serverErr; err != nil {
		t.Fatalf("fake helper did not receive the complete request: %v", err)
	}
}
