package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type fakeRunner struct {
	mu    sync.Mutex
	calls []Command
	run   func(Command) (CommandResult, error)
}

func (runner *fakeRunner) Run(_ context.Context, command Command) (CommandResult, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.calls = append(runner.calls, command)
	if runner.run == nil {
		return CommandResult{}, nil
	}
	return runner.run(command)
}

func (runner *fakeRunner) snapshotCalls() []Command {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return append([]Command(nil), runner.calls...)
}

func TestPackageSecurityUpgradeLifecycleUsesOnlyExplicitPackages(t *testing.T) {
	versions := map[string]string{"openssl": "1.0-1", "openssh-server": "2.0-1"}
	runner := &fakeRunner{}
	runner.run = func(command Command) (CommandResult, error) {
		switch command.Path {
		case "/fake/apt-get":
			if len(command.Args) == 1 && command.Args[0] == "--version" {
				return CommandResult{Stdout: "apt 2"}, nil
			}
			if len(command.Args) > 0 && command.Args[0] == "--simulate" {
				return CommandResult{Stdout: "Inst openssl"}, nil
			}
			if containsArgument(command.Args, "--allow-downgrades") {
				for _, argument := range command.Args {
					parts := strings.SplitN(argument, "=", 2)
					if len(parts) == 2 {
						versions[parts[0]] = parts[1]
					}
				}
				return CommandResult{}, nil
			}
			for _, name := range []string{"openssl", "openssh-server"} {
				if containsArgument(command.Args, name) {
					versions[name] += ".security"
				}
			}
			return CommandResult{}, nil
		case "/fake/dpkg-query":
			name := command.Args[len(command.Args)-1]
			version, exists := versions[name]
			if !exists {
				return CommandResult{}, errors.New("not installed")
			}
			return CommandResult{Stdout: "ii \t" + version + "\n"}, nil
		default:
			return CommandResult{}, fmt.Errorf("unexpected executable %q", command.Path)
		}
	}
	playbook := NewPackageSecurityUpgradePlaybook(runner, "/fake/apt-get", "/fake/dpkg-query")
	engine, _ := NewEngine(playbook)
	parameters := json.RawMessage(`{"packages":["openssl","openssh-server"]}`)
	receipt := engine.Run(context.Background(), Request{
		ActionID: "pkg-action", Actor: "tester", Type: TypePackageSecurityUpgrade,
		Operation: OperationExecute, Parameters: parameters,
	})
	if !receipt.Success {
		t.Fatalf("upgrade failed: %s, steps=%#v", receipt.Error, receipt.Steps)
	}
	if versions["openssl"] != "1.0-1.security" || versions["openssh-server"] != "2.0-1.security" {
		t.Fatalf("packages were not upgraded: %#v", versions)
	}
	rollback := engine.Run(context.Background(), Request{
		ActionID: "pkg-action", Actor: "tester", Type: TypePackageSecurityUpgrade,
		Operation: OperationRollback, Parameters: parameters, State: receipt.State,
	})
	if !rollback.Success {
		t.Fatalf("rollback failed: %s", rollback.Error)
	}
	if versions["openssl"] != "1.0-1" || versions["openssh-server"] != "2.0-1" {
		t.Fatalf("versions were not restored: %#v", versions)
	}
	for _, command := range runner.snapshotCalls() {
		if command.Path != "/fake/apt-get" && command.Path != "/fake/dpkg-query" {
			t.Fatalf("unexpected command path: %#v", command)
		}
	}
}

func TestPackageSecurityUpgradeRejectsArgumentInjectionAndDuplicates(t *testing.T) {
	playbook := NewPackageSecurityUpgradePlaybook(&fakeRunner{}, "/fake/apt-get", "/fake/dpkg-query")
	badLists := []string{
		`{"packages":["--option"]}`,
		`{"packages":["openssl=evil"]}`,
		`{"packages":["openssl;id"]}`,
		`{"packages":["openssl","openssl"]}`,
		`{"packages":[]}`,
		`{"packages":["openssl"],"command":"id"}`,
	}
	for _, raw := range badLists {
		if err := playbook.Validate(json.RawMessage(raw)); err == nil {
			t.Errorf("unsafe package request accepted: %s", raw)
		}
	}
}

func containsArgument(arguments []string, expected string) bool {
	for _, argument := range arguments {
		if argument == expected {
			return true
		}
	}
	return false
}
