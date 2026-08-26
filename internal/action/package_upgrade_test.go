package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

type packageTestEnvironment struct {
	base     string
	hookPath string
}

func newPackageTestEnvironment(t *testing.T) *packageTestEnvironment {
	t.Helper()
	hookPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	hookPath, err = filepath.EvalSymlinks(hookPath)
	if err != nil {
		t.Fatal(err)
	}
	return &packageTestEnvironment{base: filepath.Join(t.TempDir(), "plans"), hookPath: hookPath}
}

func (environment *packageTestEnvironment) playbook(t *testing.T, runner Runner) *PackageSecurityUpgradePlaybook {
	t.Helper()
	playbook, err := NewPackageSecurityUpgradePlaybook(runner, "/fake/apt-get", "/fake/dpkg-query", environment.hookPath, environment.base)
	if err != nil {
		t.Fatal(err)
	}
	return playbook
}

func (environment *packageTestEnvironment) runGuard(command Command, transitions map[string]packageVersionTransition) error {
	transactionDir := ""
	prefix := "DPkg::Pre-Install-Pkgs::=" + environment.hookPath + " apt-plan-guard "
	for _, argument := range command.Args {
		if strings.HasPrefix(argument, prefix) {
			transactionDir = strings.TrimPrefix(argument, prefix)
			break
		}
	}
	if transactionDir == "" {
		return errors.New("test APT command omitted its package plan guard")
	}
	if !containsArgument(command.Args, "APT::Get::Mark-Auto=true") {
		return errors.New("test APT command would change package auto/manual ownership")
	}
	var input strings.Builder
	input.WriteString("VERSION 3\nAPT::Architecture=amd64\n\n")
	for _, name := range sortedTransitionKeys(transitions) {
		transition := transitions[name]
		base, architecture := testPackageParts(name)
		oldArchitecture, oldMultiArch := architecture, "none"
		if transition.From == "-" {
			oldArchitecture, oldMultiArch = "-", "none"
		}
		newArchitecture, newMultiArch := architecture, "none"
		if transition.To == "-" {
			newArchitecture, newMultiArch = "-", "none"
		}
		fmt.Fprintf(&input, "%s %s %s %s %s %s %s %s /var/cache/apt/archives/%s.deb\n", base, transition.From, oldArchitecture, oldMultiArch, transition.Direction, transition.To, newArchitecture, newMultiArch, base)
		fmt.Fprintf(&input, "%s %s %s %s %s %s %s %s **CONFIGURE**\n", base, transition.From, oldArchitecture, oldMultiArch, transition.Direction, transition.To, newArchitecture, newMultiArch)
	}
	return RunPackagePlanGuard(strings.NewReader(input.String()), transactionDir, environment.base)
}

func testPackageParts(name string) (string, string) {
	base, architecture, found := strings.Cut(name, ":")
	if !found {
		return name, "amd64"
	}
	return base, architecture
}

func transitionsTo(current map[string]string, targets map[string]string, direction string) map[string]packageVersionTransition {
	transitions := make(map[string]packageVersionTransition, len(targets))
	for name, target := range targets {
		transitions[name] = packageVersionTransition{From: current[name], To: target, Direction: direction}
	}
	return transitions
}

func TestPackageSecurityUpgradeLifecycleUsesLockedExplicitPlan(t *testing.T) {
	environment := newPackageTestEnvironment(t)
	versions := map[string]string{"openssl": "1.0-1", "openssh-server": "2.0-1"}
	runner := &fakeRunner{}
	runner.run = func(command Command) (CommandResult, error) {
		switch command.Path {
		case "/fake/apt-get":
			if containsArgument(command.Args, "--version") {
				return CommandResult{Stdout: "apt 2"}, nil
			}
			if containsArgument(command.Args, "--simulate") {
				return CommandResult{Stdout: "Inst openssl"}, nil
			}
			if containsArgument(command.Args, "--allow-downgrades") {
				targets := packageTargets(command.Args)
				if err := environment.runGuard(command, transitionsTo(versions, targets, ">")); err != nil {
					return CommandResult{}, err
				}
				for name, version := range targets {
					versions[name] = version
				}
				return CommandResult{}, nil
			}
			targets := map[string]string{"openssl": "1.0-1.security", "openssh-server": "2.0-1.security"}
			if err := environment.runGuard(command, transitionsTo(versions, targets, "<")); err != nil {
				return CommandResult{}, err
			}
			for name, version := range targets {
				versions[name] = version
			}
			return CommandResult{}, nil
		case "/fake/dpkg-query":
			return fakePackageQuery(command, versions)
		default:
			return CommandResult{}, fmt.Errorf("unexpected executable %q", command.Path)
		}
	}
	playbook := environment.playbook(t, runner)
	engine, _ := NewEngine(playbook)
	parameters := json.RawMessage(`{"packages":["openssl","openssh-server"]}`)
	receipt := engine.Run(context.Background(), Request{ActionID: "pkg-action", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationExecute, Parameters: parameters})
	if !receipt.Success || versions["openssl"] != "1.0-1.security" || versions["openssh-server"] != "2.0-1.security" {
		t.Fatalf("guarded upgrade failed: receipt=%#v versions=%#v", receipt, versions)
	}
	rollback := engine.Run(context.Background(), Request{ActionID: "pkg-action", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationRollback, Parameters: parameters, State: receipt.State})
	if !rollback.Success || versions["openssl"] != "1.0-1" || versions["openssh-server"] != "2.0-1" {
		t.Fatalf("guarded rollback failed: receipt=%#v versions=%#v", rollback, versions)
	}
}

func TestPackageSecurityUpgradePartialFailureRestoresAllExplicitTransitions(t *testing.T) {
	environment := newPackageTestEnvironment(t)
	versions := map[string]string{"app": "1.0-1", "libdependency": "1.0-1"}
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		switch command.Path {
		case "/fake/dpkg-query":
			return fakePackageQuery(command, versions)
		case "/fake/apt-get":
			if containsArgument(command.Args, "--version") || containsArgument(command.Args, "--simulate") {
				return CommandResult{}, nil
			}
			if containsArgument(command.Args, "--allow-downgrades") {
				targets := packageTargets(command.Args)
				if err := environment.runGuard(command, transitionsTo(versions, targets, ">")); err != nil {
					return CommandResult{}, err
				}
				for name, version := range targets {
					versions[name] = version
				}
				return CommandResult{}, nil
			}
			targets := map[string]string{"app": "2.0-1", "libdependency": "2.0-1"}
			if err := environment.runGuard(command, transitionsTo(versions, targets, "<")); err != nil {
				return CommandResult{}, err
			}
			versions["app"] = targets["app"]
			versions["libdependency"] = targets["libdependency"]
			return CommandResult{}, errors.New("dependency configuration failed")
		default:
			return CommandResult{}, fmt.Errorf("unexpected executable %q", command.Path)
		}
	}}
	playbook := environment.playbook(t, runner)
	engine, _ := NewEngine(playbook)
	receipt := engine.Run(context.Background(), Request{ActionID: "pkg-partial", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationExecute, Parameters: json.RawMessage(`{"packages":["app","libdependency"]}`)})
	if receipt.Success || receipt.Indeterminate || len(receipt.State) != 0 || versions["app"] != "1.0-1" || versions["libdependency"] != "1.0-1" {
		t.Fatalf("partial transaction was not provably restored: receipt=%#v versions=%#v", receipt, versions)
	}
}

func TestPackageSecurityUpgradeRejectsUnlistedInstalledDependencyBeforeMutation(t *testing.T) {
	environment := newPackageTestEnvironment(t)
	versions := map[string]string{"app": "1.0-1", "libdependency": "1.0-1"}
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		switch command.Path {
		case "/fake/dpkg-query":
			return fakePackageQuery(command, versions)
		case "/fake/apt-get":
			if containsArgument(command.Args, "--version") || containsArgument(command.Args, "--simulate") {
				return CommandResult{}, nil
			}
			plan := map[string]packageVersionTransition{
				"app":           {From: "1.0-1", To: "2.0-1", Direction: "<"},
				"libdependency": {From: "1.0-1", To: "2.0-1", Direction: "<"},
			}
			return CommandResult{}, environment.runGuard(command, plan)
		default:
			return CommandResult{}, fmt.Errorf("unexpected executable %q", command.Path)
		}
	}}
	playbook := environment.playbook(t, runner)
	engine, _ := NewEngine(playbook)
	receipt := engine.Run(context.Background(), Request{ActionID: "pkg-unlisted-installed-dependency", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationExecute, Parameters: json.RawMessage(`{"packages":["app"]}`)})
	if receipt.Success || receipt.Indeterminate || len(receipt.State) != 0 || versions["app"] != "1.0-1" || versions["libdependency"] != "1.0-1" || !strings.Contains(receipt.Error, "outside the explicitly authorized package set") {
		t.Fatalf("unlisted installed dependency was not rejected before mutation: receipt=%#v versions=%#v", receipt, versions)
	}
}

func TestPackageSecurityUpgradeRejectsNewDependencyBeforeMutation(t *testing.T) {
	environment := newPackageTestEnvironment(t)
	versions := map[string]string{"app": "1.0-1"}
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		switch command.Path {
		case "/fake/dpkg-query":
			return fakePackageQuery(command, versions)
		case "/fake/apt-get":
			if containsArgument(command.Args, "--version") || containsArgument(command.Args, "--simulate") {
				return CommandResult{}, nil
			}
			plan := map[string]packageVersionTransition{
				"app":    {From: "1.0-1", To: "2.0-1", Direction: "<"},
				"newdep": {From: "-", To: "1.0-1", Direction: "<"},
			}
			return CommandResult{}, environment.runGuard(command, plan)
		default:
			return CommandResult{}, fmt.Errorf("unexpected executable %q", command.Path)
		}
	}}
	playbook := environment.playbook(t, runner)
	engine, _ := NewEngine(playbook)
	receipt := engine.Run(context.Background(), Request{ActionID: "pkg-new-dependency", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationExecute, Parameters: json.RawMessage(`{"packages":["app"]}`)})
	if receipt.Success || receipt.Indeterminate || len(receipt.State) != 0 || len(versions) != 1 || versions["app"] != "1.0-1" {
		t.Fatalf("non-reversible dependency was not rejected before mutation: receipt=%#v versions=%#v", receipt, versions)
	}
}

func TestPackageApplyGuardRejectsConcurrentExternalAPTChange(t *testing.T) {
	environment := newPackageTestEnvironment(t)
	versions := map[string]string{"app": "1.0-1", "libdependency": "1.0-1"}
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		switch command.Path {
		case "/fake/dpkg-query":
			return fakePackageQuery(command, versions)
		case "/fake/apt-get":
			if containsArgument(command.Args, "--version") || containsArgument(command.Args, "--simulate") {
				return CommandResult{}, nil
			}
			// An external apt transaction wins the frontend lock after WitShield's
			// baseline read. The locked hook sees the new predecessor and aborts.
			versions["libdependency"] = "1.5-1"
			plan := map[string]packageVersionTransition{
				"app":           {From: "1.0-1", To: "2.0-1", Direction: "<"},
				"libdependency": {From: "1.5-1", To: "2.0-1", Direction: "<"},
			}
			return CommandResult{}, environment.runGuard(command, plan)
		default:
			return CommandResult{}, fmt.Errorf("unexpected executable %q", command.Path)
		}
	}}
	playbook := environment.playbook(t, runner)
	engine, _ := NewEngine(playbook)
	receipt := engine.Run(context.Background(), Request{ActionID: "pkg-apply-race", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationExecute, Parameters: json.RawMessage(`{"packages":["app","libdependency"]}`)})
	if receipt.Success || receipt.Indeterminate || len(receipt.State) != 0 || versions["app"] != "1.0-1" || versions["libdependency"] != "1.5-1" {
		t.Fatalf("concurrent external upgrade was attributed or overwritten: receipt=%#v versions=%#v", receipt, versions)
	}
}

func TestPackageRollbackGuardRejectsConcurrentExternalAPTChange(t *testing.T) {
	environment := newPackageTestEnvironment(t)
	versions := map[string]string{"openssl": "1.0-1"}
	tracingRollback := false
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		switch command.Path {
		case "/fake/dpkg-query":
			return fakePackageQuery(command, versions)
		case "/fake/apt-get":
			if containsArgument(command.Args, "--version") || containsArgument(command.Args, "--simulate") {
				return CommandResult{}, nil
			}
			if containsArgument(command.Args, "--allow-downgrades") {
				tracingRollback = true
				versions["openssl"] = "3.0-1"
				plan := map[string]packageVersionTransition{"openssl": {From: "3.0-1", To: "1.0-1", Direction: ">"}}
				return CommandResult{}, environment.runGuard(command, plan)
			}
			plan := map[string]packageVersionTransition{"openssl": {From: "1.0-1", To: "2.0-1", Direction: "<"}}
			if err := environment.runGuard(command, plan); err != nil {
				return CommandResult{}, err
			}
			versions["openssl"] = "2.0-1"
			return CommandResult{}, nil
		default:
			return CommandResult{}, fmt.Errorf("unexpected executable %q", command.Path)
		}
	}}
	playbook := environment.playbook(t, runner)
	engine, _ := NewEngine(playbook)
	parameters := json.RawMessage(`{"packages":["openssl"]}`)
	apply := engine.Run(context.Background(), Request{ActionID: "pkg-rollback-race", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationExecute, Parameters: parameters})
	if !apply.Success {
		t.Fatal(apply.Error)
	}
	rollback := engine.Run(context.Background(), Request{ActionID: "pkg-rollback-race", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationRollback, Parameters: parameters, State: apply.State})
	if !tracingRollback || rollback.Success || !rollback.Indeterminate || versions["openssl"] != "3.0-1" {
		t.Fatalf("locked rollback overwrote an external upgrade: receipt=%#v versions=%#v", rollback, versions)
	}
}

func TestPackageRollbackRetryProvesCommittedRestoreAfterReadbackLoss(t *testing.T) {
	environment := newPackageTestEnvironment(t)
	versions := map[string]string{"openssl": "1.0-1"}
	failReadback := false
	downgrades := 0
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		switch command.Path {
		case "/fake/dpkg-query":
			if isFullInventoryQuery(command) && failReadback {
				failReadback = false
				return CommandResult{}, errors.New("injected readback loss")
			}
			return fakePackageQuery(command, versions)
		case "/fake/apt-get":
			if containsArgument(command.Args, "--version") || containsArgument(command.Args, "--simulate") {
				return CommandResult{}, nil
			}
			if containsArgument(command.Args, "--allow-downgrades") {
				targets := packageTargets(command.Args)
				if err := environment.runGuard(command, transitionsTo(versions, targets, ">")); err != nil {
					return CommandResult{}, err
				}
				downgrades++
				versions["openssl"] = "1.0-1"
				failReadback = true
				return CommandResult{}, nil
			}
			plan := map[string]packageVersionTransition{"openssl": {From: "1.0-1", To: "2.0-1", Direction: "<"}}
			if err := environment.runGuard(command, plan); err != nil {
				return CommandResult{}, err
			}
			versions["openssl"] = "2.0-1"
			return CommandResult{}, nil
		default:
			return CommandResult{}, fmt.Errorf("unexpected executable %q", command.Path)
		}
	}}
	playbook := environment.playbook(t, runner)
	engine, _ := NewEngine(playbook)
	parameters := json.RawMessage(`{"packages":["openssl"]}`)
	apply := engine.Run(context.Background(), Request{ActionID: "pkg-retry", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationExecute, Parameters: parameters})
	if !apply.Success {
		t.Fatal(apply.Error)
	}
	first := engine.Run(context.Background(), Request{ActionID: "pkg-retry", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationRollback, Parameters: parameters, State: apply.State})
	if first.Success || !first.Indeterminate || versions["openssl"] != "1.0-1" {
		t.Fatalf("first rollback did not model readback loss: receipt=%#v versions=%#v", first, versions)
	}
	second := engine.Run(context.Background(), Request{ActionID: "pkg-retry", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationRollback, Parameters: parameters, State: apply.State})
	if !second.Success || downgrades != 1 {
		t.Fatalf("idempotent rollback retry failed: receipt=%#v downgrades=%d", second, downgrades)
	}
}

func TestPackageRollbackMissingGuardReceiptIsIndeterminate(t *testing.T) {
	environment := newPackageTestEnvironment(t)
	versions := map[string]string{"app": "1.0-1", "dependency": "1.0-1"}
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		switch command.Path {
		case "/fake/dpkg-query":
			return fakePackageQuery(command, versions)
		case "/fake/apt-get":
			if containsArgument(command.Args, "--version") || containsArgument(command.Args, "--simulate") {
				return CommandResult{}, nil
			}
			if containsArgument(command.Args, "--allow-downgrades") {
				// Model a broken rollback integration that mutates both the
				// requested package and an unrecorded dependency without running
				// the locked pre-install hook.
				versions["app"] = "1.0-1"
				versions["dependency"] = "0.5-1"
				return CommandResult{}, nil
			}
			plan := map[string]packageVersionTransition{"app": {From: "1.0-1", To: "2.0-1", Direction: "<"}}
			if err := environment.runGuard(command, plan); err != nil {
				return CommandResult{}, err
			}
			versions["app"] = "2.0-1"
			return CommandResult{}, nil
		default:
			return CommandResult{}, fmt.Errorf("unexpected executable %q", command.Path)
		}
	}}
	playbook := environment.playbook(t, runner)
	engine, _ := NewEngine(playbook)
	parameters := json.RawMessage(`{"packages":["app"]}`)
	apply := engine.Run(context.Background(), Request{ActionID: "pkg-rollback-missing-guard", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationExecute, Parameters: parameters})
	if !apply.Success {
		t.Fatalf("guarded apply failed: %#v", apply)
	}
	rollback := engine.Run(context.Background(), Request{ActionID: "pkg-rollback-missing-guard", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationRollback, Parameters: parameters, State: apply.State})
	if rollback.Success || !rollback.Indeterminate || versions["app"] != "1.0-1" || versions["dependency"] != "0.5-1" || !strings.Contains(rollback.Error, "rollback plan is unavailable") {
		t.Fatalf("receipt-less rollback was classified as successful: receipt=%#v versions=%#v", rollback, versions)
	}
}

func TestPackageSecurityUpgradeAcceptsResidualConfigRowsInDpkgInventory(t *testing.T) {
	environment := newPackageTestEnvironment(t)
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		if command.Path != "/fake/dpkg-query" {
			return CommandResult{}, fmt.Errorf("unexpected executable %q", command.Path)
		}
		return CommandResult{Stdout: "ii \topenssl\tamd64\t3.0.1-1\nrc \ttzdata\tall\t2026a-1\n"}, nil
	}}
	playbook := environment.playbook(t, runner)
	versions, err := playbook.installedPackageVersions(context.Background())
	if err != nil || len(versions) != 1 || versions["openssl:amd64"] != "3.0.1-1" {
		t.Fatalf("residual-config package broke inventory: versions=%#v err=%v", versions, err)
	}
}

func TestPackagePlanGuardRejectsMalformedAndStalePlansDurably(t *testing.T) {
	base := filepath.Join(t.TempDir(), "plans")
	if err := ensurePackagePlanBase(base); err != nil {
		t.Fatal(err)
	}
	directory, err := preparePackagePlanTransaction(base, packagePlanGuardSpec{
		Version: packagePlanGuardVersion, Mode: packagePlanGuardApply,
		Installed: map[string]string{"openssl:amd64": "1.0-1"}, Authorized: map[string]string{"openssl:amd64": "1.0-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	input := "VERSION 3\nAPT::Architecture=amd64\n\nopenssl 1.5-1 amd64 none < 2.0-1 amd64 none /var/cache/apt/archives/openssl.deb\nopenssl 1.5-1 amd64 none < 2.0-1 amd64 none **CONFIGURE**\n"
	if err = RunPackagePlanGuard(strings.NewReader(input), directory, base); err == nil {
		t.Fatal("stale locked APT plan was accepted")
	}
	result, readErr := readPackagePlanGuardResult(directory)
	if readErr != nil || result.Allowed || !strings.Contains(result.Reason, "changed while waiting") {
		t.Fatalf("guard rejection was not durably recorded: result=%#v err=%v", result, readErr)
	}
}

func TestPackagePlanGuardVersion3CanonicalizesMultiArchAndRejectsLegacyOrArchitectureChanges(t *testing.T) {
	input := "VERSION 3\nAPT::Architecture=amd64\n\nlibc6 2.36-9 arm64 same < 2.36-10 arm64 same /var/cache/apt/archives/libc6.deb\nlibc6 2.36-9 arm64 same < 2.36-10 arm64 same **CONFIGURE**\n"
	plan, err := parseAPTVersion3Plan(strings.NewReader(input))
	if err != nil || len(plan) != 1 || plan["libc6:arm64"] != (packageVersionTransition{From: "2.36-9", To: "2.36-10", Direction: "<"}) {
		t.Fatalf("APT v3 multiarch plan was not canonicalized: plan=%#v err=%v", plan, err)
	}
	legacy := "VERSION 2\nAPT::Architecture=amd64\n\nlibc6 2.36-9 < 2.36-10 /var/cache/apt/archives/libc6.deb\n"
	if _, err = parseAPTVersion3Plan(strings.NewReader(legacy)); err == nil {
		t.Fatal("ambiguous APT v2 plan was accepted")
	}
	architectureChange := "VERSION 3\nAPT::Architecture=amd64\n\nlibc6 2.36-9 amd64 same < 2.36-10 arm64 same /var/cache/apt/archives/libc6.deb\n"
	if _, err = parseAPTVersion3Plan(strings.NewReader(architectureChange)); err == nil {
		t.Fatal("APT plan that changed architecture was accepted")
	}
}

func TestPackagePlanGuardRejectsReinstallBeforeMutation(t *testing.T) {
	base := filepath.Join(t.TempDir(), "plans")
	if err := ensurePackagePlanBase(base); err != nil {
		t.Fatal(err)
	}
	directory, err := preparePackagePlanTransaction(base, packagePlanGuardSpec{
		Version: packagePlanGuardVersion, Mode: packagePlanGuardApply,
		Installed: map[string]string{"adduser:all": "3.134"}, Authorized: map[string]string{"adduser:all": "3.134"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	input := "VERSION 3\nAPT::Architecture=amd64\n\nadduser 3.134 all foreign = 3.134 all foreign /var/cache/apt/archives/adduser.deb\nadduser 3.134 all foreign = 3.134 all foreign **CONFIGURE**\n"
	if err = RunPackagePlanGuard(strings.NewReader(input), directory, base); err == nil {
		t.Fatal("same-version reinstall with untracked maintainer-script effects was accepted")
	}
	result, readErr := readPackagePlanGuardResult(directory)
	if readErr != nil || result.Allowed || !strings.Contains(result.Reason, "monotonically") {
		t.Fatalf("reinstall rejection was not durably recorded: result=%#v err=%v", result, readErr)
	}
}

func TestPackageNoOpRollbackDoesNotOwnLaterExternalUpgrade(t *testing.T) {
	environment := newPackageTestEnvironment(t)
	versions := map[string]string{"app": "1.0-1"}
	aptTransactions := 0
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		switch command.Path {
		case "/fake/dpkg-query":
			return fakePackageQuery(command, versions)
		case "/fake/apt-get":
			if !containsArgument(command.Args, "--version") && !containsArgument(command.Args, "--simulate") {
				aptTransactions++
				if !containsArgument(command.Args, "APT::Get::Mark-Auto=true") {
					return CommandResult{}, errors.New("package selection ownership would not be preserved")
				}
			}
			return CommandResult{}, nil
		default:
			return CommandResult{}, fmt.Errorf("unexpected executable %q", command.Path)
		}
	}}
	playbook := environment.playbook(t, runner)
	engine, _ := NewEngine(playbook)
	parameters := json.RawMessage(`{"packages":["app"]}`)
	apply := engine.Run(context.Background(), Request{ActionID: "pkg-no-op", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationExecute, Parameters: parameters})
	if !apply.Success || aptTransactions != 1 {
		t.Fatalf("no-op apply failed: receipt=%#v transactions=%d", apply, aptTransactions)
	}
	versions["app"] = "2.0-1"
	rollback := engine.Run(context.Background(), Request{ActionID: "pkg-no-op", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationRollback, Parameters: parameters, State: apply.State})
	if !rollback.Success || versions["app"] != "2.0-1" || aptTransactions != 1 {
		t.Fatalf("no-op rollback overwrote or claimed an external upgrade: receipt=%#v versions=%#v transactions=%d", rollback, versions, aptTransactions)
	}
}

func TestPackageMissingGuardReceiptRejectsChangedPackagesAsIndeterminate(t *testing.T) {
	environment := newPackageTestEnvironment(t)
	versions := map[string]string{"app": "1.0-1"}
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		switch command.Path {
		case "/fake/dpkg-query":
			return fakePackageQuery(command, versions)
		case "/fake/apt-get":
			if containsArgument(command.Args, "--version") || containsArgument(command.Args, "--simulate") {
				return CommandResult{}, nil
			}
			// Model a regressed or incompatible APT integration that reports
			// success and mutates the package without invoking the locked hook.
			versions["app"] = "2.0-1"
			return CommandResult{}, nil
		default:
			return CommandResult{}, fmt.Errorf("unexpected executable %q", command.Path)
		}
	}}
	playbook := environment.playbook(t, runner)
	engine, _ := NewEngine(playbook)
	receipt := engine.Run(context.Background(), Request{ActionID: "pkg-missing-guard-receipt", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationExecute, Parameters: json.RawMessage(`{"packages":["app"]}`)})
	if receipt.Success || !receipt.Indeterminate || len(receipt.State) == 0 || versions["app"] != "2.0-1" || !strings.Contains(receipt.Error, "without a locked package plan receipt") {
		t.Fatalf("missing guard receipt was classified as a safe no-op: receipt=%#v versions=%#v", receipt, versions)
	}
}

func TestPackageMissingGuardReceiptWithAPTErrorIsIndeterminate(t *testing.T) {
	environment := newPackageTestEnvironment(t)
	versions := map[string]string{"app": "1.0-1"}
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		switch command.Path {
		case "/fake/dpkg-query":
			return fakePackageQuery(command, versions)
		case "/fake/apt-get":
			if containsArgument(command.Args, "--version") || containsArgument(command.Args, "--simulate") {
				return CommandResult{}, nil
			}
			versions["app"] = "2.0-1"
			return CommandResult{}, errors.New("dpkg configuration failed")
		default:
			return CommandResult{}, fmt.Errorf("unexpected executable %q", command.Path)
		}
	}}
	playbook := environment.playbook(t, runner)
	engine, _ := NewEngine(playbook)
	receipt := engine.Run(context.Background(), Request{ActionID: "pkg-missing-guard-error", Actor: "tester", Type: TypePackageSecurityUpgrade, Operation: OperationExecute, Parameters: json.RawMessage(`{"packages":["app"]}`)})
	if receipt.Success || !receipt.Indeterminate || len(receipt.State) == 0 || versions["app"] != "2.0-1" || !strings.Contains(receipt.Error, "without a locked mutation plan receipt") {
		t.Fatalf("receipt-less failed APT mutation was classified as determinate: receipt=%#v versions=%#v", receipt, versions)
	}
}

func TestPackageSecurityUpgradeRejectsArgumentInjectionAndDuplicates(t *testing.T) {
	environment := newPackageTestEnvironment(t)
	playbook := environment.playbook(t, &fakeRunner{})
	if _, err := NewPackageSecurityUpgradePlaybook(&fakeRunner{}, "/fake/apt-get", "/fake/dpkg-query", environment.hookPath, "/tmp/witshield plans;id"); err == nil {
		t.Fatal("shell-significant package plan directory was accepted into the root APT hook command")
	}
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

func fakePackageQuery(command Command, versions map[string]string) (CommandResult, error) {
	if isFullInventoryQuery(command) {
		return CommandResult{Stdout: fakeInstalledPackageBaseline(versions)}, nil
	}
	requested := command.Args[len(command.Args)-1]
	name, architecture := testPackageParts(requested)
	version, exists := versions[requested]
	if !exists {
		version, exists = versions[name]
	}
	if !exists {
		return CommandResult{}, errors.New("not installed")
	}
	return CommandResult{Stdout: fmt.Sprintf("ii \t%s\t%s\t%s\n", name, architecture, version)}, nil
}

func isFullInventoryQuery(command Command) bool {
	return len(command.Args) == 2 && command.Args[0] == "-W" && strings.HasPrefix(command.Args[1], "-f=")
}

func packageTargets(arguments []string) map[string]string {
	targets := make(map[string]string)
	for _, argument := range arguments {
		parts := strings.SplitN(argument, "=", 2)
		if len(parts) == 2 && debianPackagePattern.MatchString(parts[0]) && debianVersionPattern.MatchString(parts[1]) {
			name, _ := testPackageParts(parts[0])
			targets[name] = parts[1]
		}
	}
	return targets
}

func containsArgument(arguments []string, expected string) bool {
	for _, argument := range arguments {
		if argument == expected {
			return true
		}
	}
	return false
}

func fakeInstalledPackageBaseline(versions map[string]string) string {
	names := make([]string, 0, len(versions))
	for name := range versions {
		names = append(names, name)
	}
	sort.Strings(names)
	var output strings.Builder
	for _, name := range names {
		base, architecture := testPackageParts(name)
		fmt.Fprintf(&output, "ii \t%s\t%s\t%s\n", base, architecture, versions[name])
	}
	return output.String()
}
