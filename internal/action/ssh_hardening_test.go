package action

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSSHSnapshotRejectsSpecialBitsBeforeCreatingRecoveryState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(path, []byte("PasswordAuthentication yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !hasSpecialModeBits(info.Mode()) {
		t.Skip("filesystem does not preserve setuid in this test environment")
	}
	if _, err := snapshotRegularFile(path); err == nil || !strings.Contains(err.Error(), "setuid") {
		t.Fatalf("special-bit SSH config was accepted: %v", err)
	}
	after, err := os.Lstat(path)
	if err != nil || after.Mode() != info.Mode() {
		t.Fatalf("SSH config changed during rejection: before=%v after=%v err=%v", info.Mode(), after.Mode(), err)
	}
}

func newTestSSHPlaybook(t *testing.T, runner Runner, configPath, journalDir string, delay time.Duration) *SSHPasswordHardeningPlaybook {
	t.Helper()
	playbook, err := NewSSHPasswordHardeningPlaybook(SSHHardeningConfig{
		Runner: runner, SSHDPath: "/fake/sshd", SystemctlPath: "/fake/systemctl",
		ConfigPath: configPath, ServiceName: "ssh", JournalDir: journalDir,
		DefaultRollbackDelay: delay, MinRollbackDelay: 10 * time.Millisecond, MaxRollbackDelay: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return playbook
}

func successfulSSHRunner(configPath string) *fakeRunner {
	return &fakeRunner{run: func(command Command) (CommandResult, error) {
		if command.Path == "/fake/sshd" && containsArgument(command.Args, "-T") {
			content, _ := os.ReadFile(configPath)
			if strings.Contains(string(content), "PasswordAuthentication no") {
				return CommandResult{Stdout: "passwordauthentication no\n"}, nil
			}
			return CommandResult{Stdout: "passwordauthentication yes\n"}, nil
		}
		return CommandResult{}, nil
	}}
}

func TestSSHHardeningPersistsJournalAndRollsBackAfterRestart(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sshd_config")
	journalDir := filepath.Join(root, "journal")
	original := []byte("Port 22\nPasswordAuthentication yes\n")
	if err := os.WriteFile(configPath, original, 0644); err != nil {
		t.Fatal(err)
	}
	runner := successfulSSHRunner(configPath)
	first := newTestSSHPlaybook(t, runner, configPath, journalDir, 120*time.Millisecond)
	engine, _ := NewEngine(first)
	parameters := json.RawMessage(`{}`)
	receipt := engine.Run(context.Background(), Request{
		ActionID: "ssh-restart", Actor: "tester", Type: TypeSSHPasswordHardening,
		Operation: OperationExecute, Parameters: parameters,
	})
	if !receipt.Success || receipt.ConfirmBy == nil {
		t.Fatalf("SSH apply failed or lacked confirmation deadline: %#v", receipt)
	}
	if _, err := os.Stat(first.journalPath("ssh-restart")); err != nil {
		t.Fatalf("durable rollback journal missing: %v", err)
	}
	hardened, _ := os.ReadFile(configPath)
	if !strings.Contains(string(hardened), "PasswordAuthentication no") {
		t.Fatalf("configuration not hardened: %s", hardened)
	}
	// Simulate process death: its in-memory timer disappears but the journal is
	// intentionally retained. A new helper instance must resume it.
	first.cancelTimer("ssh-restart")
	second := newTestSSHPlaybook(t, runner, configPath, journalDir, 120*time.Millisecond)
	defer second.cancelTimer("ssh-restart")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		current, _ := os.ReadFile(configPath)
		_, journalErr := os.Stat(second.journalPath("ssh-restart"))
		if string(current) == string(original) && errors.Is(journalErr, os.ErrNotExist) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	current, _ := os.ReadFile(configPath)
	if string(current) != string(original) {
		t.Fatalf("timed rollback did not restore the snapshot: %s", current)
	}
	if _, err := os.Stat(second.journalPath("ssh-restart")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal was not removed after rollback: %v", err)
	}
}

func TestSSHConfirmationDisarmsTimedRollback(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sshd_config")
	journalDir := filepath.Join(root, "journal")
	if err := os.WriteFile(configPath, []byte("PasswordAuthentication yes\n"), 0644); err != nil {
		t.Fatal(err)
	}
	playbook := newTestSSHPlaybook(t, successfulSSHRunner(configPath), configPath, journalDir, 150*time.Millisecond)
	engine, _ := NewEngine(playbook)
	parameters := json.RawMessage(`{}`)
	apply := engine.Run(context.Background(), Request{
		ActionID: "ssh-confirm", Actor: "tester", Type: TypeSSHPasswordHardening,
		Operation: OperationExecute, Parameters: parameters,
	})
	if !apply.Success {
		t.Fatal(apply.Error)
	}
	confirm := engine.Run(context.Background(), Request{
		ActionID: "ssh-confirm", Actor: "tester", Type: TypeSSHPasswordHardening,
		Operation: OperationConfirm, Parameters: parameters, State: apply.State,
	})
	if !confirm.Success {
		t.Fatalf("confirmation failed: %s", confirm.Error)
	}
	time.Sleep(300 * time.Millisecond)
	content, _ := os.ReadFile(configPath)
	if !strings.Contains(string(content), "PasswordAuthentication no") {
		t.Fatalf("confirmed SSH change was rolled back: %s", content)
	}
	if _, err := os.Stat(playbook.journalPath("ssh-confirm")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("confirmed journal remains: %v", err)
	}
}

func TestSSHJournalDirectorySyncFailureIsCompensatedWhenRenameCommitted(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sshd_config")
	journalDir := filepath.Join(root, "journal")
	original := []byte("PasswordAuthentication yes\n")
	if err := os.WriteFile(configPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	playbook := newTestSSHPlaybook(t, successfulSSHRunner(configPath), configPath, journalDir, time.Second)
	realSync := playbook.syncDirectory
	calls := 0
	playbook.syncDirectory = func(path string) error {
		calls++
		if calls == 1 {
			return errors.New("injected directory sync failure after rename")
		}
		return realSync(path)
	}
	engine, _ := NewEngine(playbook)
	receipt := engine.Run(context.Background(), Request{ActionID: "ssh-journal-sync", Actor: "tester", Type: TypeSSHPasswordHardening, Operation: OperationExecute, Parameters: json.RawMessage(`{}`)})
	content, readErr := os.ReadFile(configPath)
	_, journalErr := os.Stat(playbook.journalPath("ssh-journal-sync"))
	if receipt.Success || receipt.Indeterminate || len(receipt.State) != 0 || readErr != nil || string(content) != string(original) || !errors.Is(journalErr, os.ErrNotExist) {
		t.Fatalf("uncertain journal rename was not compensated: receipt=%#v content=%q readErr=%v journalErr=%v", receipt, content, readErr, journalErr)
	}
}

func TestSSHAutomaticRollbackReloadsAnAlreadyRestoredSnapshot(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sshd_config")
	journalDir := filepath.Join(root, "journal")
	original := []byte("PasswordAuthentication yes\n")
	if err := os.WriteFile(configPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	reloads := 0
	runtimeHardened := false
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		if command.Path == "/fake/systemctl" {
			reloads++
			switch reloads {
			case 1:
				runtimeHardened = true
				return CommandResult{}, errors.New("reload response failed after commit")
			case 2:
				return CommandResult{}, errors.New("snapshot reload failed before commit")
			default:
				runtimeHardened = false
				return CommandResult{}, nil
			}
		}
		return CommandResult{}, nil
	}}
	playbook := newTestSSHPlaybook(t, runner, configPath, journalDir, time.Second)
	engine, _ := NewEngine(playbook)
	receipt := engine.Run(context.Background(), Request{ActionID: "ssh-runtime-restore", Actor: "tester", Type: TypeSSHPasswordHardening, Operation: OperationExecute, Parameters: json.RawMessage(`{}`)})
	content, readErr := os.ReadFile(configPath)
	if receipt.Success || receipt.Indeterminate || len(receipt.State) != 0 || reloads != 3 || runtimeHardened || readErr != nil || string(content) != string(original) {
		t.Fatalf("runtime rollback was falsely proven: receipt=%#v reloads=%d hardened=%v content=%q err=%v", receipt, reloads, runtimeHardened, content, readErr)
	}
}

func TestSSHTimedRollbackDoesNotOverwriteANewerConfiguration(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sshd_config")
	journalDir := filepath.Join(root, "journal")
	if err := os.WriteFile(configPath, []byte("PasswordAuthentication yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	playbook := newTestSSHPlaybook(t, successfulSSHRunner(configPath), configPath, journalDir, time.Second)
	engine, _ := NewEngine(playbook)
	parameters := json.RawMessage(`{}`)
	apply := engine.Run(context.Background(), Request{ActionID: "ssh-newer-config", Actor: "tester", Type: TypeSSHPasswordHardening, Operation: OperationExecute, Parameters: parameters})
	if !apply.Success {
		t.Fatal(apply.Error)
	}
	playbook.cancelTimer("ssh-newer-config")
	newer := []byte("# managed elsewhere\nPasswordAuthentication no\nAllowUsers admin\n")
	if err := os.WriteFile(configPath, newer, 0o644); err != nil {
		t.Fatal(err)
	}
	playbook.expire("ssh-newer-config")
	content, readErr := os.ReadFile(configPath)
	if readErr != nil || string(content) != string(newer) {
		t.Fatalf("timed rollback overwrote newer configuration: content=%q err=%v", content, readErr)
	}
	if _, err := os.Stat(playbook.journalPath("ssh-newer-config")); err != nil {
		t.Fatalf("conflict journal was not retained for manual review: %v", err)
	}
	rollback := engine.Run(context.Background(), Request{ActionID: "ssh-newer-config", Actor: "tester", Type: TypeSSHPasswordHardening, Operation: OperationRollback, Parameters: parameters, State: apply.State})
	if rollback.Success || !rollback.Indeterminate {
		t.Fatalf("manual stale rollback was not marked unknown: %#v", rollback)
	}
}

func TestSSHApplyIsIdempotentForSameActionAndBlocksConcurrentChange(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sshd_config")
	journalDir := filepath.Join(root, "journal")
	if err := os.WriteFile(configPath, []byte("PasswordAuthentication yes\n"), 0644); err != nil {
		t.Fatal(err)
	}
	playbook := newTestSSHPlaybook(t, successfulSSHRunner(configPath), configPath, journalDir, time.Second)
	engine, _ := NewEngine(playbook)
	parameters := json.RawMessage(`{}`)
	first := engine.Run(context.Background(), Request{
		ActionID: "ssh-idempotent", Actor: "tester", Type: TypeSSHPasswordHardening,
		Operation: OperationApply, Parameters: parameters,
	})
	if !first.Success {
		t.Fatal(first.Error)
	}
	second := engine.Run(context.Background(), Request{
		ActionID: "ssh-idempotent", Actor: "tester", Type: TypeSSHPasswordHardening,
		Operation: OperationApply, Parameters: parameters,
	})
	if !second.Success || string(second.State) != string(first.State) {
		t.Fatalf("duplicate apply was not idempotent: first=%#v second=%#v", first, second)
	}
	concurrent := engine.Run(context.Background(), Request{
		ActionID: "ssh-other", Actor: "tester", Type: TypeSSHPasswordHardening,
		Operation: OperationApply, Parameters: parameters,
	})
	if concurrent.Success || !strings.Contains(concurrent.Error, "pending") {
		t.Fatalf("concurrent SSH change was not blocked: %#v", concurrent)
	}
	confirm := engine.Run(context.Background(), Request{
		ActionID: "ssh-idempotent", Actor: "tester", Type: TypeSSHPasswordHardening,
		Operation: OperationConfirm, Parameters: parameters, State: first.State,
	})
	if !confirm.Success {
		t.Fatalf("cleanup confirmation failed: %s", confirm.Error)
	}
}

func TestSSHValidationFailureRestoresSnapshot(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sshd_config")
	journalDir := filepath.Join(root, "journal")
	original := []byte("PasswordAuthentication yes\n")
	if err := os.WriteFile(configPath, original, 0644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		if command.Path == "/fake/sshd" && containsArgument(command.Args, "-t") {
			content, _ := os.ReadFile(configPath)
			if strings.Contains(string(content), sshManagedMarker) {
				return CommandResult{}, errors.New("invalid candidate")
			}
		}
		return CommandResult{}, nil
	}}
	playbook := newTestSSHPlaybook(t, runner, configPath, journalDir, time.Second)
	engine, _ := NewEngine(playbook)
	receipt := engine.Run(context.Background(), Request{
		ActionID: "ssh-invalid", Actor: "tester", Type: TypeSSHPasswordHardening,
		Operation: OperationExecute, Parameters: json.RawMessage(`{}`),
	})
	if receipt.Success {
		t.Fatal("invalid sshd configuration unexpectedly succeeded")
	}
	current, _ := os.ReadFile(configPath)
	if string(current) != string(original) {
		t.Fatalf("snapshot was not restored: %s", current)
	}
	if _, err := os.Stat(playbook.journalPath("ssh-invalid")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed apply left a journal behind: %v", err)
	}
}

func TestHardenSSHConfigIsIdempotent(t *testing.T) {
	original := []byte("# comment\nPasswordAuthentication yes\nMatch User deploy\n  PasswordAuthentication yes\n")
	hardened, changes := hardenSSHConfig(original)
	if changes == 0 || strings.Count(string(hardened), "PasswordAuthentication no") != 1 {
		t.Fatalf("unexpected hardened config (%d changes):\n%s", changes, hardened)
	}
	again, secondChanges := hardenSSHConfig(hardened)
	if string(again) != string(hardened) || secondChanges != 0 {
		t.Fatalf("hardening is not idempotent (%d changes):\n%s", secondChanges, again)
	}
}

func TestSSHConstructorRejectsUnsafeServiceName(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "sshd_config")
	if err := os.WriteFile(configPath, []byte("PasswordAuthentication yes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := NewSSHPasswordHardeningPlaybook(SSHHardeningConfig{
		Runner: &fakeRunner{}, SSHDPath: "/fake/sshd", SystemctlPath: "/fake/systemctl",
		ConfigPath: configPath, JournalDir: filepath.Join(root, "journal"), ServiceName: "--now;evil",
	})
	if err == nil {
		t.Fatal("unsafe systemd service name was accepted")
	}
}
