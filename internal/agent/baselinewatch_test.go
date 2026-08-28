package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBaselineWatcherEstablishesBaselineThenEmitsOnlyMetadataDelta(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	passwd := filepath.Join(root, "etc", "passwd")
	if err := os.MkdirAll(filepath.Dir(passwd), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	watcher := &baselineWatcher{hostRoot: root, statePath: filepath.Join(stateDir, "baseline.json"), now: func() time.Time { return now }}
	events, err := watcher.Poll(context.Background())
	if err != nil || len(events) != 0 {
		t.Fatalf("initial poll events=%#v err=%v", events, err)
	}
	if err = os.WriteFile(passwd, []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	events, err = watcher.Poll(context.Background())
	if err != nil || len(events) != 1 || events[0].Type != "identity_state_changed" || events[0].OccurredAt != now {
		t.Fatalf("delta events=%#v err=%v", events, err)
	}
	var payload map[string]any
	if err = json.Unmarshal(events[0].Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["path"] != "/etc/passwd" || payload["change"] != "modified" || payload["automaticActionEligible"] != false {
		t.Fatalf("unexpected safe payload: %#v", payload)
	}
	if _, leaked := payload["content"]; leaked {
		t.Fatal("baseline event leaked file contents")
	}
}

func TestBaselineWatcherDoesNotFollowTargetSymlink(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("do-not-read"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "etc", "ssh", "sshd_config")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, target); err != nil {
		t.Fatal(err)
	}
	watcher := &baselineWatcher{hostRoot: root, statePath: filepath.Join(stateDir, "baseline.json")}
	if events, err := watcher.Poll(context.Background()); err != nil || len(events) != 0 {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	data, err := os.ReadFile(watcher.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "" || string(data) == "do-not-read" {
		t.Fatal("baseline state was not safely persisted")
	}
}

func TestBaselineWatcherReplaysBeforeCommitAndUsesNewGenerationAfterCommit(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	passwd := filepath.Join(root, "etc", "passwd")
	if err := os.MkdirAll(filepath.Dir(passwd), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwd, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	watcher := &baselineWatcher{hostRoot: root, statePath: filepath.Join(stateDir, "baseline.json")}
	if _, err := watcher.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwd, []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := watcher.Poll(context.Background())
	if err != nil || len(first) != 1 {
		t.Fatalf("first delta=%#v err=%v", first, err)
	}
	replay, err := watcher.Poll(context.Background())
	if err != nil || len(replay) != 1 || replay[0].ID != first[0].ID {
		t.Fatalf("uncommitted delta did not replay idempotently: first=%#v replay=%#v err=%v", first, replay, err)
	}
	if err = watcher.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(passwd, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	back, err := watcher.Poll(context.Background())
	if err != nil || len(back) != 1 {
		t.Fatalf("reverse delta=%#v err=%v", back, err)
	}
	if err = watcher.Commit(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(passwd, []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	repeated, err := watcher.Poll(context.Background())
	if err != nil || len(repeated) != 1 || repeated[0].ID == first[0].ID {
		t.Fatalf("later identical transition reused an old event id: first=%#v repeated=%#v err=%v", first, repeated, err)
	}
}
