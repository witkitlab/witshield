package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const authFailureLine = "Aug 26 host sshd[1]: Failed password for invalid user root from 203.0.113.9 port 22 ssh2\n"

func TestAuthLogWatcherCheckpoint(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	statePath := filepath.Join(dir, "checkpoint")
	if err := os.WriteFile(logPath, []byte(authFailureLine), 0o640); err != nil {
		t.Fatal(err)
	}
	w := authLogWatcher{path: logPath, statePath: statePath}
	events, checkpoint, err := w.Poll(context.Background())
	if err != nil || len(events) != 0 || checkpoint.Offset != int64(len(authFailureLine)) || checkpoint.Generation != 1 {
		t.Fatalf("%#v %#v %v", events, checkpoint, err)
	}
	if err = w.Commit(checkpoint); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("Aug 26 host sshd[2]: authentication failure; rhost=2001:db8::2 user=x\n")
	_ = f.Close()
	events, checkpoint, err = w.Poll(context.Background())
	if err != nil || len(events) != 1 || events[0].SourceIP != "2001:db8::2" || events[0].Type != "ssh_auth_failure_untrusted" {
		t.Fatalf("%#v %v", events, err)
	}
	if !checkpoint.valid() || checkpoint.Offset <= int64(len(authFailureLine)) {
		t.Fatalf("checkpoint did not advance: %#v", checkpoint)
	}
	var payload map[string]any
	if err = json.Unmarshal(events[0].Payload, &payload); err != nil || payload["automaticActionEligible"] != false || payload["trust"] != "unverified" {
		t.Fatalf("untrusted observation was not explicit: payload=%s err=%v", events[0].Payload, err)
	}
}

func TestAuthLogWatcherDetectsRotationWhenReplacementIsNotShorter(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	w := authLogWatcher{path: logPath, statePath: filepath.Join(dir, "checkpoint")}
	if err := os.WriteFile(logPath, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	_, checkpoint, err := w.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Commit(checkpoint); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(logPath, []byte(authFailureLine), 0o640); err != nil {
		t.Fatal(err)
	}
	first, checkpoint, err := w.Poll(context.Background())
	if err != nil || len(first) != 1 {
		t.Fatalf("first=%#v checkpoint=%#v err=%v", first, checkpoint, err)
	}
	if err = w.Commit(checkpoint); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatal(err)
	}
	// Equal size defeats offset-only rotation detection. Keeping the renamed
	// file alive also prevents the filesystem from reusing its inode.
	if err = os.WriteFile(logPath, []byte(authFailureLine), 0o640); err != nil {
		t.Fatal(err)
	}
	second, rotated, err := w.Poll(context.Background())
	if err != nil || len(second) != 1 {
		t.Fatalf("second=%#v checkpoint=%#v err=%v", second, rotated, err)
	}
	if rotated.Generation != checkpoint.Generation+1 || rotated.Offset != int64(len(authFailureLine)) {
		t.Fatalf("rotation did not reset and advance the generation: before=%#v after=%#v", checkpoint, rotated)
	}
	if first[0].ID == second[0].ID {
		t.Fatalf("event IDs collided across log generations: %s", first[0].ID)
	}
}

func TestAuthLogWatcherDiscardsOversizedLineAndContinues(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	w := authLogWatcher{path: logPath, statePath: filepath.Join(dir, "checkpoint")}
	if err := os.WriteFile(logPath, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	_, checkpoint, err := w.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Commit(checkpoint); err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat("x", maxAuthLine+1) + "\n" + authFailureLine
	if err = os.WriteFile(logPath, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	events, checkpoint, err := w.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Type != oversizedAuthLogEventType || events[1].Type != "ssh_auth_failure_untrusted" {
		t.Fatalf("expected overflow observation followed by parsed event: %#v", events)
	}
	if checkpoint.Offset != int64(len(content)) || checkpoint.DiscardingOversizeLine {
		t.Fatalf("oversized complete line did not drain: %#v", checkpoint)
	}
}

func TestAuthLogWatcherDrainsLineBeyondReadBudgetAcrossPolls(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	w := authLogWatcher{path: logPath, statePath: filepath.Join(dir, "checkpoint")}
	if err := os.WriteFile(logPath, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	_, checkpoint, err := w.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Commit(checkpoint); err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat("z", maxAuthLogRead+1024) + "\n" + authFailureLine
	if err = os.WriteFile(logPath, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	first, checkpoint, err := w.Poll(context.Background())
	if err != nil || len(first) != 1 || first[0].Type != oversizedAuthLogEventType {
		t.Fatalf("first=%#v checkpoint=%#v err=%v", first, checkpoint, err)
	}
	if checkpoint.Offset != maxAuthLogRead || !checkpoint.DiscardingOversizeLine {
		t.Fatalf("first bounded drain checkpoint=%#v", checkpoint)
	}
	if err = w.Commit(checkpoint); err != nil {
		t.Fatal(err)
	}
	second, checkpoint, err := w.Poll(context.Background())
	if err != nil || len(second) != 1 || second[0].Type != "ssh_auth_failure_untrusted" {
		t.Fatalf("second=%#v checkpoint=%#v err=%v", second, checkpoint, err)
	}
	if checkpoint.Offset != int64(len(content)) || checkpoint.DiscardingOversizeLine {
		t.Fatalf("multi-poll line did not drain through newline: %#v", checkpoint)
	}
}

func TestAuthLogWatcherDoesNotCommitNormalPartialLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	w := authLogWatcher{path: logPath, statePath: filepath.Join(dir, "checkpoint")}
	if err := os.WriteFile(logPath, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	_, checkpoint, err := w.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Commit(checkpoint); err != nil {
		t.Fatal(err)
	}
	partial := strings.TrimSuffix(authFailureLine, "\n")
	if err = os.WriteFile(logPath, []byte(partial), 0o640); err != nil {
		t.Fatal(err)
	}
	events, checkpoint, err := w.Poll(context.Background())
	if err != nil || len(events) != 0 || checkpoint.Offset != 0 {
		t.Fatalf("partial line advanced checkpoint: events=%#v checkpoint=%#v err=%v", events, checkpoint, err)
	}
}

func TestAuthLogWatcherMigratesLegacyOffsetWithoutReplay(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "auth.log")
	statePath := filepath.Join(dir, "checkpoint")
	if err := os.WriteFile(logPath, []byte(authFailureLine), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte(strconv.Itoa(len(authFailureLine))), 0o600); err != nil {
		t.Fatal(err)
	}
	w := authLogWatcher{path: logPath, statePath: statePath}
	events, checkpoint, err := w.Poll(context.Background())
	if err != nil || len(events) != 0 || checkpoint.Offset != int64(len(authFailureLine)) || checkpoint.Generation != 1 {
		t.Fatalf("legacy migration replayed history: events=%#v checkpoint=%#v err=%v", events, checkpoint, err)
	}
}

func TestAuthLogWatcherMissingFileDoesNotCreateCheckpoint(t *testing.T) {
	dir := t.TempDir()
	w := authLogWatcher{path: filepath.Join(dir, "missing"), statePath: filepath.Join(dir, "checkpoint")}
	events, checkpoint, err := w.Poll(context.Background())
	if err != nil || len(events) != 0 || checkpoint.valid() {
		t.Fatalf("events=%v checkpoint=%#v err=%v", events, checkpoint, err)
	}
	if _, err = os.Stat(w.statePath); !os.IsNotExist(err) {
		t.Fatalf("unexpected checkpoint state: %v", err)
	}
}
