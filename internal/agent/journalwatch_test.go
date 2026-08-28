package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeJournalRunner struct {
	outputs [][]byte
	args    [][]string
}

func (f *fakeJournalRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	f.args = append(f.args, append([]string(nil), args...))
	if len(f.outputs) == 0 {
		return nil, fmt.Errorf("no fake output")
	}
	value := f.outputs[0]
	f.outputs = f.outputs[1:]
	return value, nil
}

func TestJournalWatcherStartsAtTailAndPersistsCursor(t *testing.T) {
	now := time.Now().UTC()
	micros := now.UnixMicro()
	runner := &fakeJournalRunner{outputs: [][]byte{
		[]byte("-- cursor: initial-cursor\n"),
		[]byte(fmt.Sprintf(`{"MESSAGE":"Failed password for root from 203.0.113.9 port 22 ssh2","__CURSOR":"next-cursor","__REALTIME_TIMESTAMP":"%d"}`+"\n-- cursor: next-cursor\n", micros)),
	}}
	w := journalWatcher{executable: "/usr/bin/journalctl", statePath: filepath.Join(t.TempDir(), "cursor"), runner: runner}
	events, cursor, err := w.Poll(context.Background())
	if err != nil || len(events) != 0 || cursor != "initial-cursor" {
		t.Fatalf("initial events=%v cursor=%q err=%v", events, cursor, err)
	}
	if err = w.Commit(cursor); err != nil {
		t.Fatal(err)
	}
	events, cursor, err = w.Poll(context.Background())
	if err != nil || len(events) != 1 || events[0].SourceIP != "203.0.113.9" || cursor != "next-cursor" {
		t.Fatalf("events=%v cursor=%q err=%v", events, cursor, err)
	}
	if len(runner.args) != 2 || !containsArg(runner.args[0], "--lines=0") || !containsArg(runner.args[1], "--after-cursor=initial-cursor") {
		t.Fatalf("unexpected journal args: %#v", runner.args)
	}
}

func TestJournalParserDropsHistoricalDefenseEvents(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-8 * 24 * time.Hour).UnixMicro()
	data := []byte(fmt.Sprintf(`{"MESSAGE":"Failed password for root from 8.8.8.8 port 22 ssh2","__CURSOR":"old","__REALTIME_TIMESTAMP":"%d"}`+"\n-- cursor: old\n", old))
	events, cursor, err := parseJournalOutput(data, true, now)
	if err != nil || len(events) != 0 || cursor != "old" {
		t.Fatalf("events=%v cursor=%q err=%v", events, cursor, err)
	}
}

func TestJournalParserRecordsSuccessfulSSHAsInvestigationOnlyEvidence(t *testing.T) {
	now := time.Now().UTC()
	data := []byte(fmt.Sprintf(`{"MESSAGE":"Accepted publickey for deploy from 203.0.113.44 port 5512 ssh2","__CURSOR":"accepted","__REALTIME_TIMESTAMP":"%d"}`+"\n-- cursor: accepted\n", now.UnixMicro()))
	events, cursor, err := parseJournalOutput(data, true, now)
	if err != nil || cursor != "accepted" || len(events) != 1 || events[0].Type != "ssh_auth_success" || events[0].SourceIP != "203.0.113.44" {
		t.Fatalf("events=%#v cursor=%q err=%v", events, cursor, err)
	}
	if !strings.Contains(string(events[0].Payload), `"automaticActionEligible":false`) || !strings.Contains(string(events[0].Payload), `"principal":"deploy"`) {
		t.Fatalf("successful login payload is incomplete: %s", events[0].Payload)
	}
}

func TestJournalParserRecognizesKeyboardInteractiveSSHSuccess(t *testing.T) {
	now := time.Now().UTC()
	data := []byte(fmt.Sprintf(`{"MESSAGE":"Accepted keyboard-interactive/pam for ops$ from 2001:db8::44 port 5512 ssh2","__CURSOR":"accepted-pam","__REALTIME_TIMESTAMP":"%d"}`+"\n-- cursor: accepted-pam\n", now.UnixMicro()))
	events, _, err := parseJournalOutput(data, true, now)
	if err != nil || len(events) != 1 || events[0].Type != "ssh_auth_success" || events[0].SourceIP != "2001:db8::44" || !strings.Contains(string(events[0].Payload), `"method":"keyboard-interactive/pam"`) {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}

func TestJournalCursorFileIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cursor")
	w := journalWatcher{statePath: path}
	if err := w.Commit("safe-cursor"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v", info.Mode())
	}
	if err = w.Commit("bad\ncursor"); err == nil {
		t.Fatal("newline cursor accepted")
	}
}

func containsArg(args []string, value string) bool {
	for _, arg := range args {
		if strings.EqualFold(arg, value) {
			return true
		}
	}
	return false
}
