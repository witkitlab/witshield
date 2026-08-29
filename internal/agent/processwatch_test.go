package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/observation"
)

func TestProcessWatcherReportsPrivilegedTransientExecutableWithoutCommandLine(t *testing.T) {
	root := t.TempDir()
	pidDir := filepath.Join(root, "proc", "321")
	if err := os.MkdirAll(pidDir, 0o700); err != nil {
		t.Fatal(err)
	}
	status := "Name:\tevil-worker\nPPid:\t1\nUid:\t0\t0\t0\t0\n"
	stat := "321 (evil-worker) S 1 " + strings.Repeat("0 ", 17) + "4242\n"
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte(stat), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/evil-worker", filepath.Join(pidDir, "exe")); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 28, 13, 0, 0, 0, time.UTC)
	w := processWatcher{hostRoot: root, statePath: filepath.Join(t.TempDir(), "process.json"), now: func() time.Time { return now }}
	events, err := w.Poll(context.Background())
	if err != nil || len(events) != 1 || events[0].Type != "suspicious_privileged_process_started" {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	var payload map[string]any
	if err = json.Unmarshal(events[0].Payload, &payload); err != nil || payload["uid"] != float64(0) || payload["executable"] != "/tmp/evil-worker" || payload["automaticActionEligible"] != true {
		t.Fatalf("payload=%#v err=%v", payload, err)
	}
	if _, exists := payload["commandLine"]; exists {
		t.Fatal("process command line leaked into security event")
	}
	replay, err := w.Poll(context.Background())
	if err != nil || len(replay) != 1 || replay[0].ID != events[0].ID {
		t.Fatalf("replay=%#v err=%v", replay, err)
	}
	if err = w.Commit(); err != nil {
		t.Fatal(err)
	}
	quiet, err := w.Poll(context.Background())
	if err != nil || len(quiet) != 0 {
		t.Fatalf("quiet=%#v err=%v", quiet, err)
	}
}

func TestProcessWatcherReportsDeletedExecutableAndIgnoresNormalRootBinary(t *testing.T) {
	root := t.TempDir()
	makeProcess := func(pid int, target string) {
		t.Helper()
		dir := filepath.Join(root, "proc", fmt.Sprint(pid))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(fmt.Sprintf("Name:\tp%d\nPPid:\t1\nUid:\t0\t0\t0\t0\n", pid)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(fmt.Sprintf("%d (p%d) S 1 %s%d\n", pid, pid, strings.Repeat("0 ", 17), pid)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	makeProcess(100, "/usr/bin/normal")
	makeProcess(200, "/usr/bin/upgraded (deleted)")
	w := processWatcher{hostRoot: root, statePath: filepath.Join(t.TempDir(), "process.json")}
	events, err := w.Poll(context.Background())
	if err != nil || len(events) != 1 || events[0].Type != "deleted_executable_process_running" {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}

func TestParseProcessStartTimeHandlesSpacesAndParenthesesInName(t *testing.T) {
	raw := "19 (worker ) name) S 1 " + strings.Repeat("0 ", 17) + "991\n"
	if value, ok := observation.ParseStartTime(raw); !ok || value != 991 {
		t.Fatalf("value=%d ok=%v", value, ok)
	}
}

func TestProcessWatcherSurfacesEventCapacityAndAdvancesBaseline(t *testing.T) {
	root := t.TempDir()
	for offset := 0; offset <= maxProcessEvents; offset++ {
		pid := 1000 + offset
		dir := filepath.Join(root, "proc", fmt.Sprint(pid))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "status"), []byte(fmt.Sprintf("Name:\tp%d\nPPid:\t1\nUid:\t0\t0\t0\t0\n", pid)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(fmt.Sprintf("%d (p%d) S 1 %s%d\n", pid, pid, strings.Repeat("0 ", 17), pid)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(fmt.Sprintf("/tmp/p%d", pid), filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	w := processWatcher{hostRoot: root, statePath: filepath.Join(t.TempDir(), "process.json")}
	events, err := w.Poll(context.Background())
	lastType := ""
	if len(events) > 0 {
		lastType = events[len(events)-1].Type
	}
	if err != nil || len(events) != maxProcessEvents+1 || lastType != "process_sensor_capacity_degraded" {
		t.Fatalf("events=%d last=%q err=%v", len(events), lastType, err)
	}
	if err = w.Commit(); err != nil {
		t.Fatal(err)
	}
	if events, err = w.Poll(context.Background()); err != nil || len(events) != 0 {
		t.Fatalf("capacity baseline did not advance: events=%#v err=%v", events, err)
	}
}
