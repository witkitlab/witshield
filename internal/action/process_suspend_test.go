package action

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

type fakeProcessController struct {
	mu          sync.Mutex
	identity    ProcessRuntimeIdentity
	stopped     bool
	stopErr     error
	continueErr error
}

func (f *fakeProcessController) Inspect(int) (ProcessRuntimeIdentity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identity.Stopped = f.stopped
	return f.identity, nil
}
func (f *fakeProcessController) Stop(int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = true
	return f.stopErr
}
func (f *fakeProcessController) Continue(int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.continueErr != nil {
		return f.continueErr
	}
	f.stopped = false
	return nil
}
func (f *fakeProcessController) isStopped() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopped
}
func (f *fakeProcessController) setStopped(stopped bool) {
	f.mu.Lock()
	f.stopped = stopped
	f.mu.Unlock()
}
func (f *fakeProcessController) setStartTime(startTime uint64) {
	f.mu.Lock()
	f.identity.StartTime = startTime
	f.mu.Unlock()
}
func (f *fakeProcessController) setContinueError(err error) {
	f.mu.Lock()
	f.continueErr = err
	f.mu.Unlock()
}

func TestTemporaryProcessSuspendBindsPIDStartTimeAndRollsBack(t *testing.T) {
	controller := &fakeProcessController{identity: ProcessRuntimeIdentity{PID: 88, PPID: 1, UID: 0, StartTime: 991, Executable: "/tmp/suspicious"}}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	playbook, err := NewTemporaryProcessSuspendPlaybook(controller, dir)
	if err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(TemporaryProcessSuspendParams{PID: 88, StartTime: 991, Executable: "/tmp/suspicious", TTLSeconds: 60})
	apply, err := playbook.Apply(context.Background(), Invocation{ActionID: "act_test", Parameters: params})
	if err != nil || !controller.isStopped() || len(apply.State) == 0 || apply.ConfirmBy != nil {
		t.Fatalf("apply=%#v stopped=%v err=%v", apply, controller.isStopped(), err)
	}
	if _, err = playbook.Verify(context.Background(), Invocation{State: apply.State}); err != nil {
		t.Fatal(err)
	}
	if _, err = playbook.Rollback(context.Background(), Invocation{ActionID: "act_test", State: apply.State}); err != nil || controller.isStopped() {
		t.Fatalf("rollback stopped=%v err=%v", controller.isStopped(), err)
	}
	controller.setStartTime(992)
	controller.setStopped(true)
	if _, err = playbook.Rollback(context.Background(), Invocation{ActionID: "act_test", State: apply.State}); err != nil || !controller.isStopped() {
		t.Fatalf("reused PID was signaled: stopped=%v err=%v", controller.isStopped(), err)
	}
}

func TestTemporaryProcessSuspendAutomaticallyResumesAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	controller := &fakeProcessController{identity: ProcessRuntimeIdentity{PID: 91, PPID: 1, UID: 0, StartTime: 992, Executable: "/tmp/restart-safe"}}
	first, err := NewTemporaryProcessSuspendPlaybook(controller, dir)
	if err != nil {
		t.Fatal(err)
	}
	// A 30-second validated TTL becomes due in a few milliseconds. Cancel the
	// first in-memory timer to model a Helper crash, then reconstruct it solely
	// from the fsynced journal.
	first.now = func() time.Time { return time.Now().Add(-30*time.Second + 50*time.Millisecond) }
	params, _ := json.Marshal(TemporaryProcessSuspendParams{PID: 91, StartTime: 992, Executable: "/tmp/restart-safe", TTLSeconds: 30})
	if _, err = first.Apply(context.Background(), Invocation{ActionID: "act_restart", Parameters: params}); err != nil {
		t.Fatal(err)
	}
	first.cancelTimer("act_restart")
	if _, err = NewTemporaryProcessSuspendPlaybook(controller, dir); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, statErr := os.Stat(first.journalPath("act_restart"))
		if !controller.isStopped() && errors.Is(statErr, os.ErrNotExist) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if controller.isStopped() {
		t.Fatal("expired durable process journal did not resume the process")
	}
	if _, err = os.Stat(first.journalPath("act_restart")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resume journal was not removed: %v", err)
	}
}

func TestTemporaryProcessSuspendKeepsJournalWhenResumeFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	controller := &fakeProcessController{identity: ProcessRuntimeIdentity{PID: 92, PPID: 1, UID: 0, StartTime: 993, Executable: "/tmp/retry-safe"}}
	playbook, err := NewTemporaryProcessSuspendPlaybook(controller, dir)
	if err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(TemporaryProcessSuspendParams{PID: 92, StartTime: 993, Executable: "/tmp/retry-safe", TTLSeconds: 30})
	if _, err = playbook.Apply(context.Background(), Invocation{ActionID: "act_retry", Parameters: params}); err != nil {
		t.Fatal(err)
	}
	playbook.cancelTimer("act_retry")
	controller.setContinueError(errors.New("temporary signal failure"))
	playbook.expire("act_retry")
	playbook.cancelTimer("act_retry")
	if !controller.isStopped() {
		t.Fatal("failed resume unexpectedly changed process state")
	}
	if _, err = os.Stat(playbook.journalPath("act_retry")); err != nil {
		t.Fatalf("failed resume discarded durable journal: %v", err)
	}
}
