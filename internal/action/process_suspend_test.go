package action

import (
	"context"
	"encoding/json"
	"testing"
)

type fakeProcessController struct {
	identity ProcessRuntimeIdentity
	stopped  bool
}

func (f *fakeProcessController) Inspect(int) (ProcessRuntimeIdentity, error) {
	f.identity.Stopped = f.stopped
	return f.identity, nil
}
func (f *fakeProcessController) Stop(int) error     { f.stopped = true; return nil }
func (f *fakeProcessController) Continue(int) error { f.stopped = false; return nil }

func TestTemporaryProcessSuspendBindsPIDStartTimeAndRollsBack(t *testing.T) {
	controller := &fakeProcessController{identity: ProcessRuntimeIdentity{PID: 88, PPID: 1, UID: 0, StartTime: 991, Executable: "/tmp/suspicious"}}
	playbook, err := NewTemporaryProcessSuspendPlaybook(controller)
	if err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(TemporaryProcessSuspendParams{PID: 88, StartTime: 991, Executable: "/tmp/suspicious", TTLSeconds: 60})
	apply, err := playbook.Apply(context.Background(), Invocation{Parameters: params})
	if err != nil || !controller.stopped || len(apply.State) == 0 || apply.ConfirmBy == nil {
		t.Fatalf("apply=%#v stopped=%v err=%v", apply, controller.stopped, err)
	}
	if _, err = playbook.Verify(context.Background(), Invocation{State: apply.State}); err != nil {
		t.Fatal(err)
	}
	if _, err = playbook.Rollback(context.Background(), Invocation{State: apply.State}); err != nil || controller.stopped {
		t.Fatalf("rollback stopped=%v err=%v", controller.stopped, err)
	}
	controller.identity.StartTime++
	controller.stopped = true
	if _, err = playbook.Rollback(context.Background(), Invocation{State: apply.State}); err != nil || !controller.stopped {
		t.Fatalf("reused PID was signaled: stopped=%v err=%v", controller.stopped, err)
	}
}
