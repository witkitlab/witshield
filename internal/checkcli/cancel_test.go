package checkcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/domain"
)

type canceledSSHRunner struct {
	cancel        context.CancelFunc
	config        string
	stage         string
	livePassword  bool
	reloads       int
	failRestore   bool
	freshRollback bool
}

func (r *canceledSSHRunner) Run(ctx context.Context, c action.Command) (action.CommandResult, error) {
	if err := ctx.Err(); err != nil {
		return action.CommandResult{}, err
	}
	if c.Path == systemctlPath && len(c.Args) > 0 && c.Args[0] == "reload" {
		content, err := os.ReadFile(r.config)
		if err != nil {
			return action.CommandResult{}, err
		}
		password := bytes.Contains(content, []byte("PasswordAuthentication yes"))
		if r.reloads > 0 && password {
			r.freshRollback = true
			if _, bounded := ctx.Deadline(); !bounded {
				return action.CommandResult{}, errors.New("recovery context has no deadline")
			}
			if r.failRestore {
				return action.CommandResult{}, errors.New("fixture restorative reload unavailable")
			}
		}
		r.livePassword = password
		r.reloads++
		if r.stage == "apply" && r.reloads == 1 {
			r.cancel()
			return action.CommandResult{}, ctx.Err()
		}
		return action.CommandResult{}, nil
	}
	if c.Path == sshdPath {
		if len(c.Args) > 0 && c.Args[0] == "-T" && r.stage == "verify" {
			r.cancel()
			return action.CommandResult{}, ctx.Err()
		}
		return action.CommandResult{Stdout: "passwordauthentication no\n"}, nil
	}
	return action.CommandResult{}, errors.New("unexpected fixture command")
}

type recordingSSHEngine struct {
	engine  *action.Engine
	execute action.Request
	receipt action.Receipt
}

func (e *recordingSSHEngine) Run(ctx context.Context, r action.Request) action.Receipt {
	receipt := e.engine.Run(ctx, r)
	if r.Operation == action.OperationExecute {
		e.execute = r
		e.receipt = receipt
	}
	return receipt
}

func TestCancellationDuringTypedSSHMutationRestoresLiveService(t *testing.T) {
	for _, stage := range []string{"apply", "verify"} {
		t.Run(stage, func(t *testing.T) {
			runner, engine, config, journalDir, original, ctx, out := runCanceledSSHFixture(t, stage, false)
			if !engine.receipt.Indeterminate || len(engine.receipt.State) == 0 {
				t.Fatalf("fixture did not cross uncertain mutation: %#v", engine.receipt)
			}
			restored, err := os.ReadFile(config)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(restored, original) || !runner.livePassword || runner.reloads != 2 || !runner.freshRollback || !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("disk=%s livePassword=%v reloads=%d fresh=%v canceled=%v output=%s", restored, runner.livePassword, runner.reloads, runner.freshRollback, ctx.Err(), out)
			}
			entries, err := os.ReadDir(journalDir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 || !strings.Contains(out, "已恢复原来的 SSH 配置") {
				t.Fatalf("journals=%v output=%s", entries, out)
			}
		})
	}
}

func TestFailedDetachedSSHRecoveryPreservesJournalAndReportsUncertainty(t *testing.T) {
	runner, engine, config, journalDir, original, _, out := runCanceledSSHFixture(t, "verify", true)
	restored, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(journalDir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, original) || runner.livePassword || len(entries) != 1 || !strings.Contains(out, "主动恢复没有成功") || strings.Contains(out, "已恢复原来的 SSH 配置") {
		t.Fatalf("disk=%s livePassword=%v journals=%v output=%s", restored, runner.livePassword, entries, out)
	}
	// Finish the fixture rollback so no timer survives the test.
	runner.failRestore = false
	req := engine.execute
	req.Operation = action.OperationRollback
	req.State = engine.receipt.State
	cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if receipt := engine.engine.Run(cleanupCtx, req); !receipt.Success {
		t.Fatalf("fixture cleanup failed: %#v", receipt)
	}
}

func runCanceledSSHFixture(t *testing.T, stage string, failRestore bool) (*canceledSSHRunner, *recordingSSHEngine, string, string, []byte, context.Context, string) {
	t.Helper()
	dir := t.TempDir()
	config := filepath.Join(dir, "sshd_config")
	journalDir := filepath.Join(dir, "journals")
	original := []byte("PasswordAuthentication yes\n")
	if err := os.WriteFile(config, original, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	runner := &canceledSSHRunner{cancel: cancel, config: config, stage: stage, livePassword: true, failRestore: failRestore}
	playbook, err := action.NewSSHPasswordHardeningPlaybook(action.SSHHardeningConfig{
		Runner: runner, SSHDPath: sshdPath, SystemctlPath: systemctlPath, ConfigPath: config, ServiceName: "ssh", JournalDir: journalDir, DefaultRollbackDelay: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	typedEngine, err := action.NewEngine(playbook)
	if err != nil {
		t.Fatal(err)
	}
	engine := &recordingSSHEngine{engine: typedEngine}
	var output bytes.Buffer
	fixer := &Fixer{Engine: engine, In: NewLineReader(strings.NewReader("y\n")), Out: &output, SSHConfirmWindow: time.Minute, KeyLoginReady: func() (bool, string) { return true, "fixture" }, Now: time.Now}
	fixer.FixAll(ctx, []domain.Finding{sshFinding})
	return runner, engine, config, journalDir, original, ctx, output.String()
}

type uncertainSSHEngine struct{}

func (uncertainSSHEngine) Run(_ context.Context, r action.Request) action.Receipt {
	if r.Operation == action.OperationExecute {
		return action.Receipt{Indeterminate: true, Error: "fixture lost rollback state"}
	}
	return action.Receipt{Success: true}
}

func TestUncertainSSHWithoutSealedStateRequiresProtectedRecovery(t *testing.T) {
	for _, recoverError := range []error{nil, errors.New("protected journal not found")} {
		ctx, cancel := context.WithCancel(context.Background())
		var out bytes.Buffer
		called := false
		fixer := &Fixer{Engine: uncertainSSHEngine{}, In: NewLineReader(strings.NewReader("y\n")), Out: &out, SSHConfirmWindow: time.Minute, KeyLoginReady: func() (bool, string) { return true, "fixture" }, Now: time.Now,
			RecoverSSH: func(recoveryCtx context.Context, id string, _ io.Writer) error {
				called = true
				cancel()
				if recoveryCtx.Err() != nil || !strings.HasPrefix(id, "cli-ssh-") {
					t.Fatalf("invalid recovery context or action: %v %q", recoveryCtx.Err(), id)
				}
				if _, ok := recoveryCtx.Deadline(); !ok {
					t.Fatal("recovery context is not bounded")
				}
				return recoverError
			},
		}
		fixer.FixAll(ctx, []domain.Finding{sshFinding})
		cancel()
		if !called {
			t.Fatal("uncertain receipt skipped protected recovery")
		}
		if recoverError != nil && (strings.Contains(out.String(), "已恢复原来的 SSH 配置") || !strings.Contains(out.String(), "主动恢复没有成功")) {
			t.Fatal(out.String())
		}
	}
}

func TestJSONAndAIRejectedBeforeScanOrModelCall(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"--json", "--ai"}, strings.NewReader(""), &out, &errOut, runDependencies{
		isRoot: func() bool { return false },
		readOS: func() ([]byte, error) { t.Fatal("OS read before incompatible flags rejected"); return nil, nil },
		scan: func(context.Context) (domain.Report, func(context.Context) ([]string, error), error) {
			t.Fatal("scan before incompatible flags rejected")
			return domain.Report{}, nil, nil
		},
	})
	if code != 2 || out.Len() != 0 || json.Valid(out.Bytes()) || !strings.Contains(errOut.String(), "不能和 --json 一起用") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, &out, &errOut)
	}
}
