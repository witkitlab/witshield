package checkcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/domain"
)

type systemRunner struct {
	commands []action.Command
	states   map[string]string
	active   bool
}

func (s *systemRunner) Run(_ context.Context, c action.Command) (action.CommandResult, error) {
	s.commands = append(s.commands, c)
	if len(c.Args) > 0 && c.Args[0] == "show" {
		return action.CommandResult{Stdout: s.states[c.Args[len(c.Args)-1]]}, nil
	}
	if len(c.Args) > 0 && c.Args[0] == "is-active" && s.active {
		return action.CommandResult{Stdout: "active\n"}, nil
	}
	return action.CommandResult{}, errors.New("unavailable")
}

func TestDetectSSHServices(t *testing.T) {
	for _, tc := range []struct {
		name   string
		states map[string]string
		want   string
		calls  int
	}{
		{"debian", map[string]string{"ssh.service": "loaded\n"}, "ssh", 1},
		{"sshd", map[string]string{"ssh.service": "not-found", "sshd.service": "loaded"}, "sshd", 2},
		{"neither", map[string]string{"ssh.service": "not-found", "sshd.service": "not-found"}, "", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &systemRunner{states: tc.states}
			if got := detectSSHService(context.Background(), r); got != tc.want || len(r.commands) != tc.calls {
				t.Fatalf("service=%q commands=%v", got, r.commands)
			}
			for _, c := range r.commands {
				if c.Path != systemctlPath || c.Timeout != 5*time.Second {
					t.Fatalf("unexpected command: %#v", c)
				}
			}
		})
	}
}

func TestReadLineCancellationAndEOF(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	reader := NewLineReader(pr)
	cancel()
	start := time.Now()
	if _, err := reader.ReadLineContext(ctx, time.Minute); !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
		t.Fatalf("cancel err=%v", err)
	}
	empty := NewLineReader(strings.NewReader(""))
	for range 2 {
		if _, err := empty.ReadLineContext(context.Background(), time.Second); !errors.Is(err, io.EOF) {
			t.Fatalf("EOF err=%v", err)
		}
	}
}

type cancelOnExecute struct {
	fakeEngine
	cancel         context.CancelFunc
	rollbackCtxErr error
}

func (e *cancelOnExecute) Run(ctx context.Context, r action.Request) action.Receipt {
	result := e.fakeEngine.Run(ctx, r)
	if r.Operation == action.OperationExecute {
		e.cancel()
	}
	if r.Operation == action.OperationRollback {
		e.rollbackCtxErr = ctx.Err()
	}
	return result
}
func TestSSHInterruptImmediatelyRollsBackWithLiveContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deadline := time.Now().Add(10 * time.Minute)
	e := &cancelOnExecute{fakeEngine: fakeEngine{confirmBy: &deadline}, cancel: cancel}
	x, out := newFixer(&e.fakeEngine, "y\n", true)
	x.Engine = e
	start := time.Now()
	x.FixAll(ctx, []domain.Finding{sshFinding})
	if got := ops(e.ops...); got != "precheck,preview,execute,rollback" || time.Since(start) > time.Second || e.rollbackCtxErr != nil {
		t.Fatalf("ops=%v duration=%v rollbackctx=%v", e.ops, time.Since(start), e.rollbackCtxErr)
	}
	if !strings.Contains(out.String(), "已恢复原来的 SSH 配置") {
		t.Fatal(out.String())
	}
}

func TestFullHelperRequiresAdditionalApproval(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"n\n", ""}, {"y\nn\n", "precheck,preview"}, {"y\ny\n", "precheck,preview,execute"},
	} {
		e := &fakeEngine{}
		x, out := newFixer(e, tc.input, true)
		x.FullHelperActive = true
		x.FixAll(context.Background(), []domain.Finding{{Title: "/etc/shadow is accessible to other users"}})
		if got := ops(e.ops...); got != tc.want || !strings.Contains(out.String(), "这台服务器已经安装了完整版，建议在控制台里修复") {
			t.Fatalf("ops=%s output=%s", got, out)
		}
	}
	for _, active := range []bool{false, true} {
		if fullHelperActive(context.Background(), &systemRunner{active: active}) != active {
			t.Fatal("wrong helper status")
		}
	}
}

func TestDebianOSRelease(t *testing.T) {
	for _, tc := range []struct {
		text   string
		debian bool
	}{
		{"ID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04\"", true},
		{"ID=debian", true}, {"ID=linuxmint\nID_LIKE=\"ubuntu debian\"", true},
		{"ID=custom\nID_LIKE='debian'", true}, {"ID=fedora\nID_LIKE=rhel", false},
		{"ID=notdebian", false}, {"", false},
	} {
		if got := ParseOSRelease([]byte(tc.text)); got.Debian != tc.debian {
			t.Fatalf("%q => %#v", tc.text, got)
		}
	}
}

func TestUnsupportedOSScansButRejectsFix(t *testing.T) {
	for _, fix := range []bool{false, true} {
		scanned := false
		var out, errOut bytes.Buffer
		args := []string{"--no-color"}
		if fix {
			args = append(args, "--fix")
		}
		code := runWithDependencies(context.Background(), args, strings.NewReader(""), &out, &errOut, runDependencies{
			isRoot: func() bool { return true }, readOS: func() ([]byte, error) { return []byte("ID=fedora"), nil }, runner: &systemRunner{},
			scan: func(context.Context) (domain.Report, func(context.Context) ([]string, error), error) {
				scanned = true
				return report(85), nil, nil
			},
			buildEngine: func(string) (*action.Engine, error) { t.Fatal("unsupported fix built engine"); return nil, nil },
		})
		if fix {
			if code != 2 || scanned || !strings.Contains(errOut.String(), "拒绝自动修复") {
				t.Fatalf("code=%d scanned=%v err=%s", code, scanned, &errOut)
			}
		} else if code != 0 || !scanned || !strings.Contains(out.String(), "目前只对 Ubuntu/Debian 做过完整测试") {
			t.Fatalf("code=%d output=%s", code, &out)
		}
	}
}

func TestUnavailableSSHIsManualInReportsAndFixer(t *testing.T) {
	var out bytes.Buffer
	h := Host{IsRoot: true, SSHUnavailable: true}
	Render(&out, report(80, sshFinding), h, false)
	if !strings.Contains(out.String(), "本机无法自动修复，请按命令手动处理") || strings.Contains(out.String(), "SSH 允许密码登录  可一键修复") || ToJSON(report(80, sshFinding), h).Findings[0].Fixable {
		t.Fatal(out.String())
	}
	e := &fakeEngine{}
	x, _ := newFixer(e, "y\nyes\n", true)
	x.SSHUnavailable = true
	x.FixAll(context.Background(), []domain.Finding{sshFinding})
	if len(e.ops) > 0 {
		t.Fatal(e.ops)
	}
}

func TestAptArchitectureNamesAcceptedByTypedPlaybook(t *testing.T) {
	packages := ParseAptSimulate([]byte("Inst libc6:i386 [1] (2 test)\nInst libc6:amd64 [1] (2 test)\nInst libc6:i386 [1] (2 test)\n"))
	if !reflect.DeepEqual(packages, []string{"libc6:i386", "libc6:amd64"}) {
		t.Fatal(packages)
	}
	hook, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p, err := action.NewPackageSecurityUpgradePlaybook(&systemRunner{}, aptGetPath, dpkgQueryPath, hook, filepath.Join(t.TempDir(), "plans"))
	if err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(action.PackageSecurityUpgradeParams{Packages: packages})
	if err := p.Validate(params); err != nil {
		t.Fatalf("retained package rejected by playbook: %v", err)
	}
}

type recoveryRunner struct {
	systemRunner
	config string
}

func (r *recoveryRunner) Run(ctx context.Context, c action.Command) (action.CommandResult, error) {
	if c.Path == systemctlPath && len(c.Args) > 0 && c.Args[0] == "show" {
		return r.systemRunner.Run(ctx, c)
	}
	if c.Path == sshdPath {
		if len(c.Args) > 0 && c.Args[0] == "-T" {
			return action.CommandResult{Stdout: "passwordauthentication no\n"}, nil
		}
		return action.CommandResult{}, nil
	}
	if c.Path == systemctlPath && len(c.Args) > 0 && c.Args[0] == "reload" {
		return action.CommandResult{}, nil
	}
	return action.CommandResult{}, errors.New("unexpected fake command")
}

func TestStartupRecoveryCompletesBeforeReturning(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("recovery requires root-owned temporary fixtures")
	}
	dir := t.TempDir()
	journalDir := filepath.Join(dir, "journals")
	configPath := filepath.Join(dir, "sshd_config")
	original := []byte("PasswordAuthentication yes\n")
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recoveryRunner{systemRunner: systemRunner{states: map[string]string{"ssh.service": "loaded"}}, config: configPath}
	cfg := action.SSHHardeningConfig{Runner: runner, SSHDPath: sshdPath, SystemctlPath: systemctlPath, ConfigPath: configPath, ServiceName: "ssh", JournalDir: journalDir, DefaultRollbackDelay: 3 * time.Minute}
	playbook, err := action.NewSSHPasswordHardeningPlaybook(cfg)
	if err != nil {
		t.Fatal(err)
	}
	params := json.RawMessage(`{"rollbackAfterSeconds":180}`)
	_, err = playbook.Apply(context.Background(), action.Invocation{ActionID: "cli-ssh-123", Actor: "witshield-cli", Parameters: params})
	if err != nil {
		t.Fatal(err)
	}
	changed, _ := os.ReadFile(configPath)
	if bytes.Equal(changed, original) {
		t.Fatal("fixture not changed")
	}
	var out bytes.Buffer
	if err := recoverSSHJournals(context.Background(), &out, runner, cfg); err != nil {
		t.Fatal(err)
	}
	restored, _ := os.ReadFile(configPath)
	if !bytes.Equal(restored, original) {
		t.Fatalf("config not restored: %s", restored)
	}
	entries, _ := os.ReadDir(journalDir)
	if len(entries) != 0 || !strings.Contains(out.String(), "已恢复原来的 SSH 配置") {
		t.Fatalf("entries=%v output=%s", entries, &out)
	}
}

func TestRecoveryRejectsUnsafePathsAndUnknownParameters(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned recovery fixtures")
	}
	for _, kind := range []string{"directory-mode", "file-mode", "symlink", "unknown-params", "oversize", "too-many", "unknown-field"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			params, _ := json.Marshal(action.SSHPasswordHardeningParams{RollbackAfterSeconds: 180})
			journal := recoveryJournal{ActionID: "cli-ssh-1", ParametersDigest: action.ParametersDigest(params), State: json.RawMessage(`{}`), StateDigest: "irrelevant", ConfirmBy: time.Now()}
			if kind == "unknown-params" {
				journal.ParametersDigest = "unknown"
			}
			data, _ := json.Marshal(journal)
			path := filepath.Join(dir, "ssh-cli-ssh-1.json")
			if kind == "oversize" {
				data = bytes.Repeat([]byte("x"), maxRecoveryJournalBytes+1)
			}
			if kind == "unknown-field" {
				data = append(data[:len(data)-1], []byte(`,"unexpected":true}`)...)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "directory-mode":
				_ = os.Chmod(dir, 0o755)
			case "file-mode":
				_ = os.Chmod(path, 0o644)
			case "symlink":
				_ = os.Rename(path, path+".real")
				_ = os.Symlink(path+".real", path)
			case "too-many":
				for i := range 65 {
					_ = os.WriteFile(filepath.Join(dir, string(rune('A'+i))), nil, 0o600)
				}
			}
			if _, err := readRecoveryJournals(dir); err == nil {
				t.Fatal("unsafe recovery accepted")
			}
		})
	}
	for _, seconds := range []int{0, 30, 180, 600} {
		params, _ := json.Marshal(action.SSHPasswordHardeningParams{RollbackAfterSeconds: seconds})
		got, err := recoveryParameters(action.ParametersDigest(params))
		if err != nil || !bytes.Equal(got, params) {
			t.Fatalf("seconds=%d got=%s err=%v", seconds, got, err)
		}
	}
}
