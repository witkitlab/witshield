package checkcli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/scanner"
)

const (
	// StateDir holds the CLI's own rollback journals and APT plans. It is
	// separate from the native Helper's state so the two never share a lock.
	StateDir        = "/var/lib/witshield-cli"
	PackagePlanBase = StateDir + "/package-plans"
	sshJournalDir   = StateDir + "/ssh-rollbacks"
)

const usage = `用法：witshield check [选项]

  一次性体检这台服务器：不安装服务、不开端口。普通体检不联网；--ai 和软件包升级需要联网。

选项：
  --fix                 体检后逐项修复可一键修复的问题（需要 sudo）
  --ai                  用你自己的大模型 API 解读报告（见 WITSHIELD_AI_* 环境变量）
  --json                输出 JSON
  --no-color            不使用颜色
  --ssh-confirm-seconds 修复 SSH 后等待你确认新登录的秒数（默认 180，范围 30–600）
`

type runDependencies struct {
	isRoot      func() bool
	readOS      func() ([]byte, error)
	runner      action.Runner
	scan        func(context.Context) (domain.Report, func(context.Context) ([]string, error), error)
	buildEngine func(string) (*action.Engine, error)
	sshFailures func(context.Context) SSHFailures
}

// Run executes `witshield check`: 0 for score >=60, 1 below, 2 on errors.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runWithDependencies(ctx, args, stdin, stdout, stderr, runDependencies{
		isRoot:      func() bool { return os.Geteuid() == 0 },
		readOS:      func() ([]byte, error) { return os.ReadFile("/etc/os-release") },
		runner:      action.NewExecRunner(systemctlPath),
		buildEngine: buildEngine,
		sshFailures: CollectSSHFailures,
		scan: func(ctx context.Context) (domain.Report, func(context.Context) ([]string, error), error) {
			host, err := scanner.NewSystemHost("/")
			if err != nil {
				return domain.Report{}, nil, err
			}
			report, err := scanner.NewWithHost(host, false).Scan(ctx, "local")
			return report, func(ctx context.Context) ([]string, error) {
				out, err := host.Probe(ctx, scanner.ProbeUpdates)
				return ParseAptSimulate(out), err
			}, err
		},
	})
}

func runWithDependencies(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, deps runDependencies) int {
	fl := flag.NewFlagSet("check", flag.ContinueOnError)
	fl.SetOutput(stderr)
	fl.Usage = func() { fmt.Fprint(stderr, usage) }
	fix := fl.Bool("fix", false, "")
	useAI := fl.Bool("ai", false, "")
	asJSON := fl.Bool("json", false, "")
	noColor := fl.Bool("no-color", false, "")
	confirmSeconds := fl.Int("ssh-confirm-seconds", 180, "")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 0 {
		fmt.Fprintln(stderr, "check 不接受位置参数")
		return 2
	}
	if *confirmSeconds < 30 || *confirmSeconds > 600 {
		fmt.Fprintln(stderr, "--ssh-confirm-seconds 需要在 30 到 600 之间")
		return 2
	}
	isRoot := deps.isRoot()
	if *fix && !isRoot {
		fmt.Fprintln(stderr, "修复需要 root 权限，请用：sudo witshield check --fix")
		return 2
	}
	if *fix && *asJSON {
		fmt.Fprintln(stderr, "--fix 是交互式的，不能和 --json 一起用")
		return 2
	}
	color := !*noColor && !*asJSON && os.Getenv("NO_COLOR") == "" && isTerminal(stdout)

	osData, _ := deps.readOS()
	osInfo := ParseOSRelease(osData)
	if *fix && !osInfo.Debian {
		fmt.Fprintln(stderr, "目前只对 Ubuntu/Debian 做过完整测试；无法确认这是 Debian 系统，已拒绝自动修复。请按报告中的命令手动处理。")
		return 2
	}
	service := detectSSHService(ctx, deps.runner)
	h := Host{Name: hostname(), OS: osInfo.Name, IsRoot: isRoot, SSHUnavailable: service == "", UntestedOS: !osInfo.Debian}
	if !*asJSON {
		fmt.Fprintln(stderr, "正在体检，通常需要 10–30 秒……")
	}
	report, pendingUpdates, err := deps.scan(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "体检中断：%v\n", err)
		return 2
	}

	if deps.sshFailures != nil {
		h.SSHFailures = deps.sshFailures(ctx)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(ToJSON(report, h))
	} else {
		Render(stdout, report, h, color)
	}

	if *useAI {
		cfg, err := AIConfigFromEnv()
		if err != nil {
			fmt.Fprintln(stderr, aiHelp)
		} else {
			fmt.Fprintln(stderr, "正在请模型解读……")
			text, err := Explain(ctx, cfg, report, h.SSHFailures)
			if err != nil {
				fmt.Fprintf(stderr, "模型调用失败：%v\n", err)
			} else {
				fmt.Fprintf(stdout, "%s\n%s\n\n", style{color}.bold("AI 解读（"+cfg.Model+"，仅供参考）"), strings.TrimSpace(text))
			}
		}
	}

	if *fix {
		engine, err := deps.buildEngine(service)
		if err != nil {
			fmt.Fprintf(stderr, "无法准备修复环境：%v\n", err)
			return 2
		}
		(&Fixer{
			Engine: engine, In: NewLineReader(stdin), Out: stdout, Color: color,
			FullHelperActive: fullHelperActive(ctx, deps.runner), SSHUnavailable: service == "",
			SSHConfirmWindow: time.Duration(*confirmSeconds) * time.Second,
			PendingUpdates:   pendingUpdates,
			ShadowGID:        ShadowGID, KeyLoginReady: KeyLoginReady("/"), Now: time.Now,
		}).FixAll(ctx, report.Findings)
	}
	if report.Score < 60 {
		return 1
	}
	return 0
}

// buildEngine wires the same typed playbooks the native Helper uses, with the
// CLI's own state directory. Only the three repairs the CLI offers are loaded.
func buildEngine(service string) (*action.Engine, error) {
	if err := os.MkdirAll(StateDir, 0o700); err != nil {
		return nil, err
	}
	if err := privateRecoveryPath(StateDir, true); err != nil {
		return nil, err
	}
	runner := action.NewExecRunner(aptGetPath, dpkgQueryPath, sshdPath, systemctlPath)
	var playbooks []action.Playbook
	if hook, err := os.Executable(); err == nil {
		if p, err := action.NewPackageSecurityUpgradePlaybook(runner, aptGetPath, dpkgQueryPath, hook, PackagePlanBase); err == nil {
			playbooks = append(playbooks, p)
		}
	}
	if _, err := os.Stat(sshdPath); err == nil && service != "" {
		p, err := action.NewSSHPasswordHardeningPlaybook(action.SSHHardeningConfig{
			Runner: runner, SSHDPath: sshdPath, SystemctlPath: systemctlPath,
			ConfigPath: "/etc/ssh/sshd_config", ServiceName: service, JournalDir: sshJournalDir,
			DefaultRollbackDelay: 3 * time.Minute,
		})
		if err != nil {
			return nil, err
		}
		playbooks = append(playbooks, p)
	}
	modes := []fs.FileMode{0o640, 0o600}
	gids := []int{0}
	if g := ShadowGID(); g >= 0 {
		gids = append(gids, g)
	}
	if _, err := os.Stat("/etc/shadow"); err == nil {
		p, err := action.NewFilePermissionRepairPlaybook([]action.ApprovedPath{{Path: "/etc/shadow", FileModes: modes, UIDs: []int{0}, GIDs: gids}})
		if err != nil {
			return nil, err
		}
		playbooks = append(playbooks, p)
	}
	return action.NewEngine(playbooks...)
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}
