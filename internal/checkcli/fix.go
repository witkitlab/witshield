package checkcli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/domain"
)

// Runner is the subset of action.Engine the fixer needs.
type Runner interface {
	Run(context.Context, action.Request) action.Receipt
}

// Fixer walks the fixable findings one at a time. Every change is previewed,
// needs an explicit "y", is verified after apply, and is rolled back by the
// engine when verification fails.
type Fixer struct {
	Engine Runner
	In     *LineReader
	Out    io.Writer
	Color  bool
	// FullHelperActive requires an additional approval before CLI repairs.
	FullHelperActive bool
	// SSHUnavailable disables repairs when no SSH service was found.
	SSHUnavailable bool
	// SSHConfirmWindow is how long the user has to prove a new SSH login works.
	SSHConfirmWindow time.Duration
	// PendingUpdates lists upgradable packages (apt-get -s upgrade).
	PendingUpdates func(context.Context) ([]string, error)
	// ShadowGID returns the shadow group's GID, or -1 when the group is absent.
	ShadowGID func() int
	// KeyLoginReady reports whether some account can log in with an SSH key.
	KeyLoginReady func() (bool, string)
	Now           func() time.Time
}

// FixAll runs the interactive repair for every fixable finding.
func (x *Fixer) FixAll(ctx context.Context, findings []domain.Finding) {
	s := style{x.Color}
	var todo []domain.Finding
	for _, f := range Sorted(findings) {
		if AdviceFor(f).Fix != FixNone && !(x.SSHUnavailable && AdviceFor(f).Fix == FixSSHPassword) {
			todo = append(todo, f)
		}
	}
	if len(todo) == 0 {
		fmt.Fprintln(x.Out, "\n没有可以一键修复的问题。其余问题请按报告里的「怎么修」手动处理。")
		return
	}
	if x.FullHelperActive {
		fmt.Fprintln(x.Out, "\n这台服务器已经安装了完整版，建议在控制台里修复。")
		if !x.ask(ctx, "仍然使用命令行修复？") {
			fmt.Fprintln(x.Out, "  已取消命令行修复。")
			return
		}
	}
	fmt.Fprintf(x.Out, "\n%s\n", s.bold(fmt.Sprintf("开始逐项修复，共 %d 项。每一项都会先告诉你要改什么，你输入 y 才会动手。", len(todo))))
	done := 0
	for i, f := range todo {
		if ctx.Err() != nil {
			return
		}
		a := AdviceFor(f)
		fmt.Fprintf(x.Out, "\n%s %s\n", s.bold(fmt.Sprintf("[%d/%d]", i+1, len(todo))), s.bold(a.Title))
		var ok bool
		switch a.Fix {
		case FixSSHPassword:
			ok = x.fixSSH(ctx)
		case FixShadowPerm:
			ok = x.fixShadow(ctx)
		case FixPackageUpdate:
			ok = x.fixUpdates(ctx)
		}
		if ok {
			done++
		}
	}
	fmt.Fprintf(x.Out, "\n%s\n再运行一次 %s 看看新的分数。\n\n", s.bold(fmt.Sprintf("修复结束：完成 %d 项，共 %d 项。", done, len(todo))), s.bold("sudo witshield check"))
}

func (x *Fixer) actionID(kind string) string {
	return fmt.Sprintf("cli-%s-%d", kind, x.Now().UnixNano())
}

func (x *Fixer) ask(ctx context.Context, question string) bool {
	fmt.Fprintf(x.Out, "  %s [y/N] ", question)
	line, err := x.In.ReadLineContext(ctx, 0)
	if err != nil {
		fmt.Fprintln(x.Out)
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes" || answer == "是"
}

func (x *Fixer) fixSSH(ctx context.Context) bool {
	s := style{x.Color}
	if ready, who := x.KeyLoginReady(); !ready {
		fmt.Fprintln(x.Out, s.sev(domain.SeverityHigh, "  跳过：没有找到任何账号配置了 SSH 公钥。现在关闭密码登录会把你关在服务器外面。"))
		fmt.Fprintln(x.Out, "  先在自己电脑上运行 ssh-copy-id 用户名@服务器，确认能用密钥登录后，再运行一次 --fix。")
		return false
	} else {
		fmt.Fprintf(x.Out, "  已找到可以用密钥登录的账号：%s\n", who)
	}
	window := x.SSHConfirmWindow
	params, _ := json.Marshal(action.SSHPasswordHardeningParams{RollbackAfterSeconds: int(window / time.Second)})
	fmt.Fprintln(x.Out, "  会做的事：")
	fmt.Fprintln(x.Out, "    1. 备份 /etc/ssh/sshd_config，把 PasswordAuthentication 改成 no")
	fmt.Fprintln(x.Out, "    2. 用 sshd -t 校验配置，通过后重新加载 SSH（已经连着的窗口不会断）")
	fmt.Fprintf(x.Out, "    3. 等你新开一个窗口确认还能登录；%d 秒内没有确认，自动恢复原配置\n", int(window/time.Second))
	id := x.actionID("ssh")
	if !x.preview(ctx, id, action.TypeSSHPasswordHardening, params) || !x.ask(ctx, "现在修改？") {
		fmt.Fprintln(x.Out, "  已跳过。")
		return false
	}
	receipt := x.Engine.Run(ctx, action.Request{ActionID: id, Actor: "witshield-cli", Type: action.TypeSSHPasswordHardening, Operation: action.OperationExecute, Parameters: params})
	x.printSteps(receipt)
	if !receipt.Success {
		x.printFailure(receipt)
		return false
	}
	if receipt.ConfirmBy == nil {
		fmt.Fprintln(x.Out, s.wrap("32", "  完成：密码登录已经是关闭状态，无需改动。"))
		return true
	}
	deadline := *receipt.ConfirmBy
	fmt.Fprintln(x.Out)
	fmt.Fprintln(x.Out, s.bold("  请不要关闭这个窗口。"))
	fmt.Fprintln(x.Out, "  现在新开一个终端，用密钥登录这台服务器（ssh 用户名@服务器）。")
	fmt.Fprintf(x.Out, "  能登录的话，回到这里输入 yes 并回车。%s 前没有确认，会自动恢复原配置。\n", deadline.Local().Format("15:04:05"))
	fmt.Fprint(x.Out, "  新窗口能登录吗？输入 yes 确认，其他任意内容恢复原配置：")
	wait := time.Until(deadline) - 5*time.Second
	if wait < time.Second {
		wait = time.Second
	}
	line, err := x.In.ReadLineContext(ctx, wait)
	answer := strings.ToLower(strings.TrimSpace(line))
	fmt.Fprintln(x.Out)
	if err == nil && ctx.Err() == nil && (answer == "yes" || answer == "y" || answer == "是" || answer == "确认") {
		c := x.Engine.Run(ctx, action.Request{ActionID: id, Actor: "witshield-cli", Type: action.TypeSSHPasswordHardening, Operation: action.OperationConfirm, Parameters: params, State: receipt.State})
		if c.Success {
			fmt.Fprintln(x.Out, s.wrap("32", "  完成：SSH 已改为只允许密钥登录，自动恢复已取消。"))
			return true
		}
		fmt.Fprintf(x.Out, "  确认没有成功（%s），正在恢复原配置。\n", c.Error)
	}
	if err != nil {
		fmt.Fprintln(x.Out, "  没有收到确认。")
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := x.Engine.Run(rollbackCtx, action.Request{ActionID: id, Actor: "witshield-cli", Type: action.TypeSSHPasswordHardening, Operation: action.OperationRollback, Parameters: params, State: receipt.State})
	if r.Success {
		fmt.Fprintln(x.Out, "  已恢复原来的 SSH 配置，密码登录仍然可用。")
	} else {
		fmt.Fprintf(x.Out, "  主动恢复没有成功（%s）。原配置的备份记录在 /var/lib/witshield-cli/ssh-rollbacks，下次运行 witshield 时会继续恢复。\n", r.Error)
	}
	return false
}

func (x *Fixer) fixShadow(ctx context.Context) bool {
	gid := x.ShadowGID()
	mode, gidValue, desc := "0640", gid, "root:shadow 0640"
	if gid < 0 {
		mode, gidValue, desc = "0600", 0, "root:root 0600"
	}
	uid := 0
	params, _ := json.Marshal(action.FilePermissionRepairParams{Path: "/etc/shadow", Mode: mode, UID: &uid, GID: &gidValue})
	fmt.Fprintf(x.Out, "  会做的事：把 /etc/shadow 的属主和权限改回系统默认的 %s，改完立即检查。\n", desc)
	id := x.actionID("shadow")
	if !x.preview(ctx, id, action.TypeFilePermissionRepair, params) || !x.ask(ctx, "现在修改？") {
		fmt.Fprintln(x.Out, "  已跳过。")
		return false
	}
	return x.execute(ctx, id, action.TypeFilePermissionRepair, params, "完成：/etc/shadow 权限已恢复。")
}

func (x *Fixer) fixUpdates(ctx context.Context) bool {
	packages, err := x.PendingUpdates(ctx)
	if err != nil || len(packages) == 0 {
		fmt.Fprintln(x.Out, "  读不到待更新的软件包列表，已跳过。可以手动运行：sudo apt update && sudo apt upgrade")
		return false
	}
	rest := 0
	if len(packages) > 64 {
		rest = len(packages) - 64
		packages = packages[:64]
	}
	params, _ := json.Marshal(action.PackageSecurityUpgradeParams{Packages: packages})
	fmt.Fprintf(x.Out, "  会做的事：只升级下面 %d 个已安装的软件包，不安装新包、不删除任何包；记录升级前的版本，升级后逐个核对。\n", len(packages))
	fmt.Fprintf(x.Out, "    %s\n", truncate(strings.Join(packages, " "), 300))
	if rest > 0 {
		fmt.Fprintf(x.Out, "    另有 %d 个，这次先不升级，下次再运行一次即可。\n", rest)
	}
	fmt.Fprintln(x.Out, "  提示：重要服务器建议先做快照。升级可能需要几分钟。")
	id := x.actionID("updates")
	if !x.preview(ctx, id, action.TypePackageSecurityUpgrade, params) || !x.ask(ctx, "现在升级？") {
		fmt.Fprintln(x.Out, "  已跳过。")
		return false
	}
	return x.execute(ctx, id, action.TypePackageSecurityUpgrade, params, "完成：软件包已升级并核对版本。")
}

func (x *Fixer) preview(ctx context.Context, id string, t action.Type, params json.RawMessage) bool {
	for _, op := range []action.Operation{action.OperationPrecheck, action.OperationPreview} {
		r := x.Engine.Run(ctx, action.Request{ActionID: id, Actor: "witshield-cli", Type: t, Operation: op, Parameters: params})
		if !r.Success {
			fmt.Fprintf(x.Out, "  %s没有通过，不会做任何修改：%s\n", opLabel[op], r.Error)
			return false
		}
	}
	fmt.Fprintln(x.Out, "  预检通过。")
	return true
}

func (x *Fixer) execute(ctx context.Context, id string, t action.Type, params json.RawMessage, okText string) bool {
	r := x.Engine.Run(ctx, action.Request{ActionID: id, Actor: "witshield-cli", Type: t, Operation: action.OperationExecute, Parameters: params})
	x.printSteps(r)
	if !r.Success {
		x.printFailure(r)
		return false
	}
	fmt.Fprintln(x.Out, style{x.Color}.wrap("32", "  "+okText))
	return true
}

var opLabel = map[action.Operation]string{
	action.OperationPrecheck: "预检", action.OperationPreview: "预览", action.OperationApply: "修改",
	action.OperationVerify: "验证", action.OperationRollback: "恢复", action.OperationConfirm: "确认",
}

func (x *Fixer) printSteps(r action.Receipt) {
	s := style{x.Color}
	var parts []string
	for _, step := range r.Steps {
		mark := s.wrap("32", "✓")
		if !step.Success {
			mark = s.wrap("31", "✗")
		}
		parts = append(parts, opLabel[step.Operation]+" "+mark)
	}
	if len(parts) > 0 {
		fmt.Fprintf(x.Out, "  %s\n", strings.Join(parts, "  →  "))
	}
}

func (x *Fixer) printFailure(r action.Receipt) {
	if r.Indeterminate {
		fmt.Fprintf(x.Out, "  没有成功，而且无法确认服务器当前状态，请手动检查：%s\n", r.Error)
		return
	}
	fmt.Fprintf(x.Out, "  没有成功，请核对下面的原因和服务器当前状态：%s\n", r.Error)
}

// LineReader reads answers from the terminal, optionally with a deadline.
type LineReader struct{ lines chan lineResult }

type lineResult struct {
	text string
	err  error
}

func NewLineReader(r io.Reader) *LineReader {
	lr := &LineReader{lines: make(chan lineResult)}
	go func() {
		defer close(lr.lines)
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			lr.lines <- lineResult{text: sc.Text()}
		}
		if err := sc.Err(); err != nil {
			lr.lines <- lineResult{err: err}
		}
	}()
	return lr
}

// ErrTimeout is returned when no answer arrives before the deadline.
var ErrTimeout = fmt.Errorf("no answer before the deadline")

// ReadLine waits for one line; timeout 0 waits forever.
func (lr *LineReader) ReadLine(timeout time.Duration) (string, error) {
	return lr.ReadLineContext(context.Background(), timeout)
}

// ReadLineContext waits for input, a deadline, or cancellation.
func (lr *LineReader) ReadLineContext(ctx context.Context, timeout time.Duration) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var deadline <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		deadline = t.C
	}
	select {
	case r, ok := <-lr.lines:
		if !ok {
			return "", io.EOF
		}
		return r.text, r.err
	case <-deadline:
		return "", ErrTimeout
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// KeyLoginReady looks for a non-empty authorized_keys for the sudo user and root.
func KeyLoginReady(root string) func() (bool, string) {
	return func() (bool, string) {
		var accounts []string
		if name := os.Getenv("SUDO_USER"); name != "" && name != "root" {
			if u, err := user.Lookup(name); err == nil {
				accounts = append(accounts, name+"\x00"+u.HomeDir)
			}
		}
		accounts = append(accounts, "root\x00/root")
		var ready []string
		for _, a := range accounts {
			name, home, _ := strings.Cut(a, "\x00")
			if HasAuthorizedKey(filepath.Join(root, home, ".ssh", "authorized_keys")) {
				ready = append(ready, name)
			}
		}
		return len(ready) > 0, strings.Join(ready, "、")
	}
}

// HasAuthorizedKey reports whether the file holds at least one key line.
func HasAuthorizedKey(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, f := range strings.Fields(line) {
			if strings.HasPrefix(f, "ssh-") || strings.HasPrefix(f, "ecdsa-") || strings.HasPrefix(f, "sk-") {
				return true
			}
		}
	}
	return false
}

// ShadowGID resolves the distribution's shadow group.
func ShadowGID() int {
	g, err := user.LookupGroup("shadow")
	if err != nil {
		return -1
	}
	id, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1
	}
	return id
}

// ParseAptSimulate extracts package names from `apt-get -s upgrade` output.
func ParseAptSimulate(out []byte) []string {
	var packages []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 1 && !seen[fields[1]] {
			seen[fields[1]] = true
			packages = append(packages, fields[1])
		}
	}
	return packages
}
