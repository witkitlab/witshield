package checkcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/witkitlab/witshield/internal/action"
)

const maxRecoveryJournalBytes = 512 << 10

var cliJournalName = regexp.MustCompile(`^ssh-(cli-ssh-[0-9]{1,20})\.json$`)

type recoveryJournal struct {
	ActionID         string          `json:"actionId"`
	ParametersDigest string          `json:"parametersDigest"`
	State            json.RawMessage `json:"state"`
	StateDigest      string          `json:"stateDigest"`
	ConfirmBy        time.Time       `json:"confirmBy"`
}

// RecoverInterruptedSSH runs before every root subcommand, including version.
// The existing typed playbook validates its protected journal again and owns
// all SSH changes. The CLI never interprets snapshot content or executes it.
func RecoverInterruptedSSH(ctx context.Context, out io.Writer) error {
	return recoverSSH(ctx, "", out)
}

func recoverSSH(ctx context.Context, actionID string, out io.Writer) error {
	if os.Geteuid() != 0 {
		if actionID != "" {
			return errors.New("恢复 SSH 修改需要 root 权限")
		}
		return nil
	}
	if _, err := os.Lstat(sshJournalDir); errors.Is(err, os.ErrNotExist) {
		if actionID != "" {
			return errors.New("没有找到受保护的 SSH 恢复日志，无法确认已恢复")
		}
		return nil
	} else if err != nil {
		return err
	}
	if err := privateRecoveryPath(StateDir, true); err != nil {
		return err
	}
	return recoverSSHJournalsForAction(ctx, out, action.NewExecRunner(sshdPath, systemctlPath), action.SSHHardeningConfig{
		SSHDPath: sshdPath, SystemctlPath: systemctlPath, ConfigPath: "/etc/ssh/sshd_config", JournalDir: sshJournalDir,
		DefaultRollbackDelay: 3 * time.Minute,
	}, actionID)
}

func privateRecoveryPath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := privateRecoveryInfo(info, directory); err != nil {
		return fmt.Errorf("%s：%w", path, err)
	}
	return nil
}

func privateRecoveryInfo(info os.FileInfo, directory bool) error {
	owner, ok := info.Sys().(*syscall.Stat_t)
	mode := os.FileMode(0o600)
	validType := info.Mode().IsRegular()
	if directory {
		mode = 0o700
		validType = info.IsDir()
	}
	if !ok || owner.Uid != 0 || !validType || info.Mode().Perm() != mode || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("恢复路径的属主、权限或类型不安全")
	}
	return nil
}

func openRecoveryRoot(dir string) (*os.Root, error) {
	before, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if err := privateRecoveryInfo(before, true); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err == nil {
		err = privateRecoveryInfo(opened, true)
	}
	if err != nil || !os.SameFile(before, opened) {
		_ = root.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("SSH 恢复目录在打开时发生变化")
	}
	return root, nil
}

func readRecoveryJournal(root *os.Root, name string) ([]byte, error) {
	before, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if err := privateRecoveryInfo(before, false); err != nil {
		return nil, err
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := privateRecoveryInfo(opened, false); err != nil {
		return nil, err
	}
	if !os.SameFile(before, opened) {
		return nil, errors.New("SSH 恢复日志在打开时发生变化")
	}
	if opened.Size() < 0 || opened.Size() > maxRecoveryJournalBytes {
		return nil, errors.New("SSH 恢复日志超过大小上限")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxRecoveryJournalBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRecoveryJournalBytes {
		return nil, errors.New("SSH 恢复日志超过大小上限")
	}
	return data, nil
}

func readRecoveryJournals(dir string) ([]recoveryJournal, error) {
	root, err := openRecoveryRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(65)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > 64 {
		return nil, errors.New("SSH 恢复日志过多，请手动检查")
	}
	var journals []recoveryJournal
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "ssh-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		match := cliJournalName.FindStringSubmatch(name)
		if len(match) != 2 {
			return nil, errors.New("SSH 恢复日志名称不属于命令行修复")
		}
		data, err := readRecoveryJournal(root, name)
		if err != nil {
			return nil, err
		}
		var journal recoveryJournal
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&journal); err != nil {
			return nil, errors.New("SSH 恢复日志格式无效")
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, errors.New("SSH 恢复日志包含多余数据")
		}
		if journal.ActionID != match[1] || len(journal.State) == 0 || journal.ConfirmBy.IsZero() {
			return nil, errors.New("SSH 恢复日志身份无效")
		}
		if _, err := recoveryParameters(journal.ParametersDigest); err != nil {
			return nil, err
		}
		journals = append(journals, journal)
	}
	return journals, nil
}

func recoveryParameters(digest string) (json.RawMessage, error) {
	// CLI v0.4 always writes an explicit bounded delay. Zero supports the
	// typed playbook's documented default without widening accepted inputs.
	for seconds := 0; seconds <= 600; seconds++ {
		if seconds > 0 && seconds < 30 {
			continue
		}
		params, _ := json.Marshal(action.SSHPasswordHardeningParams{RollbackAfterSeconds: seconds})
		if action.ParametersDigest(params) == digest {
			return params, nil
		}
	}
	return nil, errors.New("无法重构 SSH 修复参数，已停止；请手动检查恢复日志")
}

func recoverSSHJournals(ctx context.Context, out io.Writer, runner action.Runner, config action.SSHHardeningConfig) error {
	return recoverSSHJournalsForAction(ctx, out, runner, config, "")
}

func recoverSSHJournalsForAction(_ context.Context, out io.Writer, runner action.Runner, config action.SSHHardeningConfig, actionID string) error {
	journals, err := readRecoveryJournals(config.JournalDir)
	if err != nil {
		return err
	}
	if actionID != "" {
		found := false
		for _, journal := range journals {
			if journal.ActionID == actionID {
				found = true
				break
			}
		}
		if !found {
			return errors.New("没有找到本次修改的受保护 SSH 恢复日志，无法确认已恢复")
		}
	}
	if len(journals) == 0 {
		return nil
	}
	// Discovery is part of the safety rollback and must survive Ctrl-C too.
	recoveryCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	service := detectSSHService(recoveryCtx, runner)
	if service == "" {
		return errors.New("未找到 SSH 服务，无法自动恢复；请手动检查 SSH 配置和恢复日志")
	}
	config.Runner, config.ServiceName = runner, service
	playbook, err := action.NewSSHPasswordHardeningPlaybook(config)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "发现上次中断的 SSH 修改，正在恢复原来的 SSH 配置……")
	for _, journal := range journals {
		params, _ := recoveryParameters(journal.ParametersDigest)
		_, err := playbook.Rollback(recoveryCtx, action.Invocation{ActionID: journal.ActionID, Actor: "witshield-cli", Parameters: params, State: journal.State})
		if err != nil {
			// File absence alone cannot prove that the live service was restored.
			return err
		}
	}
	fmt.Fprintln(out, "已恢复原来的 SSH 配置。")
	return nil
}
