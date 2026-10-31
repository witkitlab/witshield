package checkcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	if os.Geteuid() != 0 {
		return nil
	}
	if _, err := os.Lstat(sshJournalDir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := privateRecoveryPath(StateDir, true); err != nil {
		return err
	}
	return recoverSSHJournals(ctx, out, action.NewExecRunner(sshdPath, systemctlPath), action.SSHHardeningConfig{
		SSHDPath: sshdPath, SystemctlPath: systemctlPath, ConfigPath: "/etc/ssh/sshd_config", JournalDir: sshJournalDir,
		DefaultRollbackDelay: 3 * time.Minute,
	})
}

func privateRecoveryPath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	mode := os.FileMode(0o600)
	validType := info.Mode().IsRegular()
	if directory {
		mode = 0o700
		validType = info.IsDir()
	}
	if !ok || owner.Uid != 0 || !validType || info.Mode().Perm() != mode || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("恢复路径的属主、权限或类型不安全：%s", path)
	}
	return nil
}

func readRecoveryJournals(dir string) ([]recoveryJournal, error) {
	if err := privateRecoveryPath(dir, true); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
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
		path := filepath.Join(dir, name)
		if err := privateRecoveryPath(path, false); err != nil {
			return nil, err
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, maxRecoveryJournalBytes+1))
		closeErr := f.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(data) > maxRecoveryJournalBytes {
			return nil, errors.New("SSH 恢复日志超过大小上限")
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
	journals, err := readRecoveryJournals(config.JournalDir)
	if err != nil || len(journals) == 0 {
		return err
	}
	service := detectSSHService(ctx, runner)
	if service == "" {
		return errors.New("未找到 SSH 服务，无法自动恢复；请手动检查 SSH 配置和恢复日志")
	}
	config.Runner, config.ServiceName = runner, service
	playbook, err := action.NewSSHPasswordHardeningPlaybook(config)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "发现上次中断的 SSH 修改，正在恢复原来的 SSH 配置……")
	// Recovery must finish even when this invocation receives Ctrl-C.
	recoveryCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for _, journal := range journals {
		params, _ := recoveryParameters(journal.ParametersDigest)
		_, err := playbook.Rollback(recoveryCtx, action.Invocation{ActionID: journal.ActionID, Actor: "witshield-cli", Parameters: params, State: journal.State})
		if err != nil {
			// An already-expired timer may have completed the same rollback.
			if _, statErr := os.Lstat(filepath.Join(config.JournalDir, "ssh-"+journal.ActionID+".json")); !errors.Is(statErr, os.ErrNotExist) {
				return err
			}
		}
	}
	fmt.Fprintln(out, "已恢复原来的 SSH 配置。")
	return nil
}
