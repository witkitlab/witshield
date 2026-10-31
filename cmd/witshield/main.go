// Command witshield is the one-shot health check: `witshield check`.
// It needs no Controller, no Web console and no registration.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/checkcli"
)

var version = "dev"
var commit = "unknown"
var buildDate = "unknown"

const help = `妙计巡御 witshield %s

  witshield check          体检这台服务器（建议 sudo 运行，结果更完整）
  sudo witshield check --fix   体检后逐项修复，每一步先预览、确认后才改；SSH 和文件权限修复失败时尝试恢复
  witshield check --help   查看全部选项
  witshield version        查看版本

文档：https://github.com/witkitlab/witshield
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, checkcli.RecoverInterruptedSSH))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, recoverSSH func(context.Context, io.Writer) error) int {
	if err := recoverSSH(ctx, stderr); err != nil {
		fmt.Fprintf(stderr, "未能恢复上次中断的 SSH 修改：%v。请检查 /var/lib/witshield-cli/ssh-rollbacks，恢复前不会继续。\n", err)
		return 2
	}
	if len(args) == 0 {
		args = []string{"check"}
	}
	switch args[0] {
	case "apt-plan-guard":
		// Invoked by APT during `check --fix` package upgrades, never by users.
		if len(args) != 2 || os.Geteuid() != 0 {
			fmt.Fprintln(stderr, "witshield apt plan guard requires one transaction directory and root")
			return 2
		}
		if err := action.RunPackagePlanGuard(stdin, args[1], checkcli.PackagePlanBase); err != nil {
			fmt.Fprintf(stderr, "witshield rejected the locked APT plan: %v\n", err)
			return 1
		}
	case "check":
		return checkcli.Run(ctx, args[1:], stdin, stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "witshield %s (commit %s, built %s)\n", version, commit, buildDate)
	case "help", "--help", "-h":
		fmt.Fprintf(stdout, help, version)
	default:
		fmt.Fprintf(stderr, "未知命令：%s\n\n", args[0])
		fmt.Fprintf(stderr, help, version)
		return 2
	}
	return 0
}
