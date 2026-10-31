// Command witshield is the one-shot health check: `witshield check`.
// It needs no Controller, no Web console and no registration.
package main

import (
	"context"
	"fmt"
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
  sudo witshield check --fix   体检后逐项修复，每一步先预览、确认后才改、失败自动恢复
  witshield check --help   查看全部选项
  witshield version        查看版本

文档：https://github.com/witkitlab/witshield
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"check"}
	}
	switch args[0] {
	case "apt-plan-guard":
		// Invoked by APT during `check --fix` package upgrades, never by users.
		if len(args) != 2 || os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "witshield apt plan guard requires one transaction directory and root")
			os.Exit(2)
		}
		if err := action.RunPackagePlanGuard(os.Stdin, args[1], checkcli.PackagePlanBase); err != nil {
			fmt.Fprintf(os.Stderr, "witshield rejected the locked APT plan: %v\n", err)
			os.Exit(1)
		}
	case "check":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := checkcli.Run(ctx, args[1:], os.Stdin, os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	case "version", "--version", "-v":
		fmt.Printf("witshield %s (commit %s, built %s)\n", version, commit, buildDate)
	case "help", "--help", "-h":
		fmt.Printf(help, version)
	default:
		fmt.Fprintf(os.Stderr, "未知命令：%s\n\n", args[0])
		fmt.Fprintf(os.Stderr, help, version)
		os.Exit(2)
	}
}
