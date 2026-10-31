package checkcli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/witkitlab/witshield/internal/domain"
)

// Summary mirrors the JSON the scanner stores in Report.Summary.
type Summary struct {
	Checks          int      `json:"checks"`
	CompletedChecks int      `json:"completedChecks"`
	CoveragePercent int      `json:"coveragePercent"`
	FindingCount    int      `json:"findingCount"`
	CheckErrors     []string `json:"checkErrors"`
	Mode            string   `json:"mode"`
}

func parseSummary(r domain.Report) Summary {
	var s Summary
	_ = json.Unmarshal(r.Summary, &s)
	return s
}

// Host describes the machine in the report header.
type Host struct {
	Name           string
	OS             string
	IsRoot         bool
	SSHUnavailable bool
	UntestedOS     bool
}

type style struct{ color bool }

func (s style) wrap(code, text string) string {
	if !s.color {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}
func (s style) bold(t string) string { return s.wrap("1", t) }
func (s style) dim(t string) string  { return s.wrap("2", t) }
func (s style) sev(sev domain.Severity, t string) string {
	switch sev {
	case domain.SeverityCritical:
		return s.wrap("1;31", t)
	case domain.SeverityHigh:
		return s.wrap("31", t)
	case domain.SeverityMedium:
		return s.wrap("33", t)
	case domain.SeverityLow:
		return s.wrap("36", t)
	}
	return s.dim(t)
}
func (s style) score(score int, t string) string {
	switch {
	case score >= 90:
		return s.wrap("1;32", t)
	case score >= 75:
		return s.wrap("1;36", t)
	case score >= 60:
		return s.wrap("1;33", t)
	}
	return s.wrap("1;31", t)
}

// Sorted orders findings by severity, fixable ones first within a severity.
func Sorted(findings []domain.Finding) []domain.Finding {
	out := append([]domain.Finding(nil), findings...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := severityRank[out[i].Severity], severityRank[out[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return AdviceFor(out[i]).Fix != FixNone && AdviceFor(out[j]).Fix == FixNone
	})
	return out
}

// Render writes the human report.
func Render(w io.Writer, r domain.Report, h Host, color bool) {
	s := style{color}
	sum := parseSummary(r)
	findings := Sorted(r.Findings)
	counts := map[domain.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	fmt.Fprintf(w, "\n%s  %s\n", s.bold("妙计巡御 · 服务器体检"), s.dim(strings.TrimSpace(h.Name+"  "+h.OS)))
	fmt.Fprintln(w, s.dim(strings.Repeat("─", 48)))
	if h.UntestedOS {
		fmt.Fprintln(w, "  目前只对 Ubuntu/Debian 做过完整测试。")
	}
	fmt.Fprintf(w, "  安全分  %s  %s", s.score(r.Score, fmt.Sprintf("%d / 100", r.Score)), s.score(r.Score, Grade(r.Score)))
	if sum.Checks > 0 {
		fmt.Fprintf(w, "    %s", s.dim(fmt.Sprintf("完成检查 %d/%d 项", sum.CompletedChecks, sum.Checks)))
	}
	fmt.Fprintln(w)
	if len(findings) == 0 {
		fmt.Fprintln(w, "  没有发现问题。")
	} else {
		fmt.Fprintf(w, "  发现 %d 个问题：严重 %d · 高危 %d · 中危 %d · 低危 %d · 提示 %d\n", len(findings),
			counts[domain.SeverityCritical], counts[domain.SeverityHigh], counts[domain.SeverityMedium], counts[domain.SeverityLow], counts[domain.SeverityInfo])
	}
	if len(sum.CheckErrors) > 0 {
		fmt.Fprintln(w)
		if !h.IsRoot {
			fmt.Fprintln(w, s.sev(domain.SeverityMedium, "  ！没有用 sudo 运行，部分检查读不到数据，分数只代表已完成的部分。"))
			fmt.Fprintln(w, s.dim("    用 sudo witshield check 可以检查完整。"))
		} else {
			fmt.Fprintln(w, s.sev(domain.SeverityMedium, "  ！有检查没能完成，分数只代表已完成的部分："))
		}
		for _, e := range sum.CheckErrors {
			fmt.Fprintln(w, s.dim("    · "+e))
		}
	}

	top := findings
	if len(top) > 3 {
		top = top[:3]
	}
	if len(top) > 0 {
		fmt.Fprintf(w, "\n%s\n", s.bold("最该先处理的 "+fmt.Sprint(len(top))+" 件事"))
		for i, f := range top {
			renderFinding(w, s, i+1, f, true, h)
		}
	}
	if len(findings) > 3 {
		fmt.Fprintf(w, "\n%s\n", s.bold("其余问题"))
		for i, f := range findings[3:] {
			renderFinding(w, s, i+4, f, false, h)
		}
	}

	fixable := 0
	for _, f := range findings {
		if reportAdvice(f, h.SSHUnavailable).Fix != FixNone {
			fixable++
		}
	}
	fmt.Fprintf(w, "\n%s\n", s.bold("下一步"))
	if fixable > 0 {
		fmt.Fprintf(w, "  %s   逐项修复 %d 个可一键修复的问题：先预览、确认后修改并验证；SSH 和文件权限支持恢复，软件包升级前建议做快照\n", s.bold("sudo witshield check --fix"), fixable)
	}
	fmt.Fprintf(w, "  %s        用你自己的大模型 API（DeepSeek、通义、豆包等）解读这份报告\n", s.bold("witshield check --ai"))
	fmt.Fprintf(w, "  %s      输出 JSON，方便接入脚本或其他 AI 工具\n", s.bold("witshield check --json"))
	fmt.Fprintf(w, "\n%s\n\n", s.dim(fmt.Sprintf("分享：我的服务器安全分 %d/100（%s），用妙计巡御体检 → github.com/witkitlab/witshield", r.Score, Grade(r.Score))))
}

func renderFinding(w io.Writer, s style, n int, f domain.Finding, detailed bool, h Host) {
	a := reportAdvice(f, h.SSHUnavailable)
	tag := s.sev(f.Severity, "["+severityLabel[f.Severity]+"]")
	fix := ""
	if a.Fix != FixNone {
		fix = "  " + s.wrap("32", "可一键修复")
	}
	fmt.Fprintf(w, "  %d. %s %s%s\n", n, tag, s.bold(a.Title), fix)
	if h.SSHUnavailable && AdviceFor(f).Fix == FixSSHPassword {
		fmt.Fprintln(w, "     本机无法自动修复，请按命令手动处理。")
	}
	if !detailed {
		return
	}
	fmt.Fprintf(w, "     为什么危险：%s\n", a.Why)
	if f.Evidence != "" {
		fmt.Fprintf(w, "     %s\n", s.dim("证据："+truncate(f.Evidence, 120)))
	}
	if len(a.Manual) > 0 {
		fmt.Fprintln(w, "     怎么修：")
		for _, m := range a.Manual {
			fmt.Fprintf(w, "       %s\n", m)
		}
	}
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// JSONReport is the --json shape: the scanner report plus the Chinese advice.
type JSONReport struct {
	Score    int           `json:"score"`
	Grade    string        `json:"grade"`
	Summary  Summary       `json:"summary"`
	Findings []JSONFinding `json:"findings"`
	Warnings []string      `json:"warnings,omitempty"`
}

type JSONFinding struct {
	Severity domain.Severity `json:"severity"`
	Category string          `json:"category"`
	Title    string          `json:"title"`
	TitleZH  string          `json:"titleZh"`
	Why      string          `json:"why"`
	Evidence string          `json:"evidence,omitempty"`
	Manual   []string        `json:"manual,omitempty"`
	Fixable  bool            `json:"fixable"`
}

func ToJSON(r domain.Report, hosts ...Host) JSONReport {
	var h Host
	if len(hosts) > 0 {
		h = hosts[0]
	}
	out := JSONReport{Score: r.Score, Grade: Grade(r.Score), Summary: parseSummary(r), Findings: []JSONFinding{}}
	if h.UntestedOS {
		out.Warnings = append(out.Warnings, "目前只对 Ubuntu/Debian 做过完整测试")
	}
	for _, f := range Sorted(r.Findings) {
		a := reportAdvice(f, h.SSHUnavailable)
		out.Findings = append(out.Findings, JSONFinding{Severity: f.Severity, Category: f.Category, Title: f.Title, TitleZH: a.Title, Why: a.Why, Evidence: f.Evidence, Manual: a.Manual, Fixable: a.Fix != FixNone})
	}
	return out
}

func reportAdvice(f domain.Finding, sshUnavailable bool) Advice {
	a := AdviceFor(f)
	if sshUnavailable && a.Fix == FixSSHPassword {
		a.Fix = FixNone
	}
	return a
}
