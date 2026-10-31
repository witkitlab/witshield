package checkcli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/domain"
)

func TestCatalogCoversEveryScannerTitle(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "scanner", "scanner.go"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?:finding\(domain\.Severity\w+, "\w+", |title: )"([^"]+)"`)
	matches := re.FindAllStringSubmatch(string(src), -1)
	if len(matches) < 10 {
		t.Fatalf("expected to find scanner titles, got %d", len(matches))
	}
	for _, m := range matches {
		if _, ok := catalog[m[1]]; !ok {
			t.Errorf("no Chinese advice for scanner finding %q", m[1])
		}
	}
}

func TestAdviceFallsBackToScannerText(t *testing.T) {
	a := AdviceFor(domain.Finding{Title: "Something new", Description: "desc", Remediation: "do it"})
	if a.Title != "Something new" || a.Why != "desc" || len(a.Manual) != 1 || a.Fix != FixNone {
		t.Fatalf("unexpected fallback: %#v", a)
	}
}

func report(score int, findings ...domain.Finding) domain.Report {
	return domain.Report{Score: score, Summary: []byte(`{"checks":8,"completedChecks":8,"coveragePercent":100,"findingCount":1,"checkErrors":[],"mode":"native"}`), Findings: findings}
}

var sshFinding = domain.Finding{Severity: domain.SeverityHigh, Category: "ssh", Title: "SSH password authentication is enabled", Evidence: "PasswordAuthentication yes"}
var portFinding = domain.Finding{Severity: domain.SeverityInfo, Category: "network", Title: "Services listen on non-loopback interfaces"}

func TestRenderShowsScoreTopIssuesAndFixHint(t *testing.T) {
	var b bytes.Buffer
	Render(&b, report(64, portFinding, sshFinding), Host{Name: "vps", OS: "Ubuntu", IsRoot: true}, false)
	out := b.String()
	for _, want := range []string{"64 / 100", "及格", "最该先处理的 2 件事", "1. [高危] SSH 允许密码登录  可一键修复", "2. [提示] 有服务对外开放端口", "sudo witshield check --fix", "分享：我的服务器安全分 64/100"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("color codes written with color disabled")
	}
}

func TestRenderWarnsAboutPartialCoverageWithoutRoot(t *testing.T) {
	r := report(50)
	r.Summary = []byte(`{"checks":8,"completedChecks":6,"coveragePercent":75,"checkErrors":["firewall: denied"]}`)
	var b bytes.Buffer
	Render(&b, r, Host{}, false)
	if !strings.Contains(b.String(), "没有用 sudo 运行") || !strings.Contains(b.String(), "完成检查 6/8 项") {
		t.Fatalf("partial coverage not explained:\n%s", b.String())
	}
}

func TestJSONIncludesChineseAdvice(t *testing.T) {
	j := ToJSON(report(80, sshFinding))
	if j.Grade != "良好" || len(j.Findings) != 1 || j.Findings[0].TitleZH != "SSH 允许密码登录" || !j.Findings[0].Fixable {
		t.Fatalf("unexpected JSON report: %#v", j)
	}
}

func TestGrade(t *testing.T) {
	for score, want := range map[int]string{100: "优秀", 90: "优秀", 89: "良好", 75: "良好", 60: "及格", 59: "危险", 0: "危险"} {
		if got := Grade(score); got != want {
			t.Errorf("Grade(%d) = %s, want %s", score, got, want)
		}
	}
}

type fakeEngine struct {
	ops       []action.Operation
	confirmBy *time.Time
	fail      action.Operation
}

func (f *fakeEngine) Run(_ context.Context, r action.Request) action.Receipt {
	f.ops = append(f.ops, r.Operation)
	rec := action.Receipt{Operation: r.Operation, Success: r.Operation != f.fail}
	if r.Operation == action.OperationExecute && rec.Success {
		rec.Steps = []action.AuditStep{{Operation: action.OperationApply, Success: true}, {Operation: action.OperationVerify, Success: true}}
		rec.ConfirmBy = f.confirmBy
		rec.State = []byte(`"sealed"`)
	}
	if !rec.Success {
		rec.Error = "boom"
	}
	return rec
}

func newFixer(e *fakeEngine, input string, keys bool) (*Fixer, *bytes.Buffer) {
	var out bytes.Buffer
	return &Fixer{
		Engine: e, In: NewLineReader(strings.NewReader(input)), Out: &out,
		SSHConfirmWindow: 60 * time.Second,
		PendingUpdates:   func(context.Context) ([]string, error) { return []string{"openssl", "curl"}, nil },
		ShadowGID:        func() int { return 42 },
		KeyLoginReady:    func() (bool, string) { return keys, "ubuntu" },
		Now:              time.Now,
	}, &out
}

func ops(o ...action.Operation) string {
	var s []string
	for _, x := range o {
		s = append(s, string(x))
	}
	return strings.Join(s, ",")
}

func TestSSHFixConfirmed(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	e := &fakeEngine{confirmBy: &deadline}
	x, out := newFixer(e, "y\nyes\n", true)
	x.FixAll(context.Background(), []domain.Finding{sshFinding})
	if got := ops(e.ops...); got != "precheck,preview,execute,confirm" {
		t.Fatalf("operations = %s\n%s", got, out)
	}
	if !strings.Contains(out.String(), "只允许密钥登录") {
		t.Fatalf("missing success text:\n%s", out)
	}
}

func TestSSHFixRolledBackWithoutConfirmation(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	e := &fakeEngine{confirmBy: &deadline}
	x, out := newFixer(e, "y\nno\n", true)
	x.FixAll(context.Background(), []domain.Finding{sshFinding})
	if got := ops(e.ops...); got != "precheck,preview,execute,rollback" {
		t.Fatalf("operations = %s\n%s", got, out)
	}
	if !strings.Contains(out.String(), "已恢复原来的 SSH 配置") {
		t.Fatalf("missing rollback text:\n%s", out)
	}
}

func TestSSHFixRolledBackOnEOF(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	e := &fakeEngine{confirmBy: &deadline}
	x, _ := newFixer(e, "y\n", true)
	x.FixAll(context.Background(), []domain.Finding{sshFinding})
	if got := ops(e.ops...); got != "precheck,preview,execute,rollback" {
		t.Fatalf("operations = %s", got)
	}
}

func TestSSHFixSkippedWithoutKeys(t *testing.T) {
	e := &fakeEngine{}
	x, out := newFixer(e, "y\nyes\n", false)
	x.FixAll(context.Background(), []domain.Finding{sshFinding})
	if len(e.ops) != 0 || !strings.Contains(out.String(), "关在服务器外面") {
		t.Fatalf("expected a lockout guard, ops=%v\n%s", e.ops, out)
	}
}

func TestDecliningChangesNothing(t *testing.T) {
	e := &fakeEngine{}
	x, _ := newFixer(e, "n\n", true)
	x.FixAll(context.Background(), []domain.Finding{{Severity: domain.SeverityHigh, Title: "/etc/shadow is accessible to other users"}})
	if got := ops(e.ops...); got != "precheck,preview" {
		t.Fatalf("operations = %s", got)
	}
}

func TestFailedPrecheckStopsBeforeAsking(t *testing.T) {
	e := &fakeEngine{fail: action.OperationPrecheck}
	x, out := newFixer(e, "y\n", true)
	x.FixAll(context.Background(), []domain.Finding{{Severity: domain.SeverityMedium, Title: "System packages have pending updates"}})
	if got := ops(e.ops...); got != "precheck" || !strings.Contains(out.String(), "不会做任何修改") {
		t.Fatalf("operations = %s\n%s", got, out)
	}
}

func TestHasAuthorizedKey(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if HasAuthorizedKey(write("empty", "# nothing here\n\n")) {
		t.Error("comment-only file counted as a key")
	}
	if !HasAuthorizedKey(write("key", "ssh-ed25519 AAAAC3Nza me@laptop\n")) {
		t.Error("ed25519 key not found")
	}
	if !HasAuthorizedKey(write("opts", `from="10.0.0.1" ecdsa-sha2-nistp256 AAAA x`+"\n")) {
		t.Error("key with options not found")
	}
	if HasAuthorizedKey(filepath.Join(dir, "missing")) {
		t.Error("missing file counted as a key")
	}
}

func TestParseAptSimulate(t *testing.T) {
	out := []byte("Reading package lists...\nInst openssl [3.0.2] (3.0.13 Ubuntu:22.04/jammy-security [amd64])\nConf openssl\nInst curl [7.81] (7.81.1 x)\nInst openssl [dup]\n")
	got := ParseAptSimulate(out)
	if strings.Join(got, ",") != "openssl,curl" {
		t.Fatalf("got %v", got)
	}
}

func TestAIPromptCarriesOnlySummaries(t *testing.T) {
	m := AIPrompt(report(70, sshFinding))
	if len(m) != 2 || !strings.Contains(m[1].Content, "SSH 允许密码登录") || !strings.Contains(m[1].Content, "70/100") {
		t.Fatalf("unexpected prompt: %#v", m)
	}
}
