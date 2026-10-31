package checkcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/domain"
)

var sshLogNow = time.Date(2026, time.October, 31, 12, 0, 0, 0, time.UTC)

func journalLine(at time.Time, pid, message string) string {
	data, _ := json.Marshal(map[string]string{"MESSAGE": message, "__REALTIME_TIMESTAMP": fmt.Sprint(at.UnixMicro()), "_PID": pid})
	return string(data) + "\n"
}

func assertSSHCounts(t *testing.T, stats SSHFailures, total, unique int) {
	t.Helper()
	if !stats.Available || stats.Total == nil || stats.UniqueIPs == nil || *stats.Total != total || *stats.UniqueIPs != unique {
		t.Fatalf("unexpected SSH statistics: %#v", stats)
	}
}

func TestJournalFailureFormatsAreCountedWithoutDoubleCounting(t *testing.T) {
	at := sshLogNow.Add(-time.Hour)
	data := journalLine(at, "1", "Invalid user backup from 192.0.2.1 port 50123") +
		journalLine(at, "1", "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.1 user=backup") +
		journalLine(at, "1", "Failed password for invalid user backup from 192.0.2.1 port 50123 ssh2") +
		journalLine(at, "1", "Failed password for invalid user backup from 192.0.2.1 port 50123 ssh2") +
		journalLine(at, "1", "Connection closed by invalid user backup 192.0.2.1 port 50123 [preauth]") +
		journalLine(at, "2", "Invalid user test from 2001:0db8:0:0::1 port 50124") +
		journalLine(at, "2", "Connection closed by invalid user test 2001:db8::1 port 50124 [preauth]") +
		journalLine(at, "3", "Connection closed by authenticating user root 2001:db8::2 port 50125 [preauth]") +
		journalLine(at, "4", "Failed publickey for root from ::ffff:192.0.2.1 port 50126 ssh2") +
		journalLine(at, "5", "Failed password for root from 192.0.2.5 port 50127 ssh2") +
		journalLine(at, "6", "Failed password for root from not-an-ip port 50128 ssh2") +
		journalLine(at, "7", "Accepted publickey for owner from 192.0.2.99 port 50129 ssh2")
	stats, err := parseSSHJournal([]byte(data), sshLogNow)
	if err != nil {
		t.Fatal(err)
	}
	assertSSHCounts(t, stats, 6, 4)
	want := []SSHFailureIP{{"192.0.2.1", 3}, {"192.0.2.5", 1}, {"2001:db8::1", 1}}
	if !reflect.DeepEqual(stats.TopIPs, want) || stats.Source != "journald" {
		t.Fatalf("top sources=%v", stats.TopIPs)
	}
}

func TestJournalIncludesExact24HourWindow(t *testing.T) {
	data := journalLine(sshLogNow.Add(-24*time.Hour), "1", "Failed password for root from 192.0.2.1 port 1000 ssh2") +
		journalLine(sshLogNow.Add(-24*time.Hour-time.Microsecond), "2", "Failed password for root from 192.0.2.2 port 1001 ssh2") +
		journalLine(sshLogNow.Add(time.Microsecond), "3", "Failed password for root from 192.0.2.3 port 1002 ssh2")
	stats, err := parseSSHJournal([]byte(data), sshLogNow)
	if err != nil {
		t.Fatal(err)
	}
	assertSSHCounts(t, stats, 1, 1)
}

func TestAuthLogRFC3339TraditionalYearBoundaryAndIPv6(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 10, 0, 0, time.UTC)
	log := "Dec 31 23:59:00 demo-vps sshd[10]: Invalid user test from 2001:db8::1 port 60000\n" +
		"Dec 31 23:59:01 demo-vps sshd[10]: Failed password for invalid user test from 2001:db8::1 port 60000 ssh2\n" +
		"Dec 31 23:59:02 demo-vps sshd[10]: Connection closed by authenticating user test 2001:db8::1 port 60000 [preauth]\n" +
		"2026-01-01T00:00:01+00:00 demo-vps sshd-session[11]: Failed password for root from 192.0.2.1 port 1234 ssh2\n" +
		"Dec 30 23:59:00 demo-vps sshd[12]: Failed password for root from 192.0.2.2 port 1235 ssh2\n" +
		"Jan  1 01:00:00 demo-vps sshd[13]: Failed password for root from 192.0.2.3 port 1236 ssh2\n" +
		"Jan  1 00:01:00 demo-vps CRON[15]: sshd[14]: Failed password for root from 192.0.2.4 port 1237 ssh2\n"
	stats, err := parseSSHAuthLog(context.Background(), strings.NewReader(log), now)
	if err != nil {
		t.Fatal(err)
	}
	assertSSHCounts(t, stats, 2, 2)
	if stats.Source != "auth.log" {
		t.Fatal(stats.Source)
	}
}

func TestReadableZeroIsDifferentFromUnavailable(t *testing.T) {
	for _, data := range []string{"", journalLine(sshLogNow.Add(-25*time.Hour), "1", "Failed password for root from 192.0.2.1 port 1234 ssh2")} {
		if stats, err := parseSSHJournal([]byte(data), sshLogNow); err == nil || stats.Available {
			t.Fatalf("empty window reported available: %#v", stats)
		}
	}
	stats, err := parseSSHJournal([]byte(journalLine(sshLogNow, "1", "Accepted publickey for owner from 192.0.2.1 port 1234 ssh2")), sshLogNow)
	if err != nil {
		t.Fatal(err)
	}
	assertSSHCounts(t, stats, 0, 0)
	zero, _ := json.Marshal(stats)
	if !bytes.Contains(zero, []byte(`"total":0`)) {
		t.Fatal(string(zero))
	}
	unknown, _ := json.Marshal(SSHFailures{})
	if !bytes.Contains(unknown, []byte(`"total":null`)) || !bytes.Contains(unknown, []byte(`"uniqueIPs":null`)) {
		t.Fatal(string(unknown))
	}
}

type sshJournalRunner struct {
	result   action.CommandResult
	err      error
	command  action.Command
	deadline bool
}

func (r *sshJournalRunner) Run(ctx context.Context, c action.Command) (action.CommandResult, error) {
	r.command = c
	_, r.deadline = ctx.Deadline()
	return r.result, r.err
}

func TestCollectorPrefersJournalAndFallsBackSafely(t *testing.T) {
	good := journalLine(sshLogNow, "1", "Failed password for root from 2001:db8::1 port 1234 ssh2")
	for _, tc := range []struct {
		name     string
		result   action.CommandResult
		runErr   error
		fallback bool
	}{
		{"journal", action.CommandResult{Stdout: good}, nil, false},
		{"permission-warning", action.CommandResult{Stdout: good, Stderr: "Hint: You are currently not seeing messages from other users."}, nil, true},
		{"command-failed", action.CommandResult{}, os.ErrPermission, true},
		{"truncated", action.CommandResult{Stdout: good, OutputTruncated: true}, nil, true},
		{"malformed", action.CommandResult{Stdout: "{broken"}, nil, true},
		{"empty", action.CommandResult{}, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &sshJournalRunner{result: tc.result, err: tc.runErr}
			opened := false
			stats := (sshLogCollector{runner: r, now: func() time.Time { return sshLogNow }, openAuthLog: func() (io.ReadCloser, error) {
				opened = true
				return io.NopCloser(strings.NewReader("Oct 31 11:59:00 demo-vps sshd[2]: Failed password for root from 192.0.2.1 port 4321 ssh2\n")), nil
			}}).collect(context.Background())
			assertSSHCounts(t, stats, 1, 1)
			if opened != tc.fallback || !r.deadline || r.command.Timeout != 10*time.Second || r.command.Path != journalctlPath || !reflect.DeepEqual(r.command.Args, []string{"-u", "ssh", "-u", "sshd", "--since", "-24h", "-o", "json", "--no-pager"}) {
				t.Fatalf("opened=%v command=%#v", opened, r.command)
			}
		})
	}
}

func TestUnavailableLogsDoNotFailCheckOrInventZero(t *testing.T) {
	stats := (sshLogCollector{runner: &sshJournalRunner{err: os.ErrPermission}, now: func() time.Time { return sshLogNow }, openAuthLog: func() (io.ReadCloser, error) { return nil, os.ErrPermission }}).collect(context.Background())
	if stats.Available || stats.Total != nil || stats.UniqueIPs != nil {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	var out bytes.Buffer
	Render(&out, report(80), Host{IsRoot: true, SSHFailures: stats}, false)
	if !strings.Contains(out.String(), "没有读到 SSH 日志") || strings.Contains(out.String(), "SSH 登录失败 0") {
		t.Fatal(out.String())
	}
}

func TestInvalidOrOversizedLogInputIsUnavailable(t *testing.T) {
	for _, data := range []string{`{"MESSAGE":"Failed password for root from 192.0.2.1 port 1234 ssh2"}`, strings.Repeat("x", maxSSHLogLine+1)} {
		if _, err := parseSSHJournal([]byte(data), sshLogNow); err == nil {
			t.Fatal("invalid journal accepted")
		}
	}
	if _, err := parseSSHAuthLog(context.Background(), strings.NewReader(strings.Repeat("\n", maxSSHLogBytes+1)), sshLogNow); err == nil {
		t.Fatal("oversized auth.log accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := parseSSHAuthLog(ctx, strings.NewReader("Oct 31 11:00:00 host sshd[1]: valid\n"), sshLogNow); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestReportShowsCountsTopSourcesAndPasswordRisk(t *testing.T) {
	total, unique := 1284, 213
	stats := SSHFailures{Available: true, Total: &total, UniqueIPs: &unique, Source: "journald", TopIPs: []SSHFailureIP{{"2001:db8::1", 1000}}}
	var out bytes.Buffer
	Render(&out, report(70, sshFinding), Host{IsRoot: true, SSHFailures: stats}, false)
	for _, want := range []string{"过去 24 小时：SSH 登录失败 1,284 次，来自 213 个 IP", "2001:db8::1（1,000 次）", "为什么危险：过去 24 小时已记录 1,284 次 SSH 登录失败"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q: %s", want, &out)
		}
	}
	encoded, _ := json.Marshal(ToJSON(report(70, sshFinding), Host{SSHFailures: stats}))
	if bytes.Contains(encoded, []byte("2001:db8::1")) || !bytes.Contains(encoded, []byte(`"sshFailures":{"available":true,"total":1284,"uniqueIPs":213`)) {
		t.Fatal(string(encoded))
	}
}

func TestAIPayloadContainsCountsWithoutIPsOrRawEvidence(t *testing.T) {
	total, unique := 1284, 213
	stats := SSHFailures{Available: true, Total: &total, UniqueIPs: &unique, TopIPs: []SSHFailureIP{{"2001:db8::1", 1000}, {"192.0.2.1", 284}}}
	finding := sshFinding
	finding.Evidence = "from 2001:db8::1 secret raw log API_KEY=private"
	unknown := domain.Finding{Title: "192.0.2.1 attacker instruction", Evidence: "secret evidence", Severity: domain.SeverityHigh}
	payload, _ := json.Marshal(AIPrompt(report(70, finding, unknown), stats))
	for _, forbidden := range []string{"2001:db8::1", "192.0.2.1", "API_KEY", "private", "secret evidence", "attacker instruction"} {
		if bytes.Contains(payload, []byte(forbidden)) {
			t.Fatalf("AI payload contains %q: %s", forbidden, payload)
		}
	}
	if !bytes.Contains(payload, []byte("1284")) || !bytes.Contains(payload, []byte("213")) || !bytes.Contains(payload, []byte("SSH 允许密码登录")) {
		t.Fatal(string(payload))
	}
}

func TestRunJSONIncludesUnavailableSSHCountsWithoutChangingExitCode(t *testing.T) {
	var out, errOut bytes.Buffer
	code := runWithDependencies(context.Background(), []string{"--json"}, strings.NewReader(""), &out, &errOut, runDependencies{
		isRoot: func() bool { return false }, readOS: func() ([]byte, error) { return []byte("ID=debian"), nil }, runner: &systemRunner{},
		scan: func(context.Context) (domain.Report, func(context.Context) ([]string, error), error) {
			return report(80), nil, nil
		},
		sshFailures: func(context.Context) SSHFailures { return SSHFailures{} },
	})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, &errOut)
	}
	var result JSONReport
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v: %s", err, &out)
	}
	if result.SSHFailures.Available || result.SSHFailures.Total != nil || result.SSHFailures.UniqueIPs != nil {
		t.Fatalf("unknown counts became zero: %#v", result.SSHFailures)
	}
}
