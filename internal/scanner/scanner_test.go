package scanner

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

type fakeInfo struct{ mode fs.FileMode }

func (fakeInfo) Name() string        { return "x" }
func (fakeInfo) Size() int64         { return 0 }
func (f fakeInfo) Mode() fs.FileMode { return f.mode }
func (fakeInfo) ModTime() time.Time  { return time.Time{} }
func (fakeInfo) IsDir() bool         { return false }
func (fakeInfo) Sys() any            { return nil }

type fakeHost struct {
	files  map[string][]byte
	modes  map[string]fs.FileMode
	probes map[Probe][]byte
}

func (f fakeHost) ReadFile(p string) ([]byte, error) {
	b, ok := f.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return b, nil
}
func (f fakeHost) Stat(p string) (fs.FileInfo, error) {
	m, ok := f.modes[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return fakeInfo{m}, nil
}
func (f fakeHost) Probe(_ context.Context, p Probe) ([]byte, error) {
	b, ok := f.probes[p]
	if !ok {
		return nil, errors.New("missing")
	}
	return b, nil
}
func TestSSHCheck(t *testing.T) {
	h := fakeHost{files: map[string][]byte{"/etc/ssh/sshd_config": []byte("# PasswordAuthentication no\nPasswordAuthentication yes\nPermitRootLogin no\n")}}
	got, err := checkSSH(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Severity != "high" {
		t.Fatalf("got %#v", got)
	}
}
func TestPrivilegedAndPortsChecks(t *testing.T) {
	h := fakeHost{files: map[string][]byte{"/etc/passwd": []byte("root:x:0:0::/root:/bin/bash\nevil:x:0:0::/tmp:/bin/sh\n"), "/proc/net/tcp": []byte("sl local_address rem_address st\n 0: 00000000:1F90 00000000:0000 0A\n")}}
	a, err := checkPasswd(context.Background(), h)
	if err != nil || len(a) != 1 || a[0].Severity != "critical" {
		t.Fatalf("%v %#v", err, a)
	}
	b, err := checkPorts(context.Background(), h)
	if err != nil || len(b) != 1 || b[0].Evidence != "Non-loopback TCP ports: 8080" {
		t.Fatalf("%v %#v", err, b)
	}
}
func TestShadowPermissions(t *testing.T) {
	h := fakeHost{modes: map[string]fs.FileMode{"/etc/shadow": 0o644}}
	got, err := checkShadow(context.Background(), h)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %#v", err, got)
	}
}
func TestScannerScoreAndFingerprint(t *testing.T) {
	s := New(CheckFunc{"one", func(context.Context, Host) ([]domain.Finding, error) {
		return []domain.Finding{finding(domain.SeverityHigh, "x", "bad", "d", "e", "r")}, nil
	}})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	r, err := s.Scan(context.Background(), "dev")
	if err != nil {
		t.Fatal(err)
	}
	if r.Score != 82 || len(r.Findings) != 1 || len(r.Findings[0].Fingerprint) != 64 {
		t.Fatalf("%#v", r)
	}
}
func TestPortsIgnoreLoopback(t *testing.T) {
	h := fakeHost{files: map[string][]byte{"/proc/net/tcp": []byte("sl local_address rem_address st\n 0: 0100007F:1F90 00000000:0000 0A\n")}}
	got, err := checkPorts(context.Background(), h)
	if err != nil || len(got) != 0 {
		t.Fatalf("%v %#v", err, got)
	}
}
func TestSSHIncludeWithoutEffectiveConfigIsUncertain(t *testing.T) {
	h := fakeHost{files: map[string][]byte{"/etc/ssh/sshd_config": []byte("Include /etc/ssh/sshd_config.d/*.conf\n")}}
	if _, err := checkSSH(context.Background(), h); err == nil {
		t.Fatal("expected uncertainty error")
	}
}
func TestSystemHostRootAndNoEscape(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := NewSystemHost(root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.ReadFile("/etc/passwd")
	if err != nil || string(b) != "inside" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err = h.ReadFile("../../etc/passwd"); err == nil {
		t.Fatal("relative escape accepted")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err = os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(root, "etc", "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err = h.ReadFile("/etc/escape"); err == nil {
		t.Fatal("symlink escape accepted")
	}
}

func TestObserverUnknownChecksReduceCoverage(t *testing.T) {
	root := t.TempDir()
	host, err := NewSystemHost(root)
	if err != nil {
		t.Fatal(err)
	}
	s := NewWithHost(host, true,
		CheckFunc{"shadow", checkShadow},
		CheckFunc{"updates", checkUpdates},
		CheckFunc{"docker", checkDockerSocket},
	)
	report, err := s.Scan(context.Background(), "device")
	if err != nil {
		t.Fatal(err)
	}
	if report.Score != 0 || !strings.Contains(string(report.Summary), `"coveragePercent":0`) || !strings.Contains(string(report.Summary), "observer mode") {
		t.Fatalf("observer uncertainty was hidden: score=%d summary=%s", report.Score, report.Summary)
	}
}

func TestObserverPartialPortsPreserveEvidenceAndReduceCoverage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "proc", "1", "net")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "tcp"), []byte("sl local_address rem_address st\n 0: 00000000:1F90 00000000:0000 0A\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	host, err := NewSystemHost(root)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := checkPorts(context.Background(), host)
	if err == nil || len(findings) != 1 || !strings.Contains(err.Error(), "/proc/1/net/tcp6") {
		t.Fatalf("partial IPv4 evidence must not imply full TCP coverage: findings=%#v err=%v", findings, err)
	}
	s := NewWithHost(host, true, CheckFunc{"ports", checkPorts})
	report, err := s.Scan(context.Background(), "device")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].DeviceID != "device" || len(report.Findings[0].Fingerprint) != 64 || report.Score != 0 || !strings.Contains(string(report.Summary), `"coveragePercent":0`) || !strings.Contains(string(report.Summary), "tcp6") {
		t.Fatalf("partial evidence or uncertainty was hidden: score=%d findings=%#v summary=%s", report.Score, report.Findings, report.Summary)
	}
}

func TestFirewallProbeFailureIsUnavailableAndReducesCoverage(t *testing.T) {
	host := fakeHost{}
	if findings, err := checkFirewall(context.Background(), host); err == nil || len(findings) != 0 {
		t.Fatalf("permission/probe failure must be unavailable, findings=%#v err=%v", findings, err)
	}
	s := New(CheckFunc{"firewall", checkFirewall})
	s.host = host
	report, err := s.Scan(context.Background(), "device")
	if err != nil {
		t.Fatal(err)
	}
	if report.Score != 0 || len(report.Findings) != 0 || !strings.Contains(string(report.Summary), `"coveragePercent":0`) || !strings.Contains(string(report.Summary), `"firewall:`) {
		t.Fatalf("firewall uncertainty was counted as completed: score=%d findings=%#v summary=%s", report.Score, report.Findings, report.Summary)
	}
}

func TestFirewallProbeSuccessStillReportsInactiveState(t *testing.T) {
	host := fakeHost{probes: map[Probe][]byte{ProbeFirewall: []byte("Status: inactive\n")}}
	findings, err := checkFirewall(context.Background(), host)
	if err != nil || len(findings) != 1 || findings[0].Severity != domain.SeverityHigh {
		t.Fatalf("completed inactive firewall check changed behavior: findings=%#v err=%v", findings, err)
	}
}

func TestKernelHardeningPreservesFindingsWhenCoverageIsPartial(t *testing.T) {
	host := fakeHost{files: map[string][]byte{
		"/proc/sys/kernel/randomize_va_space": []byte("0\n"),
		"/proc/sys/fs/protected_hardlinks":    []byte("1\n"),
		"/proc/sys/fs/protected_symlinks":     []byte("1\n"),
		"/proc/sys/net/ipv4/tcp_syncookies":   []byte("1\n"),
		"/proc/sys/kernel/dmesg_restrict":     []byte("1\n"),
	}}
	findings, err := checkKernelHardening(context.Background(), host)
	if err == nil || len(findings) != 1 || findings[0].Category != "kernel" || findings[0].Severity != domain.SeverityMedium || !strings.Contains(err.Error(), "kptr_restrict") {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
}

func TestKernelHardeningCompleteSecureState(t *testing.T) {
	files := make(map[string][]byte, len(kernelControls))
	for _, control := range kernelControls {
		files[control.path] = []byte(strconv.Itoa(control.minimum))
	}
	findings, err := checkKernelHardening(context.Background(), fakeHost{files: files})
	if err != nil || len(findings) != 0 {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
}
