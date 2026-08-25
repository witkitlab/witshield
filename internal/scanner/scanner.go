package scanner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/ids"
)

type Probe string

const (
	ProbeFirewall     Probe = "firewall"
	ProbeUpdates      Probe = "updates"
	ProbeSSHEffective Probe = "ssh_effective"
)

type Host interface {
	ReadFile(path string) ([]byte, error)
	Stat(path string) (fs.FileInfo, error)
	Probe(ctx context.Context, probe Probe) ([]byte, error)
}

type SystemHost struct{ Root string }

func (h SystemHost) ObserverRoot() bool {
	return h.Root != "" && filepath.Clean(h.Root) != "/"
}

func isObserverRoot(h Host) bool {
	rooted, ok := h.(interface{ ObserverRoot() bool })
	return ok && rooted.ObserverRoot()
}

func NewSystemHost(root string) (SystemHost, error) {
	if root == "" {
		root = "/"
	}
	if !filepath.IsAbs(root) {
		return SystemHost{}, errors.New("host root must be absolute")
	}
	clean := filepath.Clean(root)
	canonical, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return SystemHost{}, err
	}
	info, err := os.Lstat(canonical)
	if err != nil {
		return SystemHost{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return SystemHost{}, errors.New("host root must be a non-symlink directory")
	}
	return SystemHost{Root: canonical}, nil
}
func (h SystemHost) resolve(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("host path must be absolute")
	}
	root := h.Root
	if root == "" {
		root = "/"
	}
	cleanRoot := filepath.Clean(root)
	rel := strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator))
	resolved := filepath.Join(cleanRoot, rel)
	relative, err := filepath.Rel(cleanRoot, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("host path escapes configured root")
	}
	evaluated, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return "", err
	}
	relative, err = filepath.Rel(cleanRoot, evaluated)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("host path escapes configured root through a symlink")
	}
	return evaluated, nil
}
func (h SystemHost) ReadFile(path string) ([]byte, error) {
	resolved, err := h.resolve(path)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(resolved)
}
func (h SystemHost) Stat(path string) (fs.FileInfo, error) {
	resolved, err := h.resolve(path)
	if err != nil {
		return nil, err
	}
	return os.Stat(resolved)
}
func (h SystemHost) Probe(ctx context.Context, p Probe) ([]byte, error) {
	if h.Root != "" && filepath.Clean(h.Root) != "/" {
		return nil, errors.New("command probes are unavailable in observer host-root mode")
	}
	var candidates [][]string
	switch p {
	case ProbeFirewall:
		candidates = [][]string{{"ufw", "status"}, {"nft", "list", "ruleset"}}
	case ProbeUpdates:
		candidates = [][]string{{"apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"}}
	case ProbeSSHEffective:
		candidates = [][]string{{"sshd", "-T"}}
	default:
		return nil, fmt.Errorf("unsupported probe %q", p)
	}
	var errs []error
	for _, argv := range candidates {
		path, err := exec.LookPath(argv[0])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		out, err := exec.CommandContext(probeCtx, path, argv[1:]...).CombinedOutput()
		cancel()
		if err == nil {
			return out, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", argv[0], err))
	}
	return nil, errors.Join(errs...)
}

type Check interface {
	Name() string
	Run(context.Context, Host) ([]domain.Finding, error)
}
type CheckFunc struct {
	NameValue string
	Fn        func(context.Context, Host) ([]domain.Finding, error)
}

func (c CheckFunc) Name() string                                              { return c.NameValue }
func (c CheckFunc) Run(ctx context.Context, h Host) ([]domain.Finding, error) { return c.Fn(ctx, h) }

type Scanner struct {
	checks []Check
	host   Host
	mode   string
	now    func() time.Time
}

func New(checks ...Check) *Scanner {
	if len(checks) == 0 {
		checks = Builtins()
	}
	return &Scanner{checks: checks, host: SystemHost{Root: "/"}, mode: "native", now: time.Now}
}
func NewWithHost(host Host, observer bool, checks ...Check) *Scanner {
	s := New(checks...)
	s.host = host
	if observer {
		s.mode = "observer"
	}
	return s
}
func Builtins() []Check {
	return []Check{
		CheckFunc{"ssh_configuration", checkSSH}, CheckFunc{"privileged_accounts", checkPasswd}, CheckFunc{"shadow_permissions", checkShadow},
		CheckFunc{"listening_ports", checkPorts}, CheckFunc{"firewall", checkFirewall}, CheckFunc{"security_updates", checkUpdates}, CheckFunc{"docker_socket", checkDockerSocket},
	}
}

func (s *Scanner) Scan(ctx context.Context, deviceID string) (domain.Report, error) {
	started := s.now().UTC()
	var findings []domain.Finding
	var checkErrors []string
	for _, c := range s.checks {
		if err := ctx.Err(); err != nil {
			return domain.Report{}, err
		}
		items, err := c.Run(ctx, s.host)
		if err != nil {
			checkErrors = append(checkErrors, c.Name()+": "+err.Error())
		}
		// A check may still return evidence collected from a visible subset of
		// its inputs together with an availability error. Preserve that evidence,
		// while the error keeps coverage from being reported as complete.
		for i := range items {
			items[i].DeviceID = deviceID
			items[i].Status = domain.FindingOpen
			items[i].Fingerprint = fingerprint(c.Name(), items[i].Title, items[i].Evidence)
		}
		findings = append(findings, items...)
	}
	completed := s.now().UTC()
	score := 100
	for _, f := range findings {
		switch f.Severity {
		case domain.SeverityCritical:
			score -= 30
		case domain.SeverityHigh:
			score -= 18
		case domain.SeverityMedium:
			score -= 8
		case domain.SeverityLow:
			score -= 3
		}
	}
	if score < 0 {
		score = 0
	}
	coverage := 100
	if len(s.checks) > 0 {
		coverage = (len(s.checks) - len(checkErrors)) * 100 / len(s.checks)
	}
	if score > coverage {
		score = coverage
	}
	summary := fmt.Sprintf(`{"checks":%d,"completedChecks":%d,"coveragePercent":%d,"findingCount":%d,"checkErrors":%s,"mode":%q}`, len(s.checks), len(s.checks)-len(checkErrors), coverage, len(findings), jsonStringSlice(checkErrors), s.mode)
	return domain.Report{ID: ids.New("rpt"), DeviceID: deviceID, StartedAt: started, CompletedAt: completed, Score: score, Summary: []byte(summary), Findings: findings}, nil
}
func jsonStringSlice(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = strconv.Quote(x)
	}
	return "[" + strings.Join(parts, ",") + "]"
}
func fingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}
func finding(sev domain.Severity, cat, title, desc, evidence, remediation string) domain.Finding {
	return domain.Finding{Category: cat, Severity: sev, Title: title, Description: desc, Evidence: evidence, Remediation: remediation}
}

func checkSSH(ctx context.Context, h Host) ([]domain.Finding, error) {
	b, err := h.Probe(ctx, ProbeSSHEffective)
	var settings map[string]string
	if err == nil {
		settings = parseSSHD(string(b))
	} else {
		b, err = h.ReadFile("/etc/ssh/sshd_config")
		if errors.Is(err, os.ErrNotExist) {
			if isObserverRoot(h) {
				return nil, errors.New("SSH configuration is not mounted in observer mode")
			}
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if strings.Contains(strings.ToLower(string(b)), "include ") {
			return nil, errors.New("effective SSH configuration unavailable and sshd_config contains Include directives")
		}
		settings = parseSSHD(string(b))
	}
	var out []domain.Finding
	if strings.EqualFold(settings["passwordauthentication"], "yes") {
		out = append(out, finding(domain.SeverityHigh, "ssh", "SSH password authentication is enabled", "Password authentication increases exposure to credential stuffing and brute-force attacks.", "PasswordAuthentication yes", "Verify key-based access from a second session, then disable password authentication."))
	}
	root := strings.ToLower(settings["permitrootlogin"])
	if root == "yes" {
		out = append(out, finding(domain.SeverityHigh, "ssh", "Direct root SSH login is enabled", "Direct root login increases the impact of a compromised credential.", "PermitRootLogin yes", "Use a named sudo account and set PermitRootLogin to prohibit-password or no."))
	} else if root == "without-password" || root == "prohibit-password" {
		out = append(out, finding(domain.SeverityLow, "ssh", "Root SSH login is allowed with keys", "Root can still be accessed directly using a trusted key.", "PermitRootLogin "+settings["permitrootlogin"], "Prefer a named sudo account and set PermitRootLogin no."))
	}
	return out, nil
}
func parseSSHD(s string) map[string]string {
	out := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(strings.ToLower(line), "match ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			key := strings.ToLower(fields[0])
			if _, ok := out[key]; !ok {
				out[key] = fields[1]
			}
		}
	}
	return out
}

func checkPasswd(_ context.Context, h Host) ([]domain.Finding, error) {
	b, err := h.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	var privileged []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		uid, e := strconv.Atoi(f[2])
		if e == nil && uid == 0 && f[0] != "root" {
			privileged = append(privileged, f[0])
		}
	}
	if len(privileged) == 0 {
		return nil, nil
	}
	sort.Strings(privileged)
	return []domain.Finding{finding(domain.SeverityCritical, "identity", "Additional UID 0 accounts found", "Accounts other than root have unrestricted system privileges.", strings.Join(privileged, ", "), "Confirm the accounts are expected, then assign non-zero UIDs or remove them.")}, nil
}
func checkShadow(_ context.Context, h Host) ([]domain.Finding, error) {
	info, err := h.Stat("/etc/shadow")
	if errors.Is(err, os.ErrNotExist) {
		if isObserverRoot(h) {
			return nil, errors.New("shadow permission metadata is not mounted in observer mode")
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o007 != 0 {
		return []domain.Finding{finding(domain.SeverityHigh, "permissions", "/etc/shadow is accessible to other users", "Password hash metadata must not be world-accessible.", fmt.Sprintf("mode %04o", info.Mode().Perm()), "Restore distribution defaults, commonly root:shadow 0640 or root:root 0600.")}, nil
	}
	return nil, nil
}

func checkPorts(_ context.Context, h Host) ([]domain.Finding, error) {
	paths := []string{"/proc/net/tcp", "/proc/net/tcp6"}
	if isObserverRoot(h) {
		// /proc/net is relative to the Agent's own network namespace even under
		// a bind mount. Host PID 1 exposes the host namespace deliberately.
		paths = []string{"/proc/1/net/tcp", "/proc/1/net/tcp6"}
	}
	seen := map[int]bool{}
	available := 0
	var unavailable []string
	for _, path := range paths {
		b, err := h.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			if isObserverRoot(h) {
				unavailable = append(unavailable, path)
			}
			continue
		}
		if err != nil {
			if isObserverRoot(h) {
				unavailable = append(unavailable, path)
				continue
			}
			return nil, err
		}
		available++
		for _, line := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 4 || f[3] != "0A" {
				continue
			}
			parts := strings.Split(f[1], ":")
			if len(parts) != 2 || procLoopback(parts[0]) {
				continue
			}
			port, e := strconv.ParseInt(parts[1], 16, 32)
			if e == nil {
				seen[int(port)] = true
			}
		}
	}
	var ports []int
	for p := range seen {
		if p != 22 {
			ports = append(ports, p)
		}
	}
	sort.Ints(ports)
	var findings []domain.Finding
	if len(ports) != 0 {
		text := make([]string, len(ports))
		for i, p := range ports {
			text[i] = strconv.Itoa(p)
		}
		findings = []domain.Finding{finding(domain.SeverityInfo, "network", "Services listen on non-loopback interfaces", "Review listening services and confirm each port is intentionally reachable beyond localhost.", "Non-loopback TCP ports: "+strings.Join(text, ", "), "Restrict unnecessary listeners and firewall access to trusted networks.")}
	}
	if isObserverRoot(h) && (available == 0 || len(unavailable) != 0) {
		return findings, fmt.Errorf("host TCP socket coverage is incomplete; unavailable: %s", strings.Join(unavailable, ", "))
	}
	return findings, nil
}
func procLoopback(hexAddr string) bool {
	upper := strings.ToUpper(hexAddr)
	return upper == "0100007F" || upper == "00000000000000000000000001000000"
}

func checkFirewall(ctx context.Context, h Host) ([]domain.Finding, error) {
	b, err := h.Probe(ctx, ProbeFirewall)
	if err != nil {
		// An unprivileged Agent commonly cannot read nftables state. Treat that as
		// unavailable coverage, not as a completed check or evidence that the host
		// firewall is inactive.
		return nil, fmt.Errorf("firewall status is unavailable: %w", err)
	}
	lower := strings.ToLower(string(b))
	if strings.Contains(lower, "status: inactive") || strings.TrimSpace(lower) == "" {
		return []domain.Finding{finding(domain.SeverityHigh, "network", "Host firewall is inactive", "The server is relying only on external network controls.", firstLine(string(b)), "Enable a deny-by-default host firewall after preserving management access.")}, nil
	}
	return nil, nil
}
func checkUpdates(ctx context.Context, h Host) ([]domain.Finding, error) {
	b, err := h.Probe(ctx, ProbeUpdates)
	if err != nil {
		return nil, errors.New("package update status is unavailable: " + err.Error())
	}
	count := 0
	var packages []string
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		count++
		fields := strings.Fields(line)
		if len(fields) > 1 && len(packages) < 10 {
			packages = append(packages, fields[1])
		}
	}
	if count == 0 {
		return nil, nil
	}
	sev := domain.SeverityMedium
	if count >= 20 {
		sev = domain.SeverityHigh
	}
	return []domain.Finding{finding(sev, "updates", "System packages have pending updates", fmt.Sprintf("%d packages can be upgraded; not every pending update is necessarily security-related.", count), strings.Join(packages, ", "), "Review the package changes, create a backup or snapshot, then install distribution updates.")}, nil
}
func checkDockerSocket(_ context.Context, h Host) ([]domain.Finding, error) {
	info, err := h.Stat("/var/run/docker.sock")
	if errors.Is(err, os.ErrNotExist) {
		if isObserverRoot(h) {
			return nil, errors.New("docker socket metadata is intentionally unavailable in observer mode")
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o007 != 0 {
		return []domain.Finding{finding(domain.SeverityCritical, "containers", "Docker socket is accessible to all users", "Docker API access is effectively root-equivalent on the host.", fmt.Sprintf("mode %04o", info.Mode().Perm()), "Remove world permissions and restrict Docker group membership.")}, nil
	}
	return nil, nil
}
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// ParseIP is exported for safe action validation and keeps address parsing rules consistent.
func ParseIP(raw string) (net.IP, error) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return nil, errors.New("invalid IP address")
	}
	return ip, nil
}
