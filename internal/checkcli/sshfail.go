package checkcli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/action"
)

const (
	journalctlPath = "/usr/bin/journalctl"
	maxSSHLogBytes = 8 << 20
	maxSSHLogLine  = 64 << 10
)

// SSHFailures distinguishes unavailable logs from an observed zero count.
// Source addresses are deliberately restricted to the human terminal report.
type SSHFailures struct {
	Available bool           `json:"available"`
	Total     *int           `json:"total"`
	UniqueIPs *int           `json:"uniqueIPs"`
	Source    string         `json:"source,omitempty"`
	TopIPs    []SSHFailureIP `json:"-"`
}

type SSHFailureIP struct {
	IP    string
	Count int
}

type sshLogCollector struct {
	runner      action.Runner
	openAuthLog func() (io.ReadCloser, error)
	now         func() time.Time
}

// CollectSSHFailures reads only the local, retained 24-hour SSH log window.
func CollectSSHFailures(ctx context.Context) SSHFailures {
	runner := action.NewExecRunner(journalctlPath)
	runner.MaxOutputBytes = maxSSHLogBytes
	return (sshLogCollector{
		runner: runner, openAuthLog: func() (io.ReadCloser, error) { return os.Open("/var/log/auth.log") }, now: time.Now,
	}).collect(ctx)
}

func (c sshLogCollector) collect(ctx context.Context) SSHFailures {
	now := c.now()
	journalCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	result, err := c.runner.Run(journalCtx, action.Command{
		Path: journalctlPath, Args: []string{"-u", "ssh", "-u", "sshd", "--since", "-24h", "-o", "json", "--no-pager"}, Timeout: 10 * time.Second,
	})
	cancel()
	// journalctl can exit successfully yet disclose that this user cannot see
	// system logs. Such partial access must not turn into a reassuring zero.
	if err == nil && !result.OutputTruncated && strings.TrimSpace(result.Stderr) == "" {
		if stats, err := parseSSHJournal([]byte(result.Stdout), now); err == nil {
			return stats
		}
	}
	if ctx.Err() != nil {
		return SSHFailures{}
	}
	log, err := c.openAuthLog()
	if err != nil {
		return SSHFailures{}
	}
	defer log.Close()
	stats, err := parseSSHAuthLog(ctx, log, now)
	if err != nil {
		return SSHFailures{}
	}
	return stats
}

var (
	sshPrimaryFailure       = regexp.MustCompile(`(?i)^Failed (?:password|publickey|keyboard-interactive(?:/pam)?) for .+ from (\S+) port ([0-9]+)(?: |$)`)
	sshInvalidUser          = regexp.MustCompile(`(?i)^Invalid user .+ from (\S+) port ([0-9]+)(?: |$)`)
	sshClosedAuthentication = regexp.MustCompile(`(?i)^Connection (?:closed|reset) by (?:authenticating user|invalid user) \S+ (\S+) port ([0-9]+)(?: |$)`)
	sshPAMFailure           = regexp.MustCompile(`(?i)^pam_unix\(sshd:auth\): authentication failure;.*\brhost=(\S+)`)
	sshLogPrefix            = regexp.MustCompile(`\bsshd(?:-session)?\[([0-9]+)\]:\s*`)
)

type sshSessionFailures struct {
	ip        string
	primary   int
	auxiliary bool
}
type sshFailureCounter struct {
	sessions map[string]*sshSessionFailures
	sequence int
	records  int
}

func newSSHFailureCounter() *sshFailureCounter {
	return &sshFailureCounter{sessions: map[string]*sshSessionFailures{}}
}

func (c *sshFailureCounter) add(message, pid string) {
	c.records++
	if match := sshLogPrefix.FindStringSubmatchIndex(message); len(match) > 0 {
		pid = message[match[2]:match[3]]
		message = message[match[1]:]
	}
	message = strings.TrimSpace(strings.TrimPrefix(message, "error: "))
	match := sshPrimaryFailure.FindStringSubmatch(message)
	primary := len(match) > 0
	if !primary {
		match = sshInvalidUser.FindStringSubmatch(message)
	}
	if len(match) == 0 {
		match = sshClosedAuthentication.FindStringSubmatch(message)
	}
	if len(match) == 0 {
		match = sshPAMFailure.FindStringSubmatch(message)
	}
	if len(match) == 0 {
		return
	}
	ip, err := netip.ParseAddr(strings.Trim(match[1], "[]"))
	if err != nil || ip.Zone() != "" {
		return
	}
	if len(match) > 2 {
		port, err := strconv.Atoi(match[2])
		if err != nil || port < 1 || port > 65535 {
			return
		}
	}
	address := ip.Unmap().String()
	// OpenSSH emits Invalid user/PAM failure/connection closed around the
	// same Failed password record. Count each explicit authentication failure;
	// only use those auxiliary records once when no primary record exists.
	key := pid + "/" + address
	if pid == "" {
		if len(match) > 2 {
			key = "port/" + match[2] + "/" + address
		} else {
			c.sequence++
			key = fmt.Sprintf("line/%d", c.sequence)
		}
	}
	session := c.sessions[key]
	if session == nil {
		session = &sshSessionFailures{ip: address}
		c.sessions[key] = session
	}
	if primary {
		session.primary++
	} else {
		session.auxiliary = true
	}
}

func (c *sshFailureCounter) result(source string) (SSHFailures, error) {
	if c.records == 0 {
		return SSHFailures{}, errors.New("no recent SSH log records")
	}
	counts := map[string]int{}
	total := 0
	for _, session := range c.sessions {
		n := session.primary
		if n == 0 && session.auxiliary {
			n = 1
		}
		counts[session.ip] += n
		total += n
	}
	unique := len(counts)
	top := make([]SSHFailureIP, 0, len(counts))
	for ip, count := range counts {
		top = append(top, SSHFailureIP{IP: ip, Count: count})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].Count != top[j].Count {
			return top[i].Count > top[j].Count
		}
		return top[i].IP < top[j].IP
	})
	if len(top) > 3 {
		top = top[:3]
	}
	return SSHFailures{Available: true, Total: &total, UniqueIPs: &unique, TopIPs: top, Source: source}, nil
}

func parseSSHJournal(data []byte, now time.Time) (SSHFailures, error) {
	if len(data) > maxSSHLogBytes {
		return SSHFailures{}, errors.New("SSH journal exceeds limit")
	}
	counter := newSSHFailureCounter()
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxSSHLogLine)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var record struct {
			Message   string `json:"MESSAGE"`
			Timestamp string `json:"__REALTIME_TIMESTAMP"`
			PID       string `json:"_PID"`
		}
		if err := json.Unmarshal(line, &record); err != nil {
			return SSHFailures{}, errors.New("malformed SSH journal")
		}
		micros, err := strconv.ParseInt(record.Timestamp, 10, 64)
		if err != nil || micros <= 0 {
			return SSHFailures{}, errors.New("missing SSH journal timestamp")
		}
		at := time.UnixMicro(micros)
		if at.Before(now.Add(-24*time.Hour)) || at.After(now) {
			continue
		}
		counter.add(record.Message, record.PID)
	}
	if err := scanner.Err(); err != nil {
		return SSHFailures{}, err
	}
	return counter.result("journald")
}

func parseSSHAuthLog(ctx context.Context, input io.Reader, now time.Time) (SSHFailures, error) {
	counter := newSSHFailureCounter()
	limited := &io.LimitedReader{R: input, N: maxSSHLogBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), maxSSHLogLine)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return SSHFailures{}, err
		}
		line := scanner.Text()
		fields := strings.Fields(line)
		programIndex := 4
		if len(fields) > 0 {
			if _, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
				programIndex = 2
			}
		}
		if len(fields) <= programIndex || !sshLogPrefix.MatchString(fields[programIndex]) || !strings.HasPrefix(fields[programIndex], "sshd") {
			continue
		}
		at, ok := authLogTime(line, now)
		if !ok {
			return SSHFailures{}, errors.New("missing SSH auth.log timestamp")
		}
		if at.Before(now.Add(-24*time.Hour)) || at.After(now) {
			continue
		}
		counter.add(line, "")
	}
	if limited.N == 0 {
		return SSHFailures{}, errors.New("SSH auth.log exceeds limit")
	}
	if err := scanner.Err(); err != nil {
		return SSHFailures{}, err
	}
	return counter.result("auth.log")
}

func authLogTime(line string, now time.Time) (time.Time, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return time.Time{}, false
	}
	if at, err := time.Parse(time.RFC3339Nano, fields[0]); err == nil {
		return at, true
	}
	if len(line) < 15 {
		return time.Time{}, false
	}
	stamp := line[:15]
	// Traditional syslog has no year. Choose the closest occurrence across
	// year boundaries, then apply the exact 24-hour window in the caller.
	var best time.Time
	for _, year := range []int{now.Year() - 1, now.Year(), now.Year() + 1} {
		at, err := time.ParseInLocation("2006 Jan _2 15:04:05", fmt.Sprintf("%d %s", year, stamp), now.Location())
		if err == nil && (best.IsZero() || absoluteDuration(at.Sub(now)) < absoluteDuration(best.Sub(now))) {
			best = at
		}
	}
	return best, !best.IsZero()
}

func absoluteDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func formatCount(n int) string {
	value := strconv.Itoa(n)
	for i := len(value) - 3; i > 0; i -= 3 {
		value = value[:i] + "," + value[i:]
	}
	return value
}
