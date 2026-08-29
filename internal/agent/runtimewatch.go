package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

const (
	maxRuntimeLogRead = 2 << 20
	maxRuntimeLine    = 256 << 10
	maxRuntimeEvents  = 200
)

type runtimeLogWatcher struct {
	path, statePath string
	now             func() time.Time
}

func (w *runtimeLogWatcher) Poll(ctx context.Context) ([]domain.SecurityEvent, authLogCheckpoint, error) {
	checkpoint, initialized, _, err := (&authLogWatcher{statePath: w.statePath}).loadCheckpoint()
	if err != nil {
		return nil, checkpoint, err
	}
	pathInfo, err := os.Lstat(w.path)
	if err != nil {
		return nil, checkpoint, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, checkpoint, errors.New("runtime event log must be a regular non-symlink file")
	}
	file, err := os.Open(w.path)
	if err != nil {
		return nil, checkpoint, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, checkpoint, err
	}
	currentPathInfo, err := os.Lstat(w.path)
	if err != nil || !os.SameFile(info, currentPathInfo) {
		return nil, checkpoint, errors.New("runtime event log changed while opening")
	}
	device, inode, err := authLogFileIdentity(info)
	if err != nil {
		return nil, checkpoint, err
	}
	trusted := trustedRootLog(info)
	if !initialized {
		return nil, authLogCheckpoint{Version: checkpointV1, Device: device, Inode: inode, Generation: 1, Offset: info.Size()}, nil
	}
	if checkpoint.Device != device || checkpoint.Inode != inode {
		if checkpoint.Generation == math.MaxUint64 {
			return nil, checkpoint, errors.New("runtime event log generation exhausted")
		}
		checkpoint.Device, checkpoint.Inode, checkpoint.Generation, checkpoint.Offset = device, inode, checkpoint.Generation+1, 0
	} else if info.Size() < checkpoint.Offset {
		if checkpoint.Generation == math.MaxUint64 {
			return nil, checkpoint, errors.New("runtime event log generation exhausted")
		}
		checkpoint.Generation++
		checkpoint.Offset = 0
	}
	if _, err = file.Seek(checkpoint.Offset, io.SeekStart); err != nil {
		return nil, checkpoint, err
	}
	reader := bufio.NewReaderSize(io.LimitReader(file, maxRuntimeLogRead), 64<<10)
	now := time.Now().UTC()
	if w.now != nil {
		now = w.now().UTC()
	}
	var events []domain.SecurityEvent
	for len(events) < maxRuntimeEvents {
		if err = ctx.Err(); err != nil {
			return nil, checkpoint, err
		}
		start := checkpoint.Offset
		line, readErr := reader.ReadBytes('\n')
		if len(line) == 0 && errors.Is(readErr, io.EOF) {
			break
		}
		if len(line) > maxRuntimeLine {
			return nil, checkpoint, errors.New("runtime event line exceeds safe limit")
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return nil, checkpoint, readErr
		}
		if !bytes.HasSuffix(line, []byte{'\n'}) {
			break
		}
		checkpoint.Offset += int64(len(line))
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		event, ok := parseRuntimeEvent(line, w.path, checkpoint, start, trusted, now)
		if ok {
			events = append(events, event)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	return events, checkpoint, nil
}

func (w *runtimeLogWatcher) Commit(checkpoint authLogCheckpoint) error {
	return (&authLogWatcher{statePath: w.statePath}).Commit(checkpoint)
}

func trustedRootLog(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && info.Mode().Perm()&0o022 == 0
}

type falcoRecord struct {
	Time         string         `json:"time"`
	Rule         string         `json:"rule"`
	Priority     string         `json:"priority"`
	Source       string         `json:"source"`
	OutputFields map[string]any `json:"output_fields"`
	Tags         []string       `json:"tags"`
}

func parseRuntimeEvent(line []byte, path string, checkpoint authLogCheckpoint, offset int64, trusted bool, now time.Time) (domain.SecurityEvent, bool) {
	var record falcoRecord
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()
	if decoder.Decode(&record) != nil || decoder.Decode(&struct{}{}) != io.EOF || strings.TrimSpace(record.Rule) == "" || len(record.Rule) > 500 || len(record.OutputFields) > 128 || len(record.Tags) > 64 {
		return domain.SecurityEvent{}, false
	}
	eventType := classifyRuntimeRule(record.Rule, record.Tags)
	occurredAt := now
	if parsed, err := time.Parse(time.RFC3339Nano, record.Time); err == nil && !parsed.Before(now.Add(-7*24*time.Hour)) && !parsed.After(now.Add(5*time.Minute)) {
		occurredAt = parsed.UTC()
	}
	fields := allowRuntimeFields(record.OutputFields)
	fields["source"] = "falco"
	fields["trust"] = map[bool]string{true: "verified", false: "unverified"}[trusted]
	fields["automaticActionEligible"] = false
	fields["rule"] = truncateContext(record.Rule, 500)
	fields["priority"] = truncateContext(record.Priority, 32)
	fields["eventSource"] = truncateContext(record.Source, 64)
	fields["tags"] = safeRuntimeTags(record.Tags)
	payload, _ := json.Marshal(fields)
	identity := strings.Join([]string{path, strconv.FormatUint(checkpoint.Device, 10), strconv.FormatUint(checkpoint.Inode, 10), strconv.FormatUint(checkpoint.Generation, 10), strconv.FormatInt(offset, 10)}, "\x00")
	sum := sha256.Sum256(append([]byte(identity+"\x00"), line...))
	return domain.SecurityEvent{ID: "evt_" + hex.EncodeToString(sum[:12]), Type: eventType, OccurredAt: occurredAt, Payload: payload}, true
}

func classifyRuntimeRule(rule string, tags []string) string {
	value := strings.ToLower(rule + " " + strings.Join(tags, " "))
	switch {
	case strings.Contains(value, "reverse shell"):
		return "runtime_reverse_shell_detected"
	case strings.Contains(value, "crypto") || strings.Contains(value, "miner"):
		return "runtime_cryptominer_detected"
	case strings.Contains(value, "privileged container") || strings.Contains(value, "container escape") || strings.Contains(value, "namespace") || strings.Contains(value, "contact k8s api from container"):
		return "container_privilege_escalation"
	case strings.Contains(value, "persistence") || strings.Contains(value, "scheduled task") || strings.Contains(value, "systemd") || strings.Contains(value, "cron"):
		return "runtime_persistence_detected"
	case strings.Contains(value, "sensitive") || strings.Contains(value, "etc") || strings.Contains(value, "binary dir"):
		return "runtime_sensitive_file_change"
	default:
		return "runtime_security_alert"
	}
}

func allowRuntimeFields(raw map[string]any) map[string]any {
	allowed := []string{"proc.name", "proc.exepath", "proc.pid", "proc.ppid", "user.uid", "user.name", "container.id", "container.name", "container.image.repository", "fd.sip", "fd.dip", "fd.sport", "fd.dport", "evt.type"}
	out := make(map[string]any, len(allowed))
	for _, key := range allowed {
		value, ok := raw[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			out[key] = truncateContext(typed, 1024)
		case json.Number:
			out[key] = typed.String()
		case float64, bool:
			out[key] = typed
		}
	}
	return out
}

func safeRuntimeTags(tags []string) []string {
	out := make([]string, 0, min(len(tags), 16))
	for _, tag := range tags {
		tag = truncateContext(tag, 64)
		if tag != "" {
			out = append(out, tag)
		}
		if len(out) == 16 {
			break
		}
	}
	sort.Strings(out)
	return out
}

func truncateContext(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
	if len(value) > limit {
		value = value[:limit]
	}
	return value
}
