package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/ids"
)

const maxJournalOutput = 2 << 20

type journalRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type execJournalRunner struct{}

var acceptedSSH = regexp.MustCompile(`(?i)accepted (password|publickey|keyboard-interactive(?:/pam)?|hostbased) for ([A-Za-z0-9._$-]{1,64}) from ([0-9a-f:.]+)`)

func (execJournalRunner) Run(ctx context.Context, executable string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var output cappedBuffer
	output.remaining = maxJournalOutput
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("journalctl: %w: %s", err, truncateJournalError(output.String()))
	}
	return output.Bytes(), nil
}

type cappedBuffer struct {
	bytes.Buffer
	remaining int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.remaining {
		return 0, errors.New("journal output exceeds safe limit")
	}
	n, err := b.Buffer.Write(p)
	b.remaining -= n
	return n, err
}

func truncateJournalError(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 300 {
		return value[:300] + "…"
	}
	return value
}

type journalWatcher struct {
	executable string
	statePath  string
	runner     journalRunner
}

func (w *journalWatcher) Poll(ctx context.Context) ([]domain.SecurityEvent, string, error) {
	cursor, initialized, err := w.loadCursor()
	if err != nil {
		return nil, "", err
	}
	args := []string{"--no-pager", "--quiet", "--output=json", "--unit=ssh.service", "--unit=sshd.service", "--show-cursor"}
	if initialized {
		args = append(args, "--after-cursor="+cursor, "--lines=500")
	} else {
		args = append(args, "--lines=0")
	}
	data, err := w.runner.Run(ctx, w.executable, args...)
	if err != nil {
		return nil, "", err
	}
	events, next, err := parseJournalOutput(data, initialized, time.Now().UTC())
	if err != nil {
		return nil, "", err
	}
	if next == "" {
		return nil, "", errors.New("journalctl did not return a durable cursor")
	}
	return events, next, nil
}

func parseJournalOutput(data []byte, includeEvents bool, now time.Time) ([]domain.SecurityEvent, string, error) {
	if len(data) > maxJournalOutput {
		return nil, "", errors.New("journal output exceeds safe limit")
	}
	var events []domain.SecurityEvent
	var finalCursor string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxAuthLine)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "-- cursor: ") {
			finalCursor = strings.TrimSpace(strings.TrimPrefix(line, "-- cursor: "))
			continue
		}
		if line == "" {
			continue
		}
		var record struct {
			Message   string `json:"MESSAGE"`
			Cursor    string `json:"__CURSOR"`
			Timestamp string `json:"__REALTIME_TIMESTAMP"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, "", errors.New("journalctl returned malformed JSON")
		}
		if record.Cursor != "" {
			finalCursor = record.Cursor
		}
		if !includeEvents {
			continue
		}
		failure := failedSSH.FindStringSubmatch(record.Message)
		accepted := acceptedSSH.FindStringSubmatch(record.Message)
		if (len(failure) != 2 && len(accepted) != 4) || record.Cursor == "" {
			continue
		}
		occurredAt := now
		if micros, err := strconv.ParseInt(record.Timestamp, 10, 64); err == nil && micros > 0 {
			occurredAt = time.UnixMicro(micros).UTC()
		}
		// Old events are not useful to the live defense window and the Controller
		// intentionally rejects them. Advancing the cursor prevents queue blockage.
		if occurredAt.Before(now.Add(-7*24*time.Hour)) || occurredAt.After(now.Add(5*time.Minute)) {
			continue
		}
		eventType, sourceIP := "ssh_auth_failure", ""
		payload := json.RawMessage(`{"source":"journald","trust":"verified","automaticActionEligible":true}`)
		if len(failure) == 2 {
			sourceIP = strings.TrimSpace(failure[1])
		} else {
			eventType, sourceIP = "ssh_auth_success", strings.TrimSpace(accepted[3])
			payload, _ = json.Marshal(map[string]any{"source": "journald", "trust": "verified", "automaticActionEligible": false, "method": strings.ToLower(accepted[1]), "principal": accepted[2]})
		}
		sum := sha256.Sum256([]byte(record.Cursor + "\x00" + eventType + "\x00" + record.Message))
		events = append(events, domain.SecurityEvent{
			ID:         "evt_" + hex.EncodeToString(sum[:12]),
			Type:       eventType,
			SourceIP:   sourceIP,
			OccurredAt: occurredAt,
			Payload:    payload,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, "", err
	}
	if len(finalCursor) > 4096 || strings.ContainsAny(finalCursor, "\r\n\x00") {
		return nil, "", errors.New("journal cursor is invalid")
	}
	return events, finalCursor, nil
}

func (w *journalWatcher) loadCursor() (string, bool, error) {
	b, err := os.ReadFile(w.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	cursor := strings.TrimSpace(string(b))
	if cursor == "" || len(cursor) > 4096 || strings.ContainsAny(cursor, "\r\n\x00") {
		return "", false, errors.New("saved journal cursor is invalid")
	}
	return cursor, true, nil
}

func (w *journalWatcher) Commit(cursor string) error {
	if cursor == "" || len(cursor) > 4096 || strings.ContainsAny(cursor, "\r\n\x00") {
		return errors.New("journal cursor is invalid")
	}
	dir := filepath.Dir(w.statePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	tmp := w.statePath + "." + ids.New("tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if n, writeErr := io.WriteString(f, cursor); writeErr != nil || n != len(cursor) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		return writeErr
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, w.statePath); err != nil {
		return err
	}
	if err = syncDirectory(dir); err != nil {
		return err
	}
	ok = true
	return nil
}
