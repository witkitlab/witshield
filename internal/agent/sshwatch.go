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
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/ids"
)

const (
	maxAuthLogRead = 4 << 20
	maxAuthLine    = 256 << 10
	maxAuthEvents  = 500
	checkpointV1   = 1
)

const oversizedAuthLogEventType = "ssh_auth_log_line_oversized_untrusted"

var failedSSH = regexp.MustCompile(`(?i)(?:failed (?:password|publickey).* from |authentication failure;.*rhost=)([0-9a-f:.]+)`)

type authLogWatcher struct{ path, statePath string }

// authLogCheckpoint binds the byte offset to a concrete file identity. The
// local generation increments whenever the device/inode pair changes, so a
// replacement log is read from byte zero even when it is already larger than
// the previous offset. It also keeps event IDs from colliding across rotations.
type authLogCheckpoint struct {
	Version                int    `json:"version"`
	Device                 uint64 `json:"device"`
	Inode                  uint64 `json:"inode"`
	Generation             uint64 `json:"generation"`
	Offset                 int64  `json:"offset"`
	DiscardingOversizeLine bool   `json:"discardingOversizeLine,omitempty"`
}

func (c authLogCheckpoint) valid() bool {
	return c.Version == checkpointV1 && c.Generation > 0 && c.Offset >= 0
}

func (w *authLogWatcher) Poll(ctx context.Context) ([]domain.SecurityEvent, authLogCheckpoint, error) {
	checkpoint, initialized, legacy, err := w.loadCheckpoint()
	if err != nil {
		return nil, authLogCheckpoint{}, fmt.Errorf("load auth log checkpoint: %w", err)
	}
	pathInfo, err := os.Lstat(w.path)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		if !initialized {
			return nil, authLogCheckpoint{}, nil
		}
		return nil, checkpoint, nil
	}
	if err != nil {
		return nil, checkpoint, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, checkpoint, errors.New("auth log must be a regular non-symlink file")
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
	// Close the lstat/open race: the path must still name the same regular,
	// non-symlink file that was opened.
	currentPathInfo, err := os.Lstat(w.path)
	if err != nil {
		return nil, checkpoint, err
	}
	if !currentPathInfo.Mode().IsRegular() || currentPathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, currentPathInfo) {
		return nil, checkpoint, errors.New("auth log changed while it was being opened")
	}
	device, inode, err := authLogFileIdentity(info)
	if err != nil {
		return nil, checkpoint, err
	}

	// Enrollment starts at the current end of file. Replaying a historical log
	// while assigning receipt time would collapse old failures into the current
	// correlation window and could incorrectly trigger automatic defense.
	if !initialized {
		return nil, authLogCheckpoint{Version: checkpointV1, Device: device, Inode: inode, Generation: 1, Offset: info.Size()}, nil
	}
	if legacy {
		// Version-zero checkpoints stored only an offset. Adopt the current file
		// without replaying it, while preserving normal truncation detection.
		checkpoint.Version = checkpointV1
		checkpoint.Device = device
		checkpoint.Inode = inode
		checkpoint.Generation = 1
		checkpoint.DiscardingOversizeLine = false
		if info.Size() < checkpoint.Offset {
			checkpoint.Offset = 0
		}
	} else if checkpoint.Device != device || checkpoint.Inode != inode {
		if checkpoint.Generation == math.MaxUint64 {
			return nil, checkpoint, errors.New("auth log generation exhausted")
		}
		checkpoint.Device = device
		checkpoint.Inode = inode
		checkpoint.Generation++
		checkpoint.Offset = 0
		checkpoint.DiscardingOversizeLine = false
	} else if info.Size() < checkpoint.Offset {
		// Copy-truncate keeps the inode but starts a new logical generation.
		if checkpoint.Generation == math.MaxUint64 {
			return nil, checkpoint, errors.New("auth log generation exhausted")
		}
		checkpoint.Generation++
		checkpoint.Offset = 0
		checkpoint.DiscardingOversizeLine = false
	}

	if _, err = file.Seek(checkpoint.Offset, io.SeekStart); err != nil {
		return nil, checkpoint, err
	}
	reader := bufio.NewReaderSize(io.LimitReader(file, maxAuthLogRead), 64<<10)
	var events []domain.SecurityEvent
	var line []byte
	lineStart := checkpoint.Offset
	for {
		if err = ctx.Err(); err != nil {
			return nil, checkpoint, err
		}
		fragment, readErr := reader.ReadSlice('\n')
		if len(fragment) == 0 {
			if readErr == nil || errors.Is(readErr, io.EOF) {
				break
			}
			if errors.Is(readErr, bufio.ErrBufferFull) {
				continue
			}
			return nil, checkpoint, readErr
		}
		hasNewline := fragment[len(fragment)-1] == '\n'
		if checkpoint.DiscardingOversizeLine {
			checkpoint.Offset += int64(len(fragment))
			if hasNewline {
				checkpoint.DiscardingOversizeLine = false
				lineStart = checkpoint.Offset
			}
		} else if len(line)+len(fragment) > maxAuthLine {
			// Once a line exceeds the parser bound, commit progress while throwing
			// it away in at most 4 MiB per poll. The persisted discard bit lets a
			// multi-megabyte line drain across restarts without retaining content.
			events = append(events, w.oversizedLineEvent(checkpoint, lineStart))
			checkpoint.Offset += int64(len(line) + len(fragment))
			line = nil
			checkpoint.DiscardingOversizeLine = !hasNewline
			if hasNewline {
				lineStart = checkpoint.Offset
			}
		} else {
			line = append(line, fragment...)
			if hasNewline {
				lineWithoutNewline := bytes.TrimSuffix(line, []byte{'\n'})
				lineWithoutNewline = bytes.TrimSuffix(lineWithoutNewline, []byte{'\r'})
				if matches := failedSSH.FindSubmatch(lineWithoutNewline); len(matches) == 2 {
					events = append(events, w.failureEvent(checkpoint, lineStart, lineWithoutNewline, string(matches[1])))
				}
				checkpoint.Offset += int64(len(line))
				line = nil
				lineStart = checkpoint.Offset
			}
		}
		if len(events) >= maxAuthEvents {
			break
		}
		if readErr == nil || errors.Is(readErr, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		return nil, checkpoint, readErr
	}
	return events, checkpoint, nil
}

func authLogFileIdentity(info os.FileInfo) (uint64, uint64, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("authentication log file identity is unavailable")
	}
	// Stat_t uses signed device identifiers on some supported platforms and
	// unsigned identifiers on others. Decimal parsing preserves the full native
	// value and rejects a theoretically invalid negative identifier without a
	// narrowing or signedness-changing conversion.
	device, err := strconv.ParseUint(fmt.Sprint(stat.Dev), 10, 64)
	if err != nil {
		return 0, 0, errors.New("authentication log device identity is invalid")
	}
	inode, err := strconv.ParseUint(fmt.Sprint(stat.Ino), 10, 64)
	if err != nil {
		return 0, 0, errors.New("authentication log inode identity is invalid")
	}
	return device, inode, nil
}

func (w *authLogWatcher) failureEvent(checkpoint authLogCheckpoint, offset int64, line []byte, sourceIP string) domain.SecurityEvent {
	sum := sha256.Sum256([]byte(w.eventIdentity(checkpoint, offset, "failure") + "\x00" + string(line)))
	return domain.SecurityEvent{
		ID: "evt_" + hex.EncodeToString(sum[:12]),
		// Flat text logs do not carry a trustworthy process identity. Keep
		// these observations visible for an administrator, but give them a
		// distinct type so they can never authorize automatic defense.
		Type:       "ssh_auth_failure_untrusted",
		SourceIP:   strings.TrimSpace(sourceIP),
		OccurredAt: time.Now().UTC(),
		Payload:    json.RawMessage(`{"source":"auth.log","trust":"unverified","automaticActionEligible":false}`),
	}
}

func (w *authLogWatcher) oversizedLineEvent(checkpoint authLogCheckpoint, offset int64) domain.SecurityEvent {
	sum := sha256.Sum256([]byte(w.eventIdentity(checkpoint, offset, "oversized-line")))
	return domain.SecurityEvent{
		ID:         "evt_" + hex.EncodeToString(sum[:12]),
		Type:       oversizedAuthLogEventType,
		OccurredAt: time.Now().UTC(),
		Payload:    json.RawMessage(`{"source":"auth.log","trust":"unverified","automaticActionEligible":false,"reason":"line exceeded 256 KiB and was discarded"}`),
	}
}

func (w *authLogWatcher) eventIdentity(checkpoint authLogCheckpoint, offset int64, kind string) string {
	return strings.Join([]string{
		w.path,
		strconv.FormatUint(checkpoint.Device, 10),
		strconv.FormatUint(checkpoint.Inode, 10),
		strconv.FormatUint(checkpoint.Generation, 10),
		strconv.FormatInt(offset, 10),
		kind,
	}, "\x00")
}

func (w *authLogWatcher) loadCheckpoint() (authLogCheckpoint, bool, bool, error) {
	f, err := os.Open(w.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return authLogCheckpoint{}, false, false, nil
	}
	if err != nil {
		return authLogCheckpoint{}, false, false, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return authLogCheckpoint{}, false, false, err
	}
	if len(b) == 0 || len(b) > 4096 {
		return authLogCheckpoint{}, false, false, errors.New("invalid saved authentication log checkpoint")
	}
	trimmed := strings.TrimSpace(string(b))
	if offset, parseErr := strconv.ParseInt(trimmed, 10, 64); parseErr == nil {
		if offset < 0 {
			return authLogCheckpoint{}, false, false, errors.New("invalid saved authentication log offset")
		}
		return authLogCheckpoint{Offset: offset}, true, true, nil
	}
	var checkpoint authLogCheckpoint
	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&checkpoint); err != nil {
		return authLogCheckpoint{}, false, false, errors.New("invalid saved authentication log checkpoint")
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || !checkpoint.valid() {
		return authLogCheckpoint{}, false, false, errors.New("invalid saved authentication log checkpoint")
	}
	return checkpoint, true, false, nil
}

func (w *authLogWatcher) Commit(checkpoint authLogCheckpoint) error {
	if !checkpoint.valid() {
		return errors.New("invalid authentication log checkpoint")
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
	b, err := json.Marshal(checkpoint)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if n, writeErr := f.Write(b); writeErr != nil || n != len(b) {
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
