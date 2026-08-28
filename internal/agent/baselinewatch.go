package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

const (
	maxBaselineFileBytes = 1 << 20
	maxBaselineEntries   = 4096
)

type baselineRecord struct {
	Digest string `json:"digest"`
	Exists bool   `json:"exists"`
}

type baselineState struct {
	Version    int                       `json:"version"`
	Generation uint64                    `json:"generation"`
	Records    map[string]baselineRecord `json:"records"`
}

// baselineWatcher observes a deliberately small allowlist of security-relevant
// host state. It never sends file contents, command output, credentials, or
// arbitrary paths to the Controller. The first poll establishes a baseline;
// only later deltas become signed security events.
type baselineWatcher struct {
	hostRoot  string
	statePath string
	now       func() time.Time
	pending   *baselineState
}

type baselineTarget struct {
	path      string
	eventType string
	directory bool
}

var baselineTargets = []baselineTarget{
	{path: "etc/passwd", eventType: "identity_state_changed"},
	{path: "etc/group", eventType: "identity_state_changed"},
	{path: "etc/shadow", eventType: "identity_state_changed"},
	{path: "etc/sudoers", eventType: "identity_state_changed"},
	{path: "etc/sudoers.d", eventType: "identity_state_changed", directory: true},
	{path: "etc/security", eventType: "access_trust_changed", directory: true},
	{path: "etc/ssh/sshd_config", eventType: "file_integrity_changed"},
	{path: "etc/ssh/sshd_config.d", eventType: "file_integrity_changed", directory: true},
	{path: "etc/pam.d", eventType: "access_trust_changed", directory: true},
	{path: "etc/crontab", eventType: "schedule_definition_changed"},
	{path: "etc/cron.d", eventType: "schedule_definition_changed", directory: true},
	{path: "var/spool/cron/crontabs", eventType: "schedule_definition_changed", directory: true},
	{path: "etc/systemd/system", eventType: "service_definition_changed", directory: true},
	{path: "etc/rc.local", eventType: "startup_definition_changed"},
	{path: "etc/profile.d", eventType: "startup_definition_changed", directory: true},
	{path: "etc/ld.so.preload", eventType: "library_injection_changed"},
	{path: "etc/modules-load.d", eventType: "kernel_policy_changed", directory: true},
	{path: "etc/sysctl.d", eventType: "kernel_policy_changed", directory: true},
	{path: "etc/udev/rules.d", eventType: "startup_definition_changed", directory: true},
	{path: "etc/docker/daemon.json", eventType: "container_configuration_changed"},
}

func (w *baselineWatcher) Poll(ctx context.Context) ([]domain.SecurityEvent, error) {
	if w.now == nil {
		w.now = time.Now
	}
	hostRoot := filepath.Clean(w.hostRoot)
	if hostRoot == "." || hostRoot == "" {
		hostRoot = "/"
	}
	root, err := os.OpenRoot(hostRoot)
	if err != nil {
		return nil, fmt.Errorf("open security baseline root: %w", err)
	}
	defer root.Close()
	current := baselineState{Version: 1, Records: make(map[string]baselineRecord, len(baselineTargets))}
	for _, target := range baselineTargets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		record, err := w.measure(root, target)
		if err != nil {
			return nil, fmt.Errorf("measure security baseline %s: %w", target.path, err)
		}
		current.Records[target.path] = record
	}
	previous, initialized, err := w.load()
	if err != nil {
		return nil, err
	}
	if !initialized {
		current.Generation = 1
		if err = w.commit(current); err != nil {
			return nil, err
		}
		return nil, nil
	}
	current.Generation = previous.Generation
	now := w.now().UTC()
	events := make([]domain.SecurityEvent, 0)
	for _, target := range baselineTargets {
		before, after := previous.Records[target.path], current.Records[target.path]
		if before == after {
			continue
		}
		change := "modified"
		if !before.Exists && after.Exists {
			change = "created"
		} else if before.Exists && !after.Exists {
			change = "removed"
		}
		payload, _ := json.Marshal(map[string]any{
			"source": "host_security_baseline", "path": "/" + target.path,
			"change": change, "previousDigest": before.Digest, "currentDigest": after.Digest,
			"trust": "verified", "automaticActionEligible": false,
		})
		if current.Generation == previous.Generation {
			current.Generation++
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d", target.eventType, target.path, before.Digest, after.Digest, current.Generation)))
		events = append(events, domain.SecurityEvent{
			ID: "evt_" + hex.EncodeToString(sum[:12]), Type: target.eventType,
			OccurredAt: now, Payload: payload,
		})
	}
	if len(events) > 0 {
		w.pending = &current
	}
	return events, nil
}

// Commit advances the local baseline only after the caller has durably queued
// every event. If the process stops before Commit, the same generation produces
// the same event IDs on restart and Controller deduplication makes replay safe.
func (w *baselineWatcher) Commit() error {
	if w.pending == nil {
		return nil
	}
	if err := w.commit(*w.pending); err != nil {
		return err
	}
	w.pending = nil
	return nil
}

func (w *baselineWatcher) measure(root *os.Root, target baselineTarget) (baselineRecord, error) {
	info, err := root.Lstat(target.path)
	if errors.Is(err, os.ErrNotExist) {
		return baselineRecord{}, nil
	}
	if err != nil {
		return baselineRecord{}, err
	}
	h := sha256.New()
	writeMetadata(h, target.path, info)
	if target.directory {
		entries := 0
		err = fs.WalkDir(root.FS(), target.path, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if errors.Is(walkErr, os.ErrPermission) {
					_, _ = io.WriteString(h, "\x00unreadable\x00"+path)
					if entry != nil && !entry.IsDir() {
						return nil
					}
					return fs.SkipDir
				}
				return walkErr
			}
			if path == target.path {
				return nil
			}
			entries++
			if entries > maxBaselineEntries {
				return errors.New("baseline directory exceeds safe entry limit")
			}
			item, itemErr := root.Lstat(path)
			if itemErr != nil {
				return itemErr
			}
			writeMetadata(h, path, item)
			if item.Mode().IsRegular() && item.Size() <= maxBaselineFileBytes {
				if itemErr = hashRegularFile(h, root, path); itemErr != nil {
					return itemErr
				}
			}
			return nil
		})
		if err != nil {
			return baselineRecord{}, err
		}
	} else if info.Mode().IsRegular() && info.Size() <= maxBaselineFileBytes {
		if err = hashRegularFile(h, root, target.path); err != nil {
			return baselineRecord{}, err
		}
	} else if info.Mode()&os.ModeSymlink != 0 {
		targetValue, readErr := root.Readlink(target.path)
		if readErr != nil {
			return baselineRecord{}, readErr
		}
		_, _ = io.WriteString(h, "\x00symlink\x00"+targetValue)
	}
	return baselineRecord{Digest: hex.EncodeToString(h.Sum(nil)), Exists: true}, nil
}

func writeMetadata(dst io.Writer, path string, info os.FileInfo) {
	_, _ = fmt.Fprintf(dst, "%s\x00%d\x00%d\x00%d\x00", path, uint32(info.Mode()), info.Size(), info.ModTime().UTC().UnixNano())
}

func hashRegularFile(dst io.Writer, root *os.Root, path string) error {
	file, err := root.Open(path)
	if errors.Is(err, os.ErrPermission) {
		_, _ = io.WriteString(dst, "\x00unreadable\x00")
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(dst, io.LimitReader(file, maxBaselineFileBytes+1))
	return err
}

func (w *baselineWatcher) load() (baselineState, bool, error) {
	var state baselineState
	data, err := os.ReadFile(w.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return state, false, nil
	}
	if err != nil {
		return state, false, err
	}
	if len(data) > 256*1024 || json.Unmarshal(data, &state) != nil || state.Version != 1 || state.Records == nil {
		return state, false, errors.New("security baseline state is invalid")
	}
	return state, true, nil
}

func (w *baselineWatcher) commit(state baselineState) error {
	// Stable ordering makes the local state easy to audit and avoids needless
	// rewrites caused by Go map iteration order.
	keys := make([]string, 0, len(state.Records))
	for key := range state.Records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ordered := make(map[string]baselineRecord, len(keys))
	for _, key := range keys {
		ordered[key] = state.Records[key]
	}
	state.Records = ordered
	// Baseline advancement is part of the event delivery guarantee. Persist the
	// file and its directory entry before considering a generation committed so
	// a power loss cannot make us silently skip a security-relevant delta.
	return writePrivateJSONAtomic(w.statePath, state)
}
