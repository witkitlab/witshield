package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/observation"
)

const (
	processStateVersion  = 2
	maxProcessCandidates = 256
	maxProcessEvents     = 64
)

type processState struct {
	Version  int               `json:"version"`
	Records  map[string]string `json:"records"`
	Digest   string            `json:"digest"`
	Degraded bool              `json:"degraded"`
}

// processWatcher deliberately observes only two high-value process states. It
// does not collect command lines, environments, open files, or arbitrary
// process output: those commonly contain credentials. The resulting event is
// investigation evidence and is never eligible to authorize an action.
type processWatcher struct {
	hostRoot, statePath string
	helper              *HelperClient
	now                 func() time.Time
	pending             *processState
}

func (w *processWatcher) Poll(ctx context.Context) ([]domain.SecurityEvent, error) {
	if w.now == nil {
		w.now = time.Now
	}
	snapshot, err := w.measure(ctx)
	if err != nil {
		return nil, err
	}
	previous, initialized, err := w.load()
	if err != nil {
		return nil, err
	}
	if !initialized {
		previous = processState{Version: processStateVersion, Records: map[string]string{}}
	}
	candidates := snapshot.Processes
	current := processState{Version: processStateVersion, Records: make(map[string]string, len(candidates)), Degraded: snapshot.Truncated}
	events := make([]domain.SecurityEvent, 0)
	now := w.now().UTC()
	digester := sha256.New()
	omitted := 0
	for _, candidate := range candidates {
		current.Records[candidate.Identity] = candidate.EventType
		_, _ = digester.Write([]byte(candidate.Identity + "\x00" + candidate.EventType + "\n"))
		if _, exists := previous.Records[candidate.Identity]; exists {
			continue
		}
		if len(events) >= maxProcessEvents {
			omitted++
			continue
		}
		payload, _ := json.Marshal(map[string]any{
			"source": "procfs", "trust": "verified", "automaticActionEligible": false,
			"pid": candidate.PID, "ppid": candidate.PPID, "uid": candidate.UID,
			"name": candidate.Name, "executable": candidate.Executable, "reason": candidate.Reason,
		})
		sum := sha256.Sum256([]byte(candidate.Identity + "\x00" + candidate.EventType))
		events = append(events, domain.SecurityEvent{ID: "evt_" + hex.EncodeToString(sum[:12]), Type: candidate.EventType, OccurredAt: now, Payload: payload})
	}
	current.Digest = hex.EncodeToString(digester.Sum(nil))
	if current.Degraded && (!previous.Degraded || current.Digest != previous.Digest) || omitted > 0 {
		events = append(events, processCapacityEvent(current, snapshot.Observed, omitted, now, "process_sensor_capacity_degraded"))
	} else if previous.Degraded && !current.Degraded {
		events = append(events, processCapacityEvent(current, snapshot.Observed, 0, now, "process_sensor_capacity_restored"))
	}
	if len(events) > 0 || !initialized || len(previous.Records) != len(current.Records) {
		w.pending = &current
	}
	return events, nil
}

func (w *processWatcher) Commit() error {
	if w.pending == nil {
		return nil
	}
	if err := writePrivateJSONAtomic(w.statePath, *w.pending); err != nil {
		return err
	}
	w.pending = nil
	return nil
}

func (w *processWatcher) measure(ctx context.Context) (observation.ProcessSnapshot, error) {
	if w.helper != nil {
		return w.helper.ObserveSuspiciousProcesses(ctx)
	}
	return observation.SuspiciousProcesses(ctx, w.hostRoot)
}

func processCapacityEvent(state processState, observed, omitted int, now time.Time, eventType string) domain.SecurityEvent {
	payload, _ := json.Marshal(map[string]any{
		"source": "procfs", "trust": "verified", "automaticActionEligible": false,
		"observedProcesses": observed, "candidateCount": len(state.Records), "omittedEvents": omitted,
		"candidateCapacity": maxProcessCandidates, "eventCapacity": maxProcessEvents,
	})
	sum := sha256.Sum256([]byte(eventType + "\x00" + state.Digest))
	return domain.SecurityEvent{ID: "evt_" + hex.EncodeToString(sum[:12]), Type: eventType, OccurredAt: now, Payload: payload}
}

func (w *processWatcher) load() (processState, bool, error) {
	var state processState
	data, err := os.ReadFile(w.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return state, false, nil
	}
	if err != nil {
		return state, false, err
	}
	if len(data) > 256*1024 {
		return state, false, errors.New("process baseline exceeds safe size")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || state.Version != processStateVersion || state.Records == nil || len(state.Records) > maxProcessCandidates || len(state.Digest) != 64 {
		return state, false, errors.New("process baseline is invalid")
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return state, false, errors.New("process baseline has trailing data")
	}
	return state, true, nil
}
