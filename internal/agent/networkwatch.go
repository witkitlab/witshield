package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

const (
	networkStateVersion = 2
	maxNetworkListeners = 512
	maxNetworkEvents    = 128
)

type networkListener struct {
	Family  string `json:"family"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type networkState struct {
	Version    int                        `json:"version"`
	Generation uint64                     `json:"generation"`
	Listeners  map[string]networkListener `json:"listeners"`
	Total      int                        `json:"total"`
	Digest     string                     `json:"digest"`
	Saturated  bool                       `json:"saturated"`
}

// networkWatcher keeps a small, content-free baseline of non-loopback TCP
// listeners. A newly exposed service is useful security evidence, but never an
// automatic authorization: deployments and restarts can legitimately change
// listeners and still require investigation in context.
type networkWatcher struct {
	hostRoot  string
	statePath string
	now       func() time.Time
	pending   *networkState
}

func (w *networkWatcher) Poll(ctx context.Context) ([]domain.SecurityEvent, error) {
	if w.now == nil {
		w.now = time.Now
	}
	current, err := w.measure(ctx)
	if err != nil {
		return nil, err
	}
	previous, initialized, err := w.load()
	if err != nil {
		return nil, err
	}
	now := w.now().UTC()
	if !initialized {
		current.Generation = 1
		if current.Saturated {
			w.pending = &current
			return []domain.SecurityEvent{networkCapacityEvent(current, now, "network_sensor_capacity_degraded")}, nil
		}
		return nil, w.commit(current)
	}
	current.Generation = previous.Generation
	if current.Saturated || previous.Saturated {
		if current.Digest == previous.Digest && current.Saturated == previous.Saturated {
			return nil, nil
		}
		current.Generation++
		eventType := "network_sensor_capacity_degraded"
		if !current.Saturated {
			eventType = "network_sensor_capacity_restored"
		}
		w.pending = &current
		return []domain.SecurityEvent{networkCapacityEvent(current, now, eventType)}, nil
	}
	keys := make([]string, 0, len(current.Listeners)+len(previous.Listeners))
	seen := make(map[string]struct{}, len(current.Listeners)+len(previous.Listeners))
	for key := range current.Listeners {
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	for key := range previous.Listeners {
		if _, ok := seen[key]; !ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	changed := 0
	for _, key := range keys {
		_, existed := previous.Listeners[key]
		_, exists := current.Listeners[key]
		if existed != exists {
			changed++
		}
	}
	if changed > maxNetworkEvents {
		current.Generation++
		w.pending = &current
		return []domain.SecurityEvent{networkChangeCapacityEvent(current, now, changed)}, nil
	}
	events := make([]domain.SecurityEvent, 0)
	for _, key := range keys {
		before, existed := previous.Listeners[key]
		after, exists := current.Listeners[key]
		if existed == exists {
			continue
		}
		listener, eventType, change := after, "network_listener_opened", "opened"
		if !exists {
			listener, eventType, change = before, "network_listener_closed", "closed"
		}
		if current.Generation == previous.Generation {
			current.Generation++
		}
		payload, _ := json.Marshal(map[string]any{
			"source": "proc_net_tcp", "trust": "verified", "automaticActionEligible": false,
			"change": change, "family": listener.Family, "address": listener.Address, "port": listener.Port,
		})
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", eventType, key, current.Generation)))
		events = append(events, domain.SecurityEvent{ID: "evt_" + hex.EncodeToString(sum[:12]), Type: eventType, OccurredAt: now, Payload: payload})
	}
	if len(events) > 0 {
		w.pending = &current
	}
	return events, nil
}

func (w *networkWatcher) Commit() error {
	if w.pending == nil {
		return nil
	}
	if err := w.commit(*w.pending); err != nil {
		return err
	}
	w.pending = nil
	return nil
}

func (w *networkWatcher) measure(ctx context.Context) (networkState, error) {
	rootPath := filepath.Clean(w.hostRoot)
	if rootPath == "." || rootPath == "" {
		rootPath = "/"
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return networkState{}, err
	}
	defer root.Close()
	paths := []struct{ path, family string }{{"proc/net/tcp", "ipv4"}, {"proc/net/tcp6", "ipv6"}}
	if rootPath != "/" {
		paths = []struct{ path, family string }{{"proc/1/net/tcp", "ipv4"}, {"proc/1/net/tcp6", "ipv6"}}
	}
	state := networkState{Version: networkStateVersion, Listeners: map[string]networkListener{}}
	allKeys := make([]string, 0, maxNetworkListeners)
	available := 0
	for _, item := range paths {
		if err = ctx.Err(); err != nil {
			return networkState{}, err
		}
		file, openErr := root.Open(item.path)
		if errors.Is(openErr, os.ErrNotExist) || errors.Is(openErr, os.ErrPermission) {
			continue
		}
		if openErr != nil {
			return networkState{}, openErr
		}
		available++
		parseErr := parseNetworkListenersMeasured(io.LimitReader(file, 2<<20), item.family, state.Listeners, &state.Total, &allKeys)
		closeErr := file.Close()
		if parseErr != nil {
			return networkState{}, parseErr
		}
		if closeErr != nil {
			return networkState{}, closeErr
		}
	}
	if available == 0 {
		return networkState{}, errors.New("host TCP listener tables are unavailable")
	}
	sort.Strings(allKeys)
	digester := sha256.New()
	for _, key := range allKeys {
		_, _ = io.WriteString(digester, key+"\n")
	}
	state.Digest = hex.EncodeToString(digester.Sum(nil))
	state.Saturated = state.Total > maxNetworkListeners
	return state, nil
}

func parseNetworkListeners(reader io.Reader, family string, out map[string]networkListener) error {
	total := 0
	keys := make([]string, 0)
	return parseNetworkListenersMeasured(reader, family, out, &total, &keys)
}

func parseNetworkListenersMeasured(reader io.Reader, family string, out map[string]networkListener, total *int, allKeys *[]string) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 256<<10)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		parts := strings.Split(fields[1], ":")
		if len(parts) != 2 || listenerLoopback(parts[0], family) {
			continue
		}
		port, err := strconv.ParseInt(parts[1], 16, 32)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		address := normalizedListenerAddress(parts[0], family)
		listener := networkListener{Family: family, Address: address, Port: int(port)}
		key := family + ":" + address + ":" + strconv.Itoa(int(port))
		*allKeys = append(*allKeys, key)
		*total++
		if len(out) < maxNetworkListeners {
			out[key] = listener
		}
	}
	return scanner.Err()
}

func networkCapacityEvent(state networkState, now time.Time, eventType string) domain.SecurityEvent {
	payload, _ := json.Marshal(map[string]any{
		"source": "proc_net_tcp", "trust": "verified", "automaticActionEligible": false,
		"listenerCount": state.Total, "capacity": maxNetworkListeners,
	})
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", eventType, state.Digest, state.Generation)))
	return domain.SecurityEvent{ID: "evt_" + hex.EncodeToString(sum[:12]), Type: eventType, OccurredAt: now, Payload: payload}
}

func networkChangeCapacityEvent(state networkState, now time.Time, changed int) domain.SecurityEvent {
	payload, _ := json.Marshal(map[string]any{
		"source": "proc_net_tcp", "trust": "verified", "automaticActionEligible": false,
		"changeCount": changed, "eventCapacity": maxNetworkEvents,
	})
	sum := sha256.Sum256([]byte(fmt.Sprintf("network_sensor_change_capacity_degraded\x00%s\x00%d", state.Digest, state.Generation)))
	return domain.SecurityEvent{ID: "evt_" + hex.EncodeToString(sum[:12]), Type: "network_sensor_capacity_degraded", OccurredAt: now, Payload: payload}
}

func listenerLoopback(raw, family string) bool {
	upper := strings.ToUpper(raw)
	if family == "ipv4" {
		return upper == "0100007F"
	}
	return upper == "00000000000000000000000001000000"
}

func normalizedListenerAddress(raw, family string) string {
	upper := strings.ToUpper(raw)
	if (family == "ipv4" && upper == "00000000") || (family == "ipv6" && upper == strings.Repeat("0", 32)) {
		return "any"
	}
	// The proc representation is intentionally not converted into a routable IP:
	// the investigation needs interface scope, not another inventory of host
	// addresses. A short digest still distinguishes changes without disclosing it.
	sum := sha256.Sum256([]byte(family + "\x00" + upper))
	return "interface:" + hex.EncodeToString(sum[:6])
}

func (w *networkWatcher) load() (networkState, bool, error) {
	var state networkState
	data, err := os.ReadFile(w.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return state, false, nil
	}
	if err != nil {
		return state, false, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if len(data) > 256*1024 || decoder.Decode(&state) != nil || state.Version != networkStateVersion || state.Listeners == nil || state.Generation == 0 || len(state.Digest) != 64 {
		return state, false, errors.New("network listener baseline is invalid")
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return state, false, errors.New("network listener baseline has trailing data")
	}
	return state, true, nil
}

func (w *networkWatcher) commit(state networkState) error {
	if state.Version != networkStateVersion || state.Generation == 0 || len(state.Listeners) > maxNetworkListeners || state.Total < len(state.Listeners) || state.Digest == "" {
		return errors.New("network listener baseline is invalid")
	}
	return writePrivateJSONAtomic(w.statePath, state)
}
