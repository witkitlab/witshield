package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNetworkWatcherBaselinesAndEmitsBoundedListenerChanges(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc", "1", "net")
	if err := os.MkdirAll(proc, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(proc, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	header := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	write("tcp", header+"0: 0100007F:1F90 00000000:0000 0A 0 0 0 0 0 0 0\n")
	write("tcp6", header)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	w := networkWatcher{hostRoot: root, statePath: filepath.Join(t.TempDir(), "network.json"), now: func() time.Time { return now }}
	events, err := w.Poll(context.Background())
	if err != nil || len(events) != 0 {
		t.Fatalf("initial baseline events=%#v err=%v", events, err)
	}
	write("tcp", header+"0: 00000000:1F90 00000000:0000 0A 0 0 0 0 0 0 0\n")
	events, err = w.Poll(context.Background())
	if err != nil || len(events) != 1 || events[0].Type != "network_listener_opened" {
		t.Fatalf("opened listener events=%#v err=%v", events, err)
	}
	var payload map[string]any
	if err = json.Unmarshal(events[0].Payload, &payload); err != nil || payload["address"] != "any" || payload["port"] != float64(8080) || payload["automaticActionEligible"] != false {
		t.Fatalf("unexpected payload %#v err=%v", payload, err)
	}
	// Without Commit the same deterministic event is replayed.
	replayed, err := w.Poll(context.Background())
	if err != nil || len(replayed) != 1 || replayed[0].ID != events[0].ID {
		t.Fatalf("replay=%#v err=%v", replayed, err)
	}
	if err = w.Commit(); err != nil {
		t.Fatal(err)
	}
	if quiet, quietErr := w.Poll(context.Background()); quietErr != nil || len(quiet) != 0 {
		t.Fatalf("committed baseline events=%#v err=%v", quiet, quietErr)
	}
	write("tcp", header)
	events, err = w.Poll(context.Background())
	if err != nil || len(events) != 1 || events[0].Type != "network_listener_closed" {
		t.Fatalf("closed listener events=%#v err=%v", events, err)
	}
}

func TestParseNetworkListenersHidesConcreteInterfaceAddress(t *testing.T) {
	listeners := map[string]networkListener{}
	input := "sl local_address rem_address st\n0: 0100000A:0016 00000000:0000 0A\n"
	if err := parseNetworkListeners(strings.NewReader(input), "ipv4", listeners); err != nil {
		t.Fatal(err)
	}
	if len(listeners) != 1 {
		t.Fatalf("listeners=%#v", listeners)
	}
	for _, listener := range listeners {
		if listener.Address == "0100000A" || listener.Address == "10.0.0.1" || !strings.HasPrefix(listener.Address, "interface:") {
			t.Fatalf("address was not minimized: %#v", listener)
		}
	}
}

func TestNetworkWatcherSurfacesCapacityDegradationAndAdvancesBaseline(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "proc", "1", "net")
	if err := os.MkdirAll(proc, 0o700); err != nil {
		t.Fatal(err)
	}
	header := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	var body strings.Builder
	body.WriteString(header)
	for port := 1; port <= maxNetworkListeners+1; port++ {
		fmt.Fprintf(&body, "%d: 00000000:%04X 00000000:0000 0A 0 0 0 0 0 0 0\n", port, port)
	}
	if err := os.WriteFile(filepath.Join(proc, "tcp"), []byte(body.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "tcp6"), []byte(header), 0o600); err != nil {
		t.Fatal(err)
	}
	w := networkWatcher{hostRoot: root, statePath: filepath.Join(t.TempDir(), "network.json")}
	events, err := w.Poll(context.Background())
	if err != nil || len(events) != 1 || events[0].Type != "network_sensor_capacity_degraded" {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	if err = w.Commit(); err != nil {
		t.Fatal(err)
	}
	if events, err = w.Poll(context.Background()); err != nil || len(events) != 0 {
		t.Fatalf("capacity baseline did not advance: events=%#v err=%v", events, err)
	}
}
