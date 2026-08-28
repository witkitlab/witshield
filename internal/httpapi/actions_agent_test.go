package httpapi

import (
	"encoding/json"
	"testing"

	"github.com/witkitlab/witshield/internal/action"
)

func TestSecurityEventAdmissionCoversEveryAgentSensor(t *testing.T) {
	// Keep this list grouped by the Agent source that emits it. A new source or
	// event type must be admitted explicitly; otherwise one rejected item would
	// remain at the head of the durable Agent FIFO and block later evidence.
	eventTypes := map[string][]string{
		"ssh": {
			"ssh_auth_failure", "ssh_auth_success", "ssh_auth_failure_untrusted",
			"ssh_auth_log_line_oversized_untrusted",
		},
		"host_baseline": {
			"identity_state_changed", "access_trust_changed", "file_integrity_changed",
			"schedule_definition_changed", "service_definition_changed", "startup_definition_changed",
			"library_injection_changed", "kernel_policy_changed", "container_configuration_changed",
		},
		"network": {
			"network_listener_opened", "network_listener_closed",
			"network_sensor_capacity_degraded", "network_sensor_capacity_restored",
		},
		"process": {
			"suspicious_privileged_process_started", "deleted_executable_process_running",
			"process_sensor_capacity_degraded", "process_sensor_capacity_restored",
		},
	}
	for source, types := range eventTypes {
		for _, eventType := range types {
			t.Run(source+"/"+eventType, func(t *testing.T) {
				if !validSecurityEventType(eventType) {
					t.Fatalf("Agent event type %q is not admitted by the Controller", eventType)
				}
			})
		}
	}
	if validSecurityEventType("arbitrary_agent_selected_event") {
		t.Fatal("unknown event types must remain denied by default")
	}
}

func TestFilePermissionValidationUsesHelperAllowlist(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		allowed bool
	}{
		{name: "ssh config", path: "/etc/ssh/sshd_config", allowed: true},
		{name: "exact controller root", path: "/etc/witshield", allowed: true},
		{name: "controller descendant", path: "/etc/witshield/config.json", allowed: true},
		{name: "agent state descendant", path: "/var/lib/witshield-agent/state.json", allowed: true},
		{name: "helper credential", path: action.DefaultPermissionRepairTokenPath, allowed: false},
		{name: "helper trust state", path: "/var/lib/witshield-helper/state.key", allowed: false},
		{name: "lookalike prefix", path: "/var/lib/witshield-agent-evil/state", allowed: false},
		{name: "outside path", path: "/etc/passwd", allowed: false},
		{name: "relative path", path: "etc/witshield/config.json", allowed: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mode := "0600"
			if tc.path == "/etc/witshield" {
				mode = "0700"
			}
			raw, err := json.Marshal(action.FilePermissionRepairParams{Path: tc.path, Mode: mode})
			if err != nil {
				t.Fatal(err)
			}
			_, err = validateAction(string(action.TypeFilePermissionRepair), raw)
			if tc.allowed && err != nil {
				t.Fatalf("shared Helper path was rejected: %v", err)
			}
			if !tc.allowed && err == nil {
				t.Fatal("path outside the Helper allowlist was accepted")
			}
		})
	}
}

func TestFilePermissionValidationRejectsRequestsOutsideHelperModeAndOwnerEnvelope(t *testing.T) {
	uid := 1000
	tests := []action.FilePermissionRepairParams{
		{Path: action.DefaultPermissionRepairSSHPath, Mode: "0700"},
		{Path: action.DefaultPermissionRepairSSHPath, Mode: "0600", UID: &uid},
		{Path: "/etc/witshield", Mode: "0600"},
		{Path: "/var/lib/witshield-agent/state.json", Mode: "0644"},
		{Path: "/var/lib/witshield-agent/state.json", Mode: "0600", UID: &uid},
	}
	for _, params := range tests {
		raw, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = validateAction(string(action.TypeFilePermissionRepair), raw); err == nil {
			t.Fatalf("Controller accepted a request outside the Helper envelope: %#v", params)
		}
	}
}
