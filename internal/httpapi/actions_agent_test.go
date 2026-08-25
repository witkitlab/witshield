package httpapi

import (
	"encoding/json"
	"testing"

	"github.com/witkitlab/witshield/internal/action"
)

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
