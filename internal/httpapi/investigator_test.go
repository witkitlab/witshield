package httpapi

import (
	"testing"

	"github.com/witkitlab/witshield/internal/domain"
)

func TestDecodeInvestigationOutputIsStrictAndBounded(t *testing.T) {
	valid := `{"hypothesis":"配置漂移","conclusion":"确定性信号证明配置发生变化，但尚不能确认是攻击。","confidence":72,"plan":null}`
	if _, err := decodeInvestigationOutput(valid); err != nil {
		t.Fatal(err)
	}
	invalid := []string{
		"```json\n" + valid + "\n```",
		valid + ` {}`,
		`{"hypothesis":"x","conclusion":"y","confidence":101,"plan":null}`,
		`{"hypothesis":"x","conclusion":"y","confidence":1,"unexpected":true,"plan":null}`,
	}
	for _, raw := range invalid {
		if _, err := decodeInvestigationOutput(raw); err == nil {
			t.Fatalf("invalid output accepted: %q", raw)
		}
	}
}

func TestAutomaticInvestigationRespectsCapabilityBoundaries(t *testing.T) {
	incident := domain.Incident{Category: "file_integrity", Severity: domain.SeverityHigh}
	grants := []domain.PolicyGrant{{Capability: "file.integrity", Enabled: true, Mode: domain.AutonomyAssist}}
	if !automaticInvestigationAllowed(incident, grants) {
		t.Fatal("enabled assist grant did not permit read-only investigation")
	}
	grants[0].EmergencyStop = true
	if automaticInvestigationAllowed(incident, grants) {
		t.Fatal("emergency stop did not block automatic investigation")
	}
	grants[0].EmergencyStop, grants[0].Mode, incident.Severity = false, domain.AutonomyAssist, domain.SeverityLow
	if automaticInvestigationAllowed(incident, grants) {
		t.Fatal("low-severity event unexpectedly consumed AI in assist mode")
	}
	grants[0].Mode = domain.AutonomyEnhanced
	if !automaticInvestigationAllowed(incident, grants) {
		t.Fatal("enhanced mode did not permit low-severity investigation")
	}
}

func TestIncidentCapabilityMappingIsNarrow(t *testing.T) {
	cases := map[string]string{
		"identity_access":      "network.auth_bruteforce",
		"identity_persistence": "identity.persistence",
		"file_integrity":       "file.integrity",
		"updates":              "vulnerability.remediation",
		"container_runtime":    "workload.runtime",
	}
	for category, want := range cases {
		if got := incidentCapability(category); got != want {
			t.Fatalf("incidentCapability(%q)=%q want %q", category, got, want)
		}
	}
}

func TestActionRiskCannotBeDowngradedByModelText(t *testing.T) {
	if actionRisk("package_security_upgrade") != "high" || riskRank("high") <= riskRank("medium") {
		t.Fatal("Controller-owned action risk classification was weakened")
	}
}
