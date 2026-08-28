package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/witkitlab/witshield/internal/action"
	"github.com/witkitlab/witshield/internal/defense"
	"github.com/witkitlab/witshield/internal/domain"
)

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	deviceID := strings.TrimSpace(r.URL.Query().Get("deviceId"))
	if deviceID != "" && !validAgentIdentifier(deviceID) {
		writeError(w, http.StatusBadRequest, "invalid_device_id", "deviceId is invalid")
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 200 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 200")
			return
		}
		limit = value
	}
	var statuses []domain.IncidentStatus
	if raw := strings.TrimSpace(r.URL.Query().Get("status")); raw != "" {
		for _, value := range strings.Split(raw, ",") {
			status := domain.IncidentStatus(strings.TrimSpace(value))
			if !validIncidentStatus(status) {
				writeError(w, http.StatusBadRequest, "invalid_status", "status is invalid")
				return
			}
			statuses = append(statuses, status)
		}
	}
	items, err := s.store.ListIncidents(r.Context(), deviceID, statuses, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func validIncidentStatus(status domain.IncidentStatus) bool {
	switch status {
	case domain.IncidentOpen, domain.IncidentInvestigating, domain.IncidentAwaitingApproval, domain.IncidentResponding, domain.IncidentMonitoring, domain.IncidentResolved, domain.IncidentDismissed:
		return true
	default:
		return false
	}
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	incident, err := s.store.Incident(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	signals, err := s.store.ListIncidentSignals(r.Context(), incident.ID, 200)
	if err != nil {
		s.fail(w, err)
		return
	}
	timeline, err := s.store.ListIncidentTimeline(r.Context(), incident.ID, 200)
	if err != nil {
		s.fail(w, err)
		return
	}
	investigations, err := s.store.ListInvestigations(r.Context(), incident.ID, 20)
	if err != nil {
		s.fail(w, err)
		return
	}
	plans, err := s.store.ListResponsePlans(r.Context(), incident.ID, 20)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"incident": incident, "signals": signals, "timeline": timeline, "investigations": investigations, "responsePlans": plans})
}

func (s *Server) updateIncident(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Status  domain.IncidentStatus `json:"status"`
		Summary string                `json:"summary,omitempty"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	// Investigation and response transitions are owned by their state machines;
	// this administrative endpoint only supports explicit triage decisions.
	if in.Status != domain.IncidentOpen && in.Status != domain.IncidentResolved && in.Status != domain.IncidentDismissed {
		writeError(w, http.StatusBadRequest, "invalid_status", "administrators may only reopen, resolve, or dismiss an incident")
		return
	}
	in.Summary = strings.TrimSpace(in.Summary)
	if len(in.Summary) > 1000 {
		writeError(w, http.StatusBadRequest, "invalid_summary", "summary is too long")
		return
	}
	if in.Summary == "" {
		in.Summary = "管理员将事件状态更新为 " + string(in.Status)
	}
	if err := s.store.SetIncidentStatus(r.Context(), r.PathValue("id"), in.Status, adminFrom(r.Context()).ID, in.Summary, s.now().UTC()); err != nil {
		s.fail(w, err)
		return
	}
	item, err := s.store.Incident(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) listPolicyGrants(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("id")
	if _, err := s.store.Device(r.Context(), deviceID); err != nil {
		s.fail(w, err)
		return
	}
	items, err := s.store.ListPolicyGrants(r.Context(), deviceID, s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) putPolicyGrant(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("id")
	capability := r.PathValue("capability")
	allowedByCapability := map[string]map[string]bool{
		"network.auth_bruteforce":   {string(action.TypeTemporaryIPBan): true},
		"identity.persistence":      {string(action.TypeSSHPasswordHardening): true},
		"workload.runtime":          {},
		"file.integrity":            {string(action.TypeFilePermissionRepair): true},
		"vulnerability.remediation": {string(action.TypePackageSecurityUpgrade): true},
	}
	allowedForCapability, supportedCapability := allowedByCapability[capability]
	if !supportedCapability {
		writeError(w, http.StatusBadRequest, "invalid_capability", "capability is invalid")
		return
	}
	var in struct {
		Enabled            bool                `json:"enabled"`
		Mode               domain.AutonomyMode `json:"mode"`
		AllowedActionTypes []string            `json:"allowedActionTypes"`
		MaxActionsPerHour  int                 `json:"maxActionsPerHour"`
		EmergencyStop      bool                `json:"emergencyStop"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	device, err := s.store.Device(r.Context(), deviceID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if device.ObserverOnly && in.Enabled && (in.Mode == domain.AutonomyAutoLowRisk || in.Mode == domain.AutonomyEnhanced) {
		writeError(w, http.StatusConflict, "observer_only_device", "automatic response is unavailable for a read-only observer device")
		return
	}
	switch in.Mode {
	case domain.AutonomyObserve, domain.AutonomyAssist, domain.AutonomyAutoLowRisk, domain.AutonomyEnhanced:
	default:
		writeError(w, http.StatusBadRequest, "invalid_mode", "mode is invalid")
		return
	}
	if in.MaxActionsPerHour < 1 || in.MaxActionsPerHour > 1000 || (capability == "network.auth_bruteforce" && in.MaxActionsPerHour > defense.MaxAutomaticBansPerHour) {
		writeError(w, http.StatusBadRequest, "invalid_action_limit", "maxActionsPerHour is outside the supported range")
		return
	}
	if capability == "network.auth_bruteforce" && in.Mode == domain.AutonomyEnhanced {
		writeError(w, http.StatusBadRequest, "invalid_mode", "SSH brute-force containment supports observe, assist, or auto_low_risk")
		return
	}
	known := map[string]bool{
		string(action.TypePackageSecurityUpgrade): true, string(action.TypeSSHPasswordHardening): true,
		string(action.TypeTemporaryIPBan): true, string(action.TypeFilePermissionRepair): true,
	}
	seen := map[string]bool{}
	for _, value := range in.AllowedActionTypes {
		if !known[value] || !allowedForCapability[value] || seen[value] {
			writeError(w, http.StatusBadRequest, "invalid_action_type", "allowedActionTypes contains an unsupported or duplicate action")
			return
		}
		seen[value] = true
	}
	item := domain.PolicyGrant{DeviceID: deviceID, Capability: capability, Enabled: in.Enabled, Mode: in.Mode,
		AllowedActionTypes: in.AllowedActionTypes, MaxActionsPerHour: in.MaxActionsPerHour,
		EmergencyStop: in.EmergencyStop, UpdatedAt: s.now().UTC()}
	if capability == "network.auth_bruteforce" {
		item.AllowedActionTypes = []string{string(action.TypeTemporaryIPBan)}
		legacy, legacyErr := s.store.DefensePolicy(r.Context(), deviceID, s.now())
		if legacyErr != nil {
			s.fail(w, legacyErr)
			return
		}
		legacy.Enabled = item.Enabled
		legacy.AutoBan = item.Enabled && (item.Mode == domain.AutonomyAutoLowRisk || item.Mode == domain.AutonomyEnhanced)
		legacy.EmergencyStop = item.EmergencyStop
		legacy.MaxBansPerHour = item.MaxActionsPerHour
		legacy.UpdatedAt = item.UpdatedAt
		if validateErr := defense.ValidatePolicy(legacy); validateErr != nil {
			writeError(w, http.StatusBadRequest, "invalid_policy_grant", validateErr.Error())
			return
		}
		if _, legacyErr = s.store.PutDefensePolicyAndCancelQueued(r.Context(), legacy); legacyErr != nil {
			s.fail(w, legacyErr)
			return
		}
	} else if err = s.store.PutPolicyGrant(r.Context(), item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_policy_grant", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, item)
}
