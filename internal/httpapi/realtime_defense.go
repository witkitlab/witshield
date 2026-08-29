package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

func (s *Server) getAIInvestigationPolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := s.store.AIInvestigationPolicy(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	usage, err := s.store.AIInvestigationUsage(r.Context(), s.now().UTC())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": policy, "usage": usage, "accounting": "conservative_estimate"})
}

func (s *Server) putAIInvestigationPolicy(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Profile                domain.InvestigationProfile `json:"profile"`
		DailyTokenBudget       int                         `json:"dailyTokenBudget"`
		EmergencyReserveTokens int                         `json:"emergencyReserveTokens"`
		ShareNetworkIndicators bool                        `json:"shareNetworkIndicators"`
		ShareAccountNames      bool                        `json:"shareAccountNames"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	item := domain.AIInvestigationPolicy{Profile: input.Profile, DailyTokenBudget: input.DailyTokenBudget,
		EmergencyReserveTokens: input.EmergencyReserveTokens, ShareNetworkIndicators: input.ShareNetworkIndicators,
		ShareAccountNames: input.ShareAccountNames, UpdatedAt: s.now().UTC()}
	if err := s.store.PutAIInvestigationPolicy(r.Context(), item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_investigation_policy", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) listSensorHealth(w http.ResponseWriter, r *http.Request) {
	deviceID := strings.TrimSpace(r.URL.Query().Get("deviceId"))
	if deviceID != "" && !validAgentIdentifier(deviceID) {
		writeError(w, http.StatusBadRequest, "invalid_device_id", "deviceId is invalid")
		return
	}
	items, err := s.store.ListSensorHealth(r.Context(), deviceID)
	if err != nil {
		s.fail(w, err)
		return
	}
	now := s.now().UTC()
	for index := range items {
		item := &items[index]
		freshFor := time.Duration(item.CadenceSeconds*3) * time.Second
		if freshFor < 90*time.Second {
			freshFor = 90 * time.Second
		}
		if now.Sub(item.UpdatedAt) > freshFor && item.State != domain.SensorOptional {
			item.State = domain.SensorUnavailable
			item.Error = "Agent 心跳仍可能在线，但该传感器状态已经超过预期更新窗口"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "serverTime": now})
}
