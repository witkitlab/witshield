package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/defense"
	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/store"
)

type securityEventCursorWire struct {
	OccurredAt string `json:"occurredAt"`
	DeviceID   string `json:"deviceId"`
	ID         string `json:"id"`
}

func (s *Server) listSecurityEvents(w http.ResponseWriter, r *http.Request) {
	deviceID := strings.TrimSpace(r.URL.Query().Get("deviceId"))
	eventType := strings.TrimSpace(r.URL.Query().Get("type"))
	if deviceID != "" && !validAgentIdentifier(deviceID) {
		writeError(w, http.StatusBadRequest, "invalid_device_id", "deviceId is invalid")
		return
	}
	if eventType != "" && !validSecurityEventFilterType(eventType) {
		writeError(w, http.StatusBadRequest, "invalid_event_type", "type is invalid")
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			writeError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 100")
			return
		}
	}
	var cursor *store.SecurityEventCursor
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		decoded, err := decodeSecurityEventCursor(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_cursor", "cursor is invalid")
			return
		}
		cursor = &decoded
	}
	page, err := s.store.ListSecurityEvents(r.Context(), deviceID, eventType, cursor, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	next := ""
	if page.NextCursor != nil {
		next = encodeSecurityEventCursor(*page.NextCursor)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": page.Items, "nextCursor": next})
}

func validSecurityEventFilterType(eventType string) bool {
	return validSecurityEventType(eventType) || eventType == store.SecurityEventTypeCorrelationCapacityDegraded
}

func encodeSecurityEventCursor(cursor store.SecurityEventCursor) string {
	raw, _ := json.Marshal(securityEventCursorWire{OccurredAt: cursor.OccurredAt.UTC().Format(time.RFC3339Nano), DeviceID: cursor.DeviceID, ID: cursor.ID})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeSecurityEventCursor(raw string) (store.SecurityEventCursor, error) {
	if len(raw) > 1024 {
		return store.SecurityEventCursor{}, errors.New("cursor is too long")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) == 0 || len(decoded) > 512 {
		return store.SecurityEventCursor{}, errors.New("invalid cursor encoding")
	}
	var wire securityEventCursorWire
	decoder := json.NewDecoder(strings.NewReader(string(decoded)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&wire); err != nil {
		return store.SecurityEventCursor{}, err
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return store.SecurityEventCursor{}, errors.New("invalid trailing cursor data")
	}
	occurredAt, err := time.Parse(time.RFC3339Nano, wire.OccurredAt)
	if err != nil || !validAgentIdentifier(wire.DeviceID) || !validAgentIdentifier(wire.ID) {
		return store.SecurityEventCursor{}, errors.New("invalid cursor values")
	}
	return store.SecurityEventCursor{OccurredAt: occurredAt.UTC(), DeviceID: wire.DeviceID, ID: wire.ID}, nil
}

func (s *Server) getDefensePolicy(w http.ResponseWriter, r *http.Request) {
	x, err := s.store.DefensePolicy(r.Context(), r.PathValue("id"), s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, x)
}
func (s *Server) putDefensePolicy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled          bool     `json:"enabled"`
		EmergencyStop    bool     `json:"emergencyStop"`
		AutoBan          bool     `json:"autoBan"`
		FailureThreshold int      `json:"failureThreshold"`
		Window           string   `json:"window"`
		BanDuration      string   `json:"banDuration"`
		MaxBansPerHour   int      `json:"maxBansPerHour"`
		Allowlist        []string `json:"allowlist"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	window, err := time.ParseDuration(in.Window)
	if err != nil {
		writeError(w, 400, "invalid_window", "invalid window duration")
		return
	}
	ban, err := time.ParseDuration(in.BanDuration)
	if err != nil {
		writeError(w, 400, "invalid_ban_duration", "invalid ban duration")
		return
	}
	if in.Allowlist == nil {
		in.Allowlist = []string{}
	}
	p := domain.DefensePolicy{DeviceID: r.PathValue("id"), Enabled: in.Enabled, EmergencyStop: in.EmergencyStop, AutoBan: in.AutoBan, FailureThreshold: in.FailureThreshold, Window: window, WindowText: window.String(), BanDuration: ban, BanDurationText: ban.String(), MaxBansPerHour: in.MaxBansPerHour, Allowlist: in.Allowlist, UpdatedAt: s.now().UTC()}
	if err = defense.ValidatePolicy(p); err != nil {
		writeError(w, 400, "invalid_policy", err.Error())
		return
	}
	device, err := s.store.Device(r.Context(), p.DeviceID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if device.ObserverOnly && p.AutoBan {
		writeError(w, http.StatusConflict, "observer_only_device", "automatic containment is unavailable for a read-only observer device")
		return
	}
	if _, err = s.store.PutDefensePolicyAndCancelQueued(r.Context(), p); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, p)
}
func (s *Server) simulateDefense(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SourceIP       string `json:"sourceIp"`
		FailureCount   int    `json:"failureCount"`
		RecentBanCount int    `json:"recentBanCount"`
		AlreadyBanned  bool   `json:"alreadyBanned"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if net.ParseIP(in.SourceIP) == nil || in.FailureCount < 0 || in.RecentBanCount < 0 {
		writeError(w, 400, "invalid_simulation", "invalid simulation values")
		return
	}
	p, err := s.store.DefensePolicy(r.Context(), r.PathValue("id"), s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, defense.Evaluate(p, in.SourceIP, in.FailureCount, in.RecentBanCount, in.AlreadyBanned, s.now()))
}
func (s *Server) emergencyStop(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Active bool `json:"active"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	p, err := s.store.DefensePolicy(r.Context(), r.PathValue("id"), s.now())
	if err != nil {
		s.fail(w, err)
		return
	}
	p.EmergencyStop = in.Active
	p.UpdatedAt = s.now().UTC()
	cancelled, err := s.store.PutDefensePolicyAndCancelQueued(r.Context(), p)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"deviceId": p.DeviceID, "emergencyStop": p.EmergencyStop, "cancelledQueuedActions": cancelled, "updatedAt": p.UpdatedAt})
}
