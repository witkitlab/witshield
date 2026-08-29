package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

const maxSensorHealthBatch = 32

func validateInvestigationPolicy(policy domain.AIInvestigationPolicy) error {
	switch policy.Profile {
	case domain.InvestigationEconomy, domain.InvestigationBalanced, domain.InvestigationSensitive:
	default:
		return errors.New("unsupported investigation profile")
	}
	if policy.DailyTokenBudget < 1_000 || policy.DailyTokenBudget > 2_000_000 {
		return errors.New("dailyTokenBudget must be between 1000 and 2000000")
	}
	if policy.EmergencyReserveTokens < 0 || policy.EmergencyReserveTokens > 500_000 {
		return errors.New("emergencyReserveTokens must be between 0 and 500000")
	}
	return nil
}

func (s *Store) AIInvestigationPolicy(ctx context.Context) (domain.AIInvestigationPolicy, error) {
	var item domain.AIInvestigationPolicy
	var updated string
	err := s.db.QueryRowContext(ctx, `SELECT profile,daily_token_budget,emergency_reserve_tokens,share_network_indicators,share_account_names,updated_at FROM ai_investigation_policy WHERE singleton=1`).Scan(
		&item.Profile, &item.DailyTokenBudget, &item.EmergencyReserveTokens, &item.ShareNetworkIndicators, &item.ShareAccountNames, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return item, ErrNotFound
	}
	if err != nil {
		return item, err
	}
	item.UpdatedAt, err = parseTime(updated)
	return item, err
}

func (s *Store) PutAIInvestigationPolicy(ctx context.Context, item domain.AIInvestigationPolicy) error {
	if err := validateInvestigationPolicy(item); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO ai_investigation_policy(singleton,profile,daily_token_budget,emergency_reserve_tokens,share_network_indicators,share_account_names,updated_at)
		VALUES(1,?,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET profile=excluded.profile,daily_token_budget=excluded.daily_token_budget,
		emergency_reserve_tokens=excluded.emergency_reserve_tokens,share_network_indicators=excluded.share_network_indicators,
		share_account_names=excluded.share_account_names,updated_at=excluded.updated_at`, item.Profile, item.DailyTokenBudget,
		item.EmergencyReserveTokens, item.ShareNetworkIndicators, item.ShareAccountNames, timeText(item.UpdatedAt))
	return err
}

func investigationUsageDay(now time.Time) string { return now.UTC().Format("2006-01-02") }

func (s *Store) AIInvestigationUsage(ctx context.Context, now time.Time) (domain.AIInvestigationUsage, error) {
	item := domain.AIInvestigationUsage{Day: investigationUsageDay(now), UpdatedAt: now.UTC()}
	var updated string
	err := s.db.QueryRowContext(ctx, `SELECT regular_tokens_used,emergency_tokens_used,investigation_calls,updated_at FROM ai_investigation_usage WHERE usage_day=?`, item.Day).Scan(
		&item.RegularTokensUsed, &item.EmergencyTokensUsed, &item.InvestigationCalls, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return item, nil
	}
	if err != nil {
		return item, err
	}
	item.UpdatedAt, err = parseTime(updated)
	return item, err
}

// ReserveAIInvestigationBudget atomically reserves a conservative token
// estimate before the upstream request. Failed or timed-out requests remain
// charged because compatible upstreams may have processed them before the
// connection failed. Critical incidents may use the protected reserve only
// after the regular budget cannot accommodate the request.
func (s *Store) ReserveAIInvestigationBudget(ctx context.Context, severity domain.Severity, estimatedTokens int, now time.Time) (domain.AIInvestigationUsage, string, error) {
	var usage domain.AIInvestigationUsage
	if estimatedTokens < 1 || estimatedTokens > 100_000 {
		return usage, "", errors.New("investigation token estimate is outside the safe bound")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return usage, "", err
	}
	defer tx.Rollback()
	var policy domain.AIInvestigationPolicy
	if err = tx.QueryRowContext(ctx, `SELECT profile,daily_token_budget,emergency_reserve_tokens,share_network_indicators,share_account_names,updated_at FROM ai_investigation_policy WHERE singleton=1`).Scan(
		&policy.Profile, &policy.DailyTokenBudget, &policy.EmergencyReserveTokens, &policy.ShareNetworkIndicators, &policy.ShareAccountNames, &sql.NullString{}); err != nil {
		return usage, "", err
	}
	usage.Day, usage.UpdatedAt = investigationUsageDay(now), now.UTC()
	var updated sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT regular_tokens_used,emergency_tokens_used,investigation_calls,updated_at FROM ai_investigation_usage WHERE usage_day=?`, usage.Day).Scan(
		&usage.RegularTokensUsed, &usage.EmergencyTokensUsed, &usage.InvestigationCalls, &updated)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return usage, "", err
	}
	lane := "regular"
	if usage.RegularTokensUsed+estimatedTokens <= policy.DailyTokenBudget {
		usage.RegularTokensUsed += estimatedTokens
	} else if severity == domain.SeverityCritical && usage.EmergencyTokensUsed+estimatedTokens <= policy.EmergencyReserveTokens {
		lane = "emergency"
		usage.EmergencyTokensUsed += estimatedTokens
	} else {
		return usage, "", ErrAIBudgetExhausted
	}
	usage.InvestigationCalls++
	if _, err = tx.ExecContext(ctx, `INSERT INTO ai_investigation_usage(usage_day,regular_tokens_used,emergency_tokens_used,investigation_calls,updated_at)
		VALUES(?,?,?,?,?) ON CONFLICT(usage_day) DO UPDATE SET regular_tokens_used=excluded.regular_tokens_used,
		emergency_tokens_used=excluded.emergency_tokens_used,investigation_calls=excluded.investigation_calls,updated_at=excluded.updated_at`,
		usage.Day, usage.RegularTokensUsed, usage.EmergencyTokensUsed, usage.InvestigationCalls, timeText(usage.UpdatedAt)); err != nil {
		return usage, "", err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM ai_investigation_usage WHERE usage_day<?`, now.UTC().AddDate(0, 0, -31).Format("2006-01-02")); err != nil {
		return usage, "", err
	}
	if err = tx.Commit(); err != nil {
		return usage, "", err
	}
	return usage, lane, nil
}

func validSensorState(state domain.SensorState) bool {
	switch state {
	case domain.SensorActive, domain.SensorDegraded, domain.SensorUnavailable, domain.SensorOptional:
		return true
	default:
		return false
	}
}

func (s *Store) PutSensorHealth(ctx context.Context, deviceID string, items []domain.SensorHealth, now time.Time) error {
	if deviceID == "" || len(items) == 0 || len(items) > maxSensorHealthBatch {
		return errors.New("sensor health batch is invalid")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		item.SensorID, item.Name, item.Mode, item.Error = strings.TrimSpace(item.SensorID), strings.TrimSpace(item.Name), strings.TrimSpace(item.Mode), strings.TrimSpace(item.Error)
		if item.SensorID == "" || len(item.SensorID) > 64 || item.Name == "" || len(item.Name) > 100 || item.Mode == "" || len(item.Mode) > 32 || !validSensorState(item.State) || item.CadenceSeconds < 1 || item.CadenceSeconds > 86400 || item.EventCount < 0 || len(item.Error) > 500 {
			return errors.New("sensor health item is invalid")
		}
		if _, exists := seen[item.SensorID]; exists {
			return errors.New("sensor health batch contains a duplicate")
		}
		seen[item.SensorID] = struct{}{}
		var success, event any
		if item.LastSuccessAt != nil {
			success = timeText(*item.LastSuccessAt)
		}
		if item.LastEventAt != nil {
			event = timeText(*item.LastEventAt)
		}
		var previous domain.SensorState
		previousKnown := true
		if scanErr := tx.QueryRowContext(ctx, `SELECT state FROM sensor_health WHERE device_id=? AND sensor_id=?`, deviceID, item.SensorID).Scan(&previous); errors.Is(scanErr, sql.ErrNoRows) {
			previousKnown = false
		} else if scanErr != nil {
			return scanErr
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO sensor_health(device_id,sensor_id,name,mode,state,cadence_seconds,last_success_at,last_event_at,event_count,error,updated_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(device_id,sensor_id) DO UPDATE SET name=excluded.name,mode=excluded.mode,state=excluded.state,
			cadence_seconds=excluded.cadence_seconds,last_success_at=excluded.last_success_at,last_event_at=excluded.last_event_at,
			event_count=excluded.event_count,error=excluded.error,updated_at=excluded.updated_at`, deviceID, item.SensorID, item.Name, item.Mode,
			item.State, item.CadenceSeconds, success, event, item.EventCount, item.Error, timeText(now)); err != nil {
			return err
		}
		degraded := item.State == domain.SensorDegraded || item.State == domain.SensorUnavailable
		wasDegraded := previous == domain.SensorDegraded || previous == domain.SensorUnavailable
		if previousKnown && degraded != wasDegraded {
			eventType, severity, summary := "sensor_health_restored", domain.SeverityInfo, "安全传感器已恢复"
			if degraded {
				eventType, severity, summary = "sensor_health_degraded", domain.SeverityHigh, "安全传感器持续失效"
			}
			payload, _ := json.Marshal(map[string]any{"sensorId": item.SensorID, "state": item.State, "error": item.Error, "cadenceSeconds": item.CadenceSeconds})
			signal := domain.Signal{ID: "sensor:" + deviceID + ":" + item.SensorID + ":" + eventType + ":" + now.UTC().Format("20060102T150405.000000000"), DeviceID: deviceID, Type: eventType, Category: "sensor_health", Severity: severity, Trust: "verified", Subject: item.SensorID, Summary: summary + "：" + item.Name, Source: "controller_health", SourceRef: item.SensorID, Payload: payload, OccurredAt: now.UTC(), IngestedAt: now.UTC()}
			incident, _, signalErr := s.upsertSignalIncidentTx(ctx, tx, signal, "sensor-health:"+deviceID+":"+item.SensorID)
			if signalErr != nil {
				return signalErr
			}
			if !degraded {
				if _, signalErr = tx.ExecContext(ctx, `UPDATE incidents SET status='monitoring',summary=?,updated_at=? WHERE id=? AND status NOT IN ('resolved','dismissed')`, summary+"："+item.Name, timeText(now), incident.ID); signalErr != nil {
					return signalErr
				}
			} else {
				notice := domain.NotificationEvent{ID: "sensor:" + signal.ID, Type: "sensor_health", Severity: domain.SeverityHigh, DeviceID: deviceID, Title: summary, Message: item.Name + " 当前不可提供完整覆盖，请检查 Agent 与本机数据源。", OccurredAt: now.UTC()}
				if _, signalErr = enqueueNotificationTx(ctx, tx, notice, now); signalErr != nil {
					return signalErr
				}
			}
		}
	}
	return tx.Commit()
}

func (s *Store) ListSensorHealth(ctx context.Context, deviceID string) ([]domain.SensorHealth, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT device_id,sensor_id,name,mode,state,cadence_seconds,last_success_at,last_event_at,event_count,error,updated_at
		FROM sensor_health WHERE (?='' OR device_id=?) ORDER BY device_id,sensor_id`, deviceID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.SensorHealth
	for rows.Next() {
		var item domain.SensorHealth
		var success, event sql.NullString
		var updated string
		if err = rows.Scan(&item.DeviceID, &item.SensorID, &item.Name, &item.Mode, &item.State, &item.CadenceSeconds, &success, &event, &item.EventCount, &item.Error, &updated); err != nil {
			return nil, err
		}
		if item.LastSuccessAt, err = nullableTime(success); err != nil {
			return nil, err
		}
		if item.LastEventAt, err = nullableTime(event); err != nil {
			return nil, err
		}
		if item.UpdatedAt, err = parseTime(updated); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
