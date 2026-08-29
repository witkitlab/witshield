package agent

import (
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

type localSensorHealth struct {
	domain.SensorHealth
	failures int
}

func initialSensorHealth(observerOnly, hasJournal bool) map[string]*localSensorHealth {
	starting := func(id, name, mode string, cadence int) *localSensorHealth {
		return &localSensorHealth{SensorHealth: domain.SensorHealth{SensorID: id, Name: name, Mode: mode, State: domain.SensorDegraded, CadenceSeconds: cadence, Error: "等待首次成功采样"}}
	}
	authMode := "auth_log_fallback"
	if hasJournal {
		authMode = "journald"
	}
	items := map[string]*localSensorHealth{
		"authentication": starting("authentication", "登录与认证", authMode, 5),
		"host_baseline":  starting("host_baseline", "账号与持久化基线", "polling", 60),
		"network":        starting("network", "网络监听", "polling", 30),
		"process":        starting("process", "高风险进程", "procfs", 10),
		"runtime":        starting("runtime", "增强运行时行为", "falco_jsonl", 2),
	}
	items["runtime"].State = domain.SensorOptional
	items["runtime"].Error = "增强运行时传感器尚未接入；基础保护继续运行"
	if observerOnly {
		items["authentication"].State = domain.SensorOptional
		items["authentication"].Error = "Docker 观察模式不提供可信 journald 实时认证源"
		items["process"].Mode = "container_procfs"
	}
	return items
}

func (r *Runner) recordOptionalSensor(id, mode, message string) {
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	if item := r.sensors[id]; item != nil {
		item.Mode = mode
		item.State = domain.SensorOptional
		item.Error = safeSensorError(message)
		item.UpdatedAt = time.Now().UTC()
	}
}

func (r *Runner) recordSensor(id, mode string, sampleErr error, eventCount int, degraded bool) {
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	item, exists := r.sensors[id]
	if !exists {
		return
	}
	now := time.Now().UTC()
	item.Mode, item.UpdatedAt = mode, now
	if sampleErr != nil {
		item.failures++
		item.State = domain.SensorDegraded
		if item.failures >= 3 {
			item.State = domain.SensorUnavailable
		}
		item.Error = safeSensorError(sampleErr.Error())
		return
	}
	item.failures = 0
	item.LastSuccessAt = &now
	if eventCount > 0 {
		item.LastEventAt = &now
		item.EventCount += int64(eventCount)
	}
	if degraded {
		item.State = domain.SensorDegraded
		item.Error = "已降级到完整性较弱的兼容来源；该来源不能授权自动处置"
	} else {
		item.State = domain.SensorActive
		item.Error = ""
	}
}

func safeSensorError(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(value))
	if len(value) > 500 {
		value = value[:500]
	}
	return value
}

func (r *Runner) sensorSnapshot() []domain.SensorHealth {
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	order := []string{"authentication", "host_baseline", "network", "process", "runtime"}
	out := make([]domain.SensorHealth, 0, len(r.sensors))
	for _, id := range order {
		if item := r.sensors[id]; item != nil {
			out = append(out, item.SensorHealth)
		}
	}
	return out
}
