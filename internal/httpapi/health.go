package httpapi

import (
	"net/http"
	"sort"
	"time"
)

type workerHealth struct {
	LastRunAt     time.Time
	LastSuccessAt time.Time
	LastError     string
	StaleAfter    time.Duration
}

type workerHealthView struct {
	Name          string    `json:"name"`
	Status        string    `json:"status"`
	LastRunAt     time.Time `json:"lastRunAt"`
	LastSuccessAt time.Time `json:"lastSuccessAt"`
	Error         string    `json:"error,omitempty"`
	StaleAfter    int       `json:"staleAfterSeconds"`
}

// MarkWorkerHealth records bounded operational state without retaining raw
// endpoint, SQL, or peer errors that could leak through the administrator API.
func (s *Server) MarkWorkerHealth(name string, err error) {
	now := s.now().UTC()
	s.healthMu.Lock()
	state, ok := s.workers[name]
	if !ok {
		state.StaleAfter = 3 * time.Minute
	}
	state.LastRunAt = now
	if err == nil {
		state.LastSuccessAt = now
		state.LastError = ""
	} else {
		state.LastError = "worker cycle failed"
	}
	s.workers[name] = state
	s.healthMu.Unlock()
}

func (s *Server) healthSnapshot(now time.Time) (string, []workerHealthView) {
	s.healthMu.RLock()
	views := make([]workerHealthView, 0, len(s.workers))
	for name, state := range s.workers {
		status := "ok"
		errorText := state.LastError
		if state.LastRunAt.IsZero() {
			status = "starting"
			errorText = "worker has not completed its first cycle"
		} else if state.StaleAfter <= 0 || now.Sub(state.LastRunAt) > state.StaleAfter {
			status = "stale"
			errorText = "worker heartbeat is stale"
		} else if state.LastError != "" && state.LastSuccessAt.Before(state.LastRunAt) {
			status = "degraded"
		}
		views = append(views, workerHealthView{Name: name, Status: status, LastRunAt: state.LastRunAt, LastSuccessAt: state.LastSuccessAt, Error: errorText, StaleAfter: int(state.StaleAfter / time.Second)})
	}
	s.healthMu.RUnlock()
	sort.Slice(views, func(i, j int) bool { return views[i].Name < views[j].Name })
	overall := "ok"
	for _, view := range views {
		if view.Status != "ok" {
			overall = "degraded"
			break
		}
	}
	return overall, views
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database_unavailable", "database unavailable")
		return
	}
	status, _ := s.healthSnapshot(s.now().UTC())
	if status != "ok" {
		writeError(w, http.StatusServiceUnavailable, "background_workers_unhealthy", "one or more required background workers are unhealthy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) systemHealth(w http.ResponseWriter, r *http.Request) {
	database := "ok"
	if err := s.store.Ping(r.Context()); err != nil {
		database = "unavailable"
	}
	status, workers := s.healthSnapshot(s.now().UTC())
	if database != "ok" {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "database": database, "workers": workers, "checkedAt": s.now().UTC()})
}
