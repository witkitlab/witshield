package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/store"
)

const (
	securityEngineerPollInterval = 20 * time.Second
	securityEngineerRetryDelay   = 15 * time.Minute
)

// RunSecurityEngineerWorker turns enabled assist modes into a resident service:
// deterministic sensors open incidents, and this worker investigates eligible
// incidents without granting the model any direct host or action capability.
func (s *Server) RunSecurityEngineerWorker(ctx context.Context) error {
	ticker := time.NewTicker(securityEngineerPollInterval)
	defer ticker.Stop()
	for {
		s.runSecurityEngineerCycle(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Server) runSecurityEngineerCycle(ctx context.Context) {
	now := s.now().UTC()
	if _, err := s.store.RecoverStaleInvestigations(ctx, now.Add(-2*time.Minute), now); err != nil {
		if !errors.Is(err, context.Canceled) {
			s.log.Error("security engineer stale investigation recovery failed", "error", "investigation lease maintenance failed")
		}
		return
	}
	if _, err := s.store.AISettings(ctx); err != nil {
		if !errors.Is(err, store.ErrNotFound) && !errors.Is(err, context.Canceled) {
			s.log.Error("security engineer AI settings unavailable", "error", "stored AI configuration could not be read")
		}
		return
	}
	incidents, err := s.store.ListIncidents(ctx, "", []domain.IncidentStatus{domain.IncidentOpen}, 20)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.log.Error("security engineer incident queue unavailable", "error", "open incidents could not be read")
		}
		return
	}
	processed := 0
	for _, incident := range incidents {
		if ctx.Err() != nil || processed >= 3 {
			return
		}
		if incident.LastInvestigatedAt != nil && now.Sub(*incident.LastInvestigatedAt) < securityEngineerRetryDelay {
			continue
		}
		grants, grantErr := s.store.ListPolicyGrants(ctx, incident.DeviceID, now)
		if grantErr != nil {
			s.log.Error("security engineer policy boundary unavailable", "incidentId", incident.ID, "error", "policy grants could not be read")
			continue
		}
		if !automaticInvestigationAllowed(incident, grants) {
			continue
		}
		processed++
		if _, _, runErr := s.performIncidentInvestigation(ctx, incident.ID, "policy_grant"); runErr != nil && !errors.Is(runErr, store.ErrConflict) && !errors.Is(runErr, context.Canceled) {
			s.log.Warn("security engineer investigation failed", "incidentId", incident.ID, "error", "investigation did not complete")
		}
	}
}

func automaticInvestigationAllowed(incident domain.Incident, grants []domain.PolicyGrant) bool {
	capability := incidentCapability(incident.Category)
	for _, grant := range grants {
		if grant.Capability != capability || !grant.Enabled || grant.EmergencyStop || grant.Mode == domain.AutonomyObserve {
			continue
		}
		if incident.Severity == domain.SeverityInfo || incident.Severity == domain.SeverityLow {
			return grant.Mode == domain.AutonomyEnhanced
		}
		return true
	}
	return false
}

func incidentCapability(category string) string {
	switch category {
	case "identity_access":
		return "network.auth_bruteforce"
	case "identity_persistence", "persistence", "ssh":
		return "identity.persistence"
	case "file_integrity", "permissions":
		return "file.integrity"
	case "updates", "packages", "vulnerability", "vulnerabilities":
		return "vulnerability.remediation"
	default:
		return "workload.runtime"
	}
}
