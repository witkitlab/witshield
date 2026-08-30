package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
	"github.com/witkitlab/witshield/internal/store"
)

const (
	securityEngineerPollInterval = 5 * time.Second
	securityEngineerDebounce     = 10 * time.Second
)

// RunSecurityEngineerWorker turns enabled assist modes into a resident service:
// deterministic sensors open incidents, and this worker investigates eligible
// incidents without granting the model any direct host or action capability.
func (s *Server) RunSecurityEngineerWorker(ctx context.Context) error {
	ticker := time.NewTicker(securityEngineerPollInterval)
	defer ticker.Stop()
	for {
		// A normal investigation may hold the cycle for up to 90 seconds. Record
		// liveness before entering it so readiness does not mistake useful work for
		// a dead worker.
		s.MarkWorkerHealth("security_engineer", nil)
		s.MarkWorkerHealth("security_engineer", s.runSecurityEngineerCycle(ctx))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Server) runSecurityEngineerCycle(ctx context.Context) error {
	now := s.now().UTC()
	if _, err := s.store.RecoverStaleInvestigations(ctx, now.Add(-2*time.Minute), now); err != nil {
		if !errors.Is(err, context.Canceled) {
			s.log.Error("security engineer stale investigation recovery failed", "error", "investigation lease maintenance failed")
		}
		return err
	}
	if _, err := s.store.AISettings(ctx); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// AI is optional. Deterministic scanning and rule-based containment are
			// healthy while the administrator has not configured a provider.
			return nil
		}
		if !errors.Is(err, context.Canceled) {
			s.log.Error("security engineer AI settings unavailable", "error", "stored AI configuration could not be read")
		}
		return err
	}
	policy, err := s.store.AIInvestigationPolicy(ctx)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.log.Error("security engineer investigation policy unavailable", "error", "investigation policy could not be read")
		}
		return err
	}
	incidents, err := s.store.ListIncidents(ctx, "", []domain.IncidentStatus{domain.IncidentOpen}, 20)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.log.Error("security engineer incident queue unavailable", "error", "open incidents could not be read")
		}
		return err
	}
	processed := 0
	var cycleErrors []error
	for _, incident := range incidents {
		if ctx.Err() != nil || processed >= 3 {
			break
		}
		if incident.LastInvestigatedAt != nil {
			// An open incident is not a timer. Re-run only when a sensor attached
			// genuinely newer evidence; debounce a burst into one investigation.
			if !incident.LastSeenAt.After(*incident.LastInvestigatedAt) || now.Sub(incident.LastSeenAt) < securityEngineerDebounce {
				continue
			}
		}
		grants, grantErr := s.store.ListPolicyGrants(ctx, incident.DeviceID, now)
		if grantErr != nil {
			s.log.Error("security engineer policy boundary unavailable", "incidentId", incident.ID, "error", "policy grants could not be read")
			cycleErrors = append(cycleErrors, grantErr)
			continue
		}
		if !automaticInvestigationAllowed(incident, grants) {
			continue
		}
		if !investigationProfileAllows(policy.Profile, incident.Severity) {
			continue
		}
		processed++
		if _, _, runErr := s.performIncidentInvestigation(ctx, incident.ID, "policy_grant"); runErr != nil && !errors.Is(runErr, store.ErrConflict) && !errors.Is(runErr, context.Canceled) {
			s.log.Warn("security engineer investigation failed", "incidentId", incident.ID, "error", "investigation did not complete")
			cycleErrors = append(cycleErrors, runErr)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return errors.Join(cycleErrors...)
}

func investigationProfileAllows(profile domain.InvestigationProfile, severity domain.Severity) bool {
	switch profile {
	case domain.InvestigationEconomy:
		return severity == domain.SeverityCritical
	case domain.InvestigationSensitive:
		return severity != domain.SeverityInfo
	default:
		return severity == domain.SeverityMedium || severity == domain.SeverityHigh || severity == domain.SeverityCritical
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
