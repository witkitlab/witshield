package defense

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

// MaxFailureThreshold bounds the exact per-source sliding-window history kept
// by the Controller. Values above 100 are operationally poor brute-force
// signals and would let a compromised Agent inflate persistent state.
const MaxFailureThreshold = 100
const MaxAutomaticBansPerHour = 100

type Evaluation struct {
	Matched   bool       `json:"matched"`
	ShouldBan bool       `json:"shouldBan"`
	Simulated bool       `json:"simulated"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

func ValidatePolicy(p domain.DefensePolicy) error {
	if p.FailureThreshold < 3 || p.FailureThreshold > MaxFailureThreshold {
		return fmt.Errorf("failureThreshold must be between 3 and %d", MaxFailureThreshold)
	}
	if p.Window < 10*time.Second || p.Window > 24*time.Hour {
		return fmt.Errorf("window must be between 10s and 24h")
	}
	if p.BanDuration < time.Minute || p.BanDuration > 24*time.Hour {
		return fmt.Errorf("banDuration must be between 1m and 24h")
	}
	if p.MaxBansPerHour < 1 || p.MaxBansPerHour > MaxAutomaticBansPerHour {
		return fmt.Errorf("maxBansPerHour must be between 1 and %d", MaxAutomaticBansPerHour)
	}
	for _, entry := range p.Allowlist {
		if _, _, err := net.ParseCIDR(entry); err != nil {
			if net.ParseIP(entry) == nil {
				return fmt.Errorf("invalid allowlist entry %q", entry)
			}
		}
	}
	if p.AutoBan && !hasNonLoopbackAllowlist(p.Allowlist) {
		return fmt.Errorf("autoBan requires an explicit non-loopback administrator IP or network in allowlist")
	}
	return nil
}

func hasNonLoopbackAllowlist(entries []string) bool {
	for _, entry := range entries {
		if ip := net.ParseIP(entry); ip != nil {
			if !ip.IsLoopback() && !ip.IsUnspecified() {
				return true
			}
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil && !network.IP.IsLoopback() && !network.IP.IsUnspecified() {
			return true
		}
	}
	return false
}

func Evaluate(p domain.DefensePolicy, sourceIP string, failureCount, recentBanCount int, alreadyBanned bool, now time.Time) Evaluation {
	ip := net.ParseIP(strings.TrimSpace(sourceIP))
	if ip == nil {
		return Evaluation{Reason: "invalid source IP"}
	}
	if allowlisted(ip, p.Allowlist) {
		return Evaluation{Reason: "source is allowlisted"}
	}
	if !p.Enabled {
		return Evaluation{Reason: "defense policy is disabled"}
	}
	if p.EmergencyStop {
		return Evaluation{Reason: "emergency stop is active"}
	}
	if failureCount < p.FailureThreshold {
		return Evaluation{Reason: fmt.Sprintf("threshold not met (%d/%d)", failureCount, p.FailureThreshold)}
	}
	if alreadyBanned {
		return Evaluation{Matched: true, Reason: "source already has an active ban"}
	}
	if recentBanCount >= p.MaxBansPerHour {
		return Evaluation{Matched: true, Reason: "hourly ban safety limit reached"}
	}
	expires := now.Add(p.BanDuration).UTC()
	return Evaluation{Matched: true, ShouldBan: p.AutoBan, Simulated: !p.AutoBan, Reason: "SSH authentication failure threshold reached", ExpiresAt: &expires}
}
func allowlisted(ip net.IP, entries []string) bool {
	for _, x := range entries {
		if parsed := net.ParseIP(x); parsed != nil && parsed.Equal(ip) {
			return true
		}
		if _, network, err := net.ParseCIDR(x); err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func DefaultPolicy(deviceID string, now time.Time) domain.DefensePolicy {
	return domain.DefensePolicy{DeviceID: deviceID, Enabled: false, AutoBan: false, FailureThreshold: 10, Window: 5 * time.Minute, WindowText: "5m", BanDuration: 15 * time.Minute, BanDurationText: "15m", MaxBansPerHour: 10, Allowlist: []string{"127.0.0.0/8", "::1/128"}, UpdatedAt: now.UTC()}
}
