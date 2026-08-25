package httpapi

import (
	"net"
	"testing"
	"time"
)

func TestWindowLimiterBoundsAndExpiresKeys(t *testing.T) {
	limiter := newWindowLimiter(time.Minute, 2)
	now := time.Now().UTC()
	if !limiter.allow("one", now, 2) {
		t.Fatal("first valid request was rejected")
	}
	if !limiter.allow("one", now, 2) {
		t.Fatal("second valid request was rejected")
	}
	if limiter.allow("one", now, 2) {
		t.Fatal("per-key request ceiling was not enforced")
	}
	if !limiter.allow("two", now, 2) || limiter.allow("three", now, 2) {
		t.Fatal("source-key capacity was not enforced")
	}
	if !limiter.allow("three", now.Add(2*time.Minute), 2) {
		t.Fatal("expired source keys were not released")
	}
}

func TestUntrustedSourceLimiterSaturationCannotRejectARealNewSource(t *testing.T) {
	limiter := newWindowLimiter(time.Minute, 2)
	now := time.Now().UTC()
	if !limiter.allowEvicting("attacker-one", now, 1) || !limiter.allowEvicting("attacker-two", now, 1) {
		t.Fatal("could not fill source limiter")
	}
	if !limiter.allowEvicting("legitimate-new-source", now, 1) {
		t.Fatal("source-key saturation became a global denial of service")
	}
	first := agentSourceLimitKey(net.ParseIP("2001:db8:1234:5678::1"))
	second := agentSourceLimitKey(net.ParseIP("2001:db8:1234:5678::ffff"))
	other := agentSourceLimitKey(net.ParseIP("2001:db8:1234:5679::1"))
	if first != second || first == other {
		t.Fatalf("IPv6 source aggregation is incorrect: %q %q %q", first, second, other)
	}
}

func TestWeightedLimiterAtomicallyBoundsAmplifiedWorkAndExpiresDeviceKeys(t *testing.T) {
	limiter := newWeightedWindowLimiter(time.Second, 3) // global plus two devices
	now := time.Now().UTC()
	if !limiter.allowDeviceAndGlobal("one", now, 6, 10, 20) {
		t.Fatal("first weighted request was rejected")
	}
	if limiter.allowDeviceAndGlobal("one", now, 5, 10, 20) {
		t.Fatal("per-device work ceiling was not enforced")
	}
	if !limiter.allowDeviceAndGlobal("two", now, 10, 10, 20) {
		t.Fatal("second device within global budget was rejected")
	}
	if limiter.allowDeviceAndGlobal("three", now, 1, 10, 20) {
		t.Fatal("device-key capacity was not enforced")
	}
	// A periodic global sweep must remove silent device keys; otherwise churn
	// would permanently reject every device enrolled after maxKeys was reached.
	if !limiter.allowDeviceAndGlobal("three", now.Add(2*time.Minute), 10, 10, 20) {
		t.Fatal("expired weighted device keys were not released")
	}
	if limiter.allowDeviceAndGlobal("four", now.Add(2*time.Minute), 11, 10, 20) {
		t.Fatal("a single request larger than its device budget was accepted")
	}
}

func TestSyncGateAllowsOnlyOnePollPerDeviceAndBoundsGlobalUse(t *testing.T) {
	gate := newSyncGate(1)
	release, blocked := gate.begin("device-one")
	if release == nil || blocked != "" {
		t.Fatalf("first sync rejected: %s", blocked)
	}
	if duplicate, reason := gate.begin("device-one"); duplicate != nil || reason != "device" {
		t.Fatalf("duplicate sync result=%v reason=%q", duplicate != nil, reason)
	}
	if second, reason := gate.begin("device-two"); second != nil || reason != "global" {
		t.Fatalf("global sync result=%v reason=%q", second != nil, reason)
	}
	release()
	if next, reason := gate.begin("device-two"); next == nil || reason != "" {
		t.Fatalf("released sync capacity was not reusable: %q", reason)
	} else {
		next()
	}
}
