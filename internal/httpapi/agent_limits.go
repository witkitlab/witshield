package httpapi

import (
	"sync"
	"time"
)

// windowLimiter is an in-memory admission guard. Durable credentials remain
// the authentication authority; this guard prevents one credential or source
// from monopolizing SQLite and HTTP connections before normal validation.
type windowLimiter struct {
	mu        sync.Mutex
	attempts  map[string][]time.Time
	window    time.Duration
	lastSweep time.Time
	maxKeys   int
}

type weightedAttempt struct {
	at   time.Time
	cost int
}

// weightedWindowLimiter bounds authenticated work rather than only HTTP
// requests. Agent endpoints accept batches, so counting a 500-event request as
// one request would leave a large amplification path into the single SQLite
// writer. Device and Controller-wide budgets are consumed atomically.
type weightedWindowLimiter struct {
	mu        sync.Mutex
	attempts  map[string][]weightedAttempt
	window    time.Duration
	maxKeys   int
	lastSweep time.Time
}

func newWeightedWindowLimiter(window time.Duration, maxKeys int) *weightedWindowLimiter {
	return &weightedWindowLimiter{attempts: map[string][]weightedAttempt{}, window: window, maxKeys: maxKeys}
}

func (l *weightedWindowLimiter) allowDeviceAndGlobal(deviceID string, now time.Time, cost, deviceLimit, globalLimit int) bool {
	if deviceID == "" || cost <= 0 || deviceLimit <= 0 || globalLimit <= 0 || cost > deviceLimit || cost > globalLimit {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := now.Add(-l.window)
	if l.lastSweep.IsZero() || now.Sub(l.lastSweep) >= time.Minute {
		for key, attempts := range l.attempts {
			alive := attempts[:0]
			for _, attempt := range attempts {
				if attempt.at.After(cut) {
					alive = append(alive, attempt)
				}
			}
			if len(alive) == 0 {
				delete(l.attempts, key)
			} else {
				l.attempts[key] = alive
			}
		}
		l.lastSweep = now
	}
	deviceKey := "device:" + deviceID
	globalKey := "global"
	if _, exists := l.attempts[deviceKey]; !exists && len(l.attempts) >= l.maxKeys {
		return false
	}
	prune := func(key string) (int, []weightedAttempt) {
		alive := l.attempts[key][:0]
		total := 0
		for _, attempt := range l.attempts[key] {
			if attempt.at.After(cut) {
				alive = append(alive, attempt)
				total += attempt.cost
			}
		}
		if len(alive) == 0 {
			delete(l.attempts, key)
		} else {
			l.attempts[key] = alive
		}
		return total, alive
	}
	deviceUsed, deviceAttempts := prune(deviceKey)
	globalUsed, globalAttempts := prune(globalKey)
	if deviceUsed+cost > deviceLimit || globalUsed+cost > globalLimit {
		return false
	}
	attempt := weightedAttempt{at: now, cost: cost}
	l.attempts[deviceKey] = append(deviceAttempts, attempt)
	l.attempts[globalKey] = append(globalAttempts, attempt)
	return true
}

func newWindowLimiter(window time.Duration, maxKeys int) *windowLimiter {
	return &windowLimiter{attempts: map[string][]time.Time{}, window: window, maxKeys: maxKeys}
}

func (l *windowLimiter) allow(key string, now time.Time, limit int) bool {
	return l.allowInternal(key, now, limit, false)
}

// allowEvicting is for unauthenticated source-address guards. At key capacity
// it evicts one old bucket instead of turning map saturation into a global
// denial of service against a legitimate new source. Durable credential,
// signature, weighted-work and Store limits remain the actual authority.
func (l *windowLimiter) allowEvicting(key string, now time.Time, limit int) bool {
	return l.allowInternal(key, now, limit, true)
}

func (l *windowLimiter) allowInternal(key string, now time.Time, limit int, evict bool) bool {
	if key == "" || limit <= 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := now.Add(-l.window)
	if l.lastSweep.IsZero() || now.Sub(l.lastSweep) >= time.Minute {
		for candidate, attempts := range l.attempts {
			alive := attempts[:0]
			for _, attempt := range attempts {
				if attempt.After(cut) {
					alive = append(alive, attempt)
				}
			}
			if len(alive) == 0 {
				delete(l.attempts, candidate)
			} else {
				l.attempts[candidate] = alive
			}
		}
		l.lastSweep = now
	}
	if _, exists := l.attempts[key]; !exists && len(l.attempts) >= l.maxKeys {
		if !evict {
			return false
		}
		for candidate := range l.attempts {
			delete(l.attempts, candidate)
			break
		}
	}
	alive := l.attempts[key][:0]
	for _, attempt := range l.attempts[key] {
		if attempt.After(cut) {
			alive = append(alive, attempt)
		}
	}
	if len(alive) >= limit {
		l.attempts[key] = alive
		return false
	}
	l.attempts[key] = append(alive, now)
	return true
}

type syncGate struct {
	mu     sync.Mutex
	active map[string]struct{}
	global chan struct{}
}

func newSyncGate(maxGlobal int) *syncGate {
	return &syncGate{active: map[string]struct{}{}, global: make(chan struct{}, maxGlobal)}
}

func (g *syncGate) begin(deviceID string) (func(), string) {
	g.mu.Lock()
	if _, exists := g.active[deviceID]; exists {
		g.mu.Unlock()
		return nil, "device"
	}
	g.active[deviceID] = struct{}{}
	g.mu.Unlock()

	select {
	case g.global <- struct{}{}:
		return func() {
			<-g.global
			g.mu.Lock()
			delete(g.active, deviceID)
			g.mu.Unlock()
		}, ""
	default:
		g.mu.Lock()
		delete(g.active, deviceID)
		g.mu.Unlock()
		return nil, "global"
	}
}
