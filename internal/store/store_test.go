package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/witkitlab/witshield/internal/domain"
)

func TestSingleAdminBootstrapIsAtomic(t *testing.T) {
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var success atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.CreateAdmin(context.Background(), fmt.Sprintf("admin-%d", i), "hash", time.Now()); err == nil {
				success.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("successful admins=%d", success.Load())
	}
	count, err := s.AdminCount(context.Background())
	if err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestEnrollmentChallengeIdentityAndTokenWideCaps(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	if err = s.CreateEnrollmentToken(ctx, domain.EnrollmentToken{ID: "token", Name: "test", Hint: "hint", MaxUses: 1000, CreatedAt: now}, "token-hash"); err != nil {
		t.Fatal(err)
	}
	create := func(id, identity string) error {
		return s.CreateEnrollmentChallenge(ctx, EnrollmentChallengeInput{ID: id, EnrollmentHash: "token-hash", IdentityKey: identity, ChallengeHash: "challenge-" + id, Now: now, ExpiresAt: now.Add(5 * time.Minute)})
	}
	for i := 0; i < 16; i++ {
		if err = create(fmt.Sprintf("same-%d", i), "same-identity"); err != nil {
			t.Fatalf("same identity challenge %d: %v", i, err)
		}
	}
	if err = create("same-over-cap", "same-identity"); !errors.Is(err, ErrConflict) {
		t.Fatalf("per-identity outstanding cap was not enforced: %v", err)
	}
	for i := 0; i < 48; i++ { // 16 retries plus 48 unique identities reaches the token cap of 64
		if err = create(fmt.Sprintf("challenge-%d", i), fmt.Sprintf("identity-%d", i)); err != nil {
			t.Fatalf("challenge %d: %v", i, err)
		}
	}
	if err = create("over-cap", "identity-over-cap"); !errors.Is(err, ErrConflict) {
		t.Fatalf("token-wide outstanding cap was not enforced: %v", err)
	}
}
