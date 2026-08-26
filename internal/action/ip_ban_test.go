package action

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTemporaryIPBanRejectsProtectedTargets(t *testing.T) {
	playbook, err := NewTemporaryIPBanPlaybook(IPBanConfig{
		Runner: &fakeRunner{}, NFTPath: "/fake/nft",
		Protected:       []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		CurrentAdminIPs: []netip.Addr{netip.MustParseAddr("203.0.113.9")},
		MinTTL:          time.Second, MaxTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []string{
		`{"address":"127.0.0.1","ttlSeconds":60,"currentAdminIp":"8.8.8.8"}`,
		`{"address":"10.0.0.7","ttlSeconds":60,"currentAdminIp":"8.8.8.8"}`,
		`{"address":"169.254.169.254","ttlSeconds":60,"currentAdminIp":"8.8.8.8"}`,
		`{"address":"100.64.0.7","ttlSeconds":60,"currentAdminIp":"8.8.8.8"}`,
		`{"address":"8.8.8.8","ttlSeconds":60,"currentAdminIp":"8.8.8.8"}`,
		`{"address":"203.0.113.9","ttlSeconds":60,"currentAdminIp":"8.8.8.8"}`,
		`{"address":"198.51.100.23","ttlSeconds":60,"currentAdminIp":"8.8.8.8"}`,
		`{"address":"1.1.1.1","ttlSeconds":60,"currentAdminIp":""}`,
		`{"address":"1.1.1.1","ttlSeconds":999999,"currentAdminIp":"8.8.8.8"}`,
	}
	for _, raw := range tests {
		if err := playbook.Validate(json.RawMessage(raw)); err == nil {
			t.Errorf("protected target accepted: %s", raw)
		}
	}
}

func TestTemporaryIPBanUsesNftNativeTimeoutAndRollsBack(t *testing.T) {
	banned := false
	owner, _ := temporaryBanGeneration("ban-action")
	runner := &fakeRunner{}
	runner.run = func(command Command) (CommandResult, error) {
		args := strings.Join(command.Args, " ")
		switch {
		case args == "--version":
			return CommandResult{Stdout: "nftables v1"}, nil
		case strings.HasPrefix(args, "get element"):
			if banned {
				return CommandResult{Stdout: `elements = { 8.8.8.8 expires 55s comment "` + owner + `" }`}, nil
			}
			return missingNFTElement()
		case args == "list table inet witshield":
			return CommandResult{Stdout: "table inet witshield"}, nil
		case strings.HasPrefix(args, "list set"):
			addressType := "ipv4_addr"
			if strings.Contains(args, nftBanSetV6) {
				addressType = "ipv6_addr"
			}
			return CommandResult{Stdout: "type " + addressType + "; flags timeout;"}, nil
		case args == "list chain inet witshield input":
			return CommandResult{Stdout: "hook input priority -10; policy accept; ip saddr @temporary_bans_v4 drop; ip6 saddr @temporary_bans_v6 drop"}, nil
		case args == "-f -":
			script := string(command.Stdin)
			if !strings.Contains(script, "add element inet witshield temporary_bans_v4 { 8.8.8.8 }\n") ||
				!strings.Contains(script, "delete element inet witshield temporary_bans_v4 { 8.8.8.8 }\n") ||
				!strings.Contains(script, `8.8.8.8 timeout 60s comment "`+owner+`"`) {
				t.Fatalf("nft transaction lacks atomic refresh, exact timeout, or generation: %q", script)
			}
			banned = true
			return CommandResult{}, nil
		case strings.HasPrefix(args, "delete element"):
			banned = false
			return CommandResult{}, nil
		case strings.HasPrefix(args, "add "):
			return CommandResult{}, nil
		default:
			return CommandResult{}, errors.New("unexpected nft command")
		}
	}
	playbook, err := NewTemporaryIPBanPlaybook(IPBanConfig{
		Runner: runner, NFTPath: "/fake/nft", MinTTL: time.Second, MaxTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := NewEngine(playbook)
	parameters := json.RawMessage(`{"address":"8.8.8.8","ttlSeconds":60,"currentAdminIp":"1.1.1.1","reason":"SSH threshold"}`)
	receipt := engine.Run(context.Background(), Request{
		ActionID: "ban-action", Actor: "defense-policy", Type: TypeTemporaryIPBan,
		Operation: OperationExecute, Parameters: parameters,
	})
	if !receipt.Success || !banned {
		t.Fatalf("temporary ban failed: %#v", receipt)
	}
	rollback := engine.Run(context.Background(), Request{
		ActionID: "ban-action", Actor: "tester", Type: TypeTemporaryIPBan,
		Operation: OperationRollback, Parameters: parameters, State: receipt.State,
	})
	if !rollback.Success || banned {
		t.Fatalf("temporary ban rollback failed: %#v", rollback)
	}
	for _, command := range runner.snapshotCalls() {
		if command.Path != "/fake/nft" {
			t.Fatalf("unexpected executable: %#v", command)
		}
	}
}

func TestTemporaryIPBanExpiredRollbackCannotDeleteNewerBan(t *testing.T) {
	newOwner, _ := temporaryBanGeneration("newer-action")
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		if strings.HasPrefix(strings.Join(command.Args, " "), "get element") {
			return CommandResult{Stdout: `elements = { 8.8.8.8 expires 55s comment "` + newOwner + `" }`}, nil
		}
		return CommandResult{}, errors.New("stale rollback crossed its generation guard")
	}}
	playbook, err := NewTemporaryIPBanPlaybook(IPBanConfig{
		Runner: runner, NFTPath: "/fake/nft", MinTTL: time.Second, MaxTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	parameters := json.RawMessage(`{"address":"8.8.8.8","ttlSeconds":60,"currentAdminIp":"1.1.1.1"}`)
	owner, _ := temporaryBanGeneration("expired-action")
	staleState, err := encodeState(temporaryIPBanState{
		Address: "8.8.8.8", Set: nftBanSetV4, Generation: owner, ExpiresAt: time.Now().UTC().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = playbook.Rollback(context.Background(), Invocation{ActionID: "expired-action", Parameters: parameters, State: staleState})
	if err == nil || !strings.Contains(err.Error(), "superseded") {
		t.Fatalf("expired rollback did not reject newer owner: %v", err)
	}
	for _, call := range runner.snapshotCalls() {
		if strings.HasPrefix(strings.Join(call.Args, " "), "delete element") {
			t.Fatalf("stale rollback deleted a newer ban: %#v", call)
		}
	}
}

func TestTemporaryIPBanExpiredOwnedGenerationIsStillRemoved(t *testing.T) {
	owner, _ := temporaryBanGeneration("timed-out-action")
	deleted := false
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		args := strings.Join(command.Args, " ")
		switch {
		case strings.HasPrefix(args, "get element"):
			return CommandResult{Stdout: `elements = { 8.8.8.8 expires 25s comment "` + owner + `" }`}, nil
		case strings.HasPrefix(args, "delete element"):
			deleted = true
			return CommandResult{}, nil
		default:
			return CommandResult{}, errors.New("unexpected command: " + args)
		}
	}}
	playbook, err := NewTemporaryIPBanPlaybook(IPBanConfig{Runner: runner, NFTPath: "/fake/nft", MinTTL: time.Second, MaxTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	state, _ := encodeState(temporaryIPBanState{Address: "8.8.8.8", Set: nftBanSetV4, Generation: owner, ExpiresAt: time.Now().UTC().Add(-time.Second)})
	parameters := json.RawMessage(`{"address":"8.8.8.8","ttlSeconds":1,"currentAdminIp":"1.1.1.1"}`)
	result, err := playbook.Rollback(context.Background(), Invocation{ActionID: "timed-out-action", Parameters: parameters, State: state})
	if err != nil || !deleted || !strings.Contains(result.Summary, "removed") {
		t.Fatalf("result=%#v deleted=%v err=%v", result, deleted, err)
	}
}

func TestTemporaryIPBanRollbackUsesKernelTTLDespiteWallClockJump(t *testing.T) {
	oldOwner, _ := temporaryBanGeneration("old-action")
	newOwner, _ := temporaryBanGeneration("new-action")
	restored := false
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		args := strings.Join(command.Args, " ")
		switch {
		case strings.HasPrefix(args, "get element"):
			return CommandResult{Stdout: `elements = { 8.8.8.8 expires 55s comment "` + newOwner + `" }`}, nil
		case args == "-f -":
			script := string(command.Stdin)
			if !strings.Contains(script, `comment "`+oldOwner+`"`) {
				return CommandResult{}, errors.New("predecessor generation was not restored")
			}
			restored = true
			return CommandResult{}, nil
		default:
			return CommandResult{}, errors.New("unexpected command: " + args)
		}
	}}
	playbook, err := NewTemporaryIPBanPlaybook(IPBanConfig{Runner: runner, NFTPath: "/fake/nft", MinTTL: time.Second, MaxTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	previousExpiresAt := time.Now().UTC().Add(50 * time.Second)
	state, err := encodeState(temporaryIPBanState{
		Address: "8.8.8.8", Set: nftBanSetV4,
		Generation: newOwner, AppliedTTLSeconds: 60, ExpiresAt: time.Now().UTC().Add(-time.Minute),
		PreviousGeneration: oldOwner, PreviousRemainingMillis: int64((50 * time.Second) / time.Millisecond), PreviousExpiresAt: &previousExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	parameters := json.RawMessage(`{"address":"8.8.8.8","ttlSeconds":60,"currentAdminIp":"1.1.1.1"}`)
	result, err := playbook.Rollback(context.Background(), Invocation{ActionID: "new-action", Parameters: parameters, State: state})
	if err != nil || !restored || !strings.Contains(result.Summary, "previous") {
		t.Fatalf("result=%#v restored=%v err=%v", result, restored, err)
	}
}

func TestTemporaryIPBanRollbackCannotDeleteNewerGeneration(t *testing.T) {
	oldOwner, _ := temporaryBanGeneration("old-action")
	newOwner, _ := temporaryBanGeneration("new-action")
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		if strings.HasPrefix(strings.Join(command.Args, " "), "get element") {
			return CommandResult{Stdout: `elements = { 8.8.8.8 expires 55s comment "` + newOwner + `" }`}, nil
		}
		return CommandResult{}, errors.New("rollback crossed the generation guard")
	}}
	playbook, err := NewTemporaryIPBanPlaybook(IPBanConfig{Runner: runner, NFTPath: "/fake/nft", MinTTL: time.Second, MaxTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	parameters := json.RawMessage(`{"address":"8.8.8.8","ttlSeconds":60,"currentAdminIp":"1.1.1.1"}`)
	oldState, _ := encodeState(temporaryIPBanState{Address: "8.8.8.8", Set: nftBanSetV4, Generation: oldOwner, ExpiresAt: time.Now().UTC().Add(time.Minute)})
	if _, err = playbook.Rollback(context.Background(), Invocation{ActionID: "old-action", Parameters: parameters, State: oldState}); err == nil || !strings.Contains(err.Error(), "superseded") {
		t.Fatalf("old generation rollback was not rejected: %v", err)
	}
	for _, call := range runner.snapshotCalls() {
		if strings.HasPrefix(strings.Join(call.Args, " "), "delete element") {
			t.Fatalf("old action deleted the newer generation: %#v", call)
		}
	}
}

func TestTemporaryIPBanRefreshRollbackRestoresPredecessor(t *testing.T) {
	tests := []struct {
		name             string
		failVerification bool
	}{
		{name: "manual rollback"},
		{name: "automatic rollback after verification failure", failVerification: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			oldOwner, _ := temporaryBanGeneration("old-action")
			newOwner, _ := temporaryBanGeneration("new-action")
			currentOwner := oldOwner
			refreshes := 0
			failNextVerify := test.failVerification
			newOwnerReads := 0
			runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
				args := strings.Join(command.Args, " ")
				switch {
				case args == "--version":
					return CommandResult{Stdout: "nftables v1"}, nil
				case strings.HasPrefix(args, "get element"):
					if currentOwner == newOwner {
						newOwnerReads++
					}
					if currentOwner == newOwner && failNextVerify && newOwnerReads > 1 {
						failNextVerify = false
						return CommandResult{}, errors.New("forced verification read failure")
					}
					if currentOwner == "" {
						return missingNFTElement()
					}
					return CommandResult{Stdout: `elements = { 8.8.8.8 expires 55s comment "` + currentOwner + `" }`}, nil
				case args == "list table inet witshield":
					return CommandResult{Stdout: "table inet witshield"}, nil
				case strings.HasPrefix(args, "list set"):
					addressType := "ipv4_addr"
					if strings.Contains(args, nftBanSetV6) {
						addressType = "ipv6_addr"
					}
					return CommandResult{Stdout: "type " + addressType + "; flags timeout;"}, nil
				case args == "list chain inet witshield input":
					return CommandResult{Stdout: "hook input priority -10; policy accept; ip saddr @temporary_bans_v4 drop; ip6 saddr @temporary_bans_v6 drop"}, nil
				case args == "-f -":
					script := string(command.Stdin)
					switch {
					case strings.Contains(script, `comment "`+newOwner+`"`):
						currentOwner = newOwner
					case strings.Contains(script, `comment "`+oldOwner+`"`):
						currentOwner = oldOwner
					default:
						return CommandResult{}, errors.New("atomic refresh omitted its generation")
					}
					refreshes++
					return CommandResult{}, nil
				case strings.HasPrefix(args, "delete element"):
					currentOwner = ""
					return CommandResult{}, nil
				default:
					return CommandResult{}, errors.New("unexpected nft command: " + args)
				}
			}}
			playbook, err := NewTemporaryIPBanPlaybook(IPBanConfig{Runner: runner, NFTPath: "/fake/nft", MinTTL: time.Second, MaxTTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			engine, _ := NewEngine(playbook)
			parameters := json.RawMessage(`{"address":"8.8.8.8","ttlSeconds":60,"currentAdminIp":"1.1.1.1"}`)
			receipt := engine.Run(context.Background(), Request{ActionID: "new-action", Actor: "policy", Type: TypeTemporaryIPBan, Operation: OperationExecute, Parameters: parameters})
			if test.failVerification {
				if receipt.Success || len(receipt.Steps) != 5 || receipt.Steps[3].Success || !receipt.Steps[4].Success {
					t.Fatalf("automatic rollback receipt=%#v", receipt)
				}
				if currentOwner != oldOwner || refreshes != 2 {
					t.Fatalf("failed refresh did not atomically restore predecessor: owner=%q refreshes=%d", currentOwner, refreshes)
				}
				return
			}
			if !receipt.Success || currentOwner != newOwner || refreshes != 1 {
				t.Fatalf("refresh receipt=%#v owner=%q refreshes=%d", receipt, currentOwner, refreshes)
			}
			rollback := engine.Run(context.Background(), Request{ActionID: "new-action", Actor: "admin", Type: TypeTemporaryIPBan, Operation: OperationRollback, Parameters: parameters, State: receipt.State})
			if !rollback.Success || currentOwner != oldOwner || refreshes != 2 {
				t.Fatalf("rollback=%#v owner=%q refreshes=%d", rollback, currentOwner, refreshes)
			}
		})
	}
}

func TestLegacyTemporaryIPBanRollbackCompatibilityAndGenerationGuard(t *testing.T) {
	parameters := json.RawMessage(`{"address":"8.8.8.8","ttlSeconds":60,"currentAdminIp":"1.1.1.1"}`)
	legacyState, _ := encodeState(temporaryIPBanState{Address: "8.8.8.8", Set: nftBanSetV4, ExpiresAt: time.Now().UTC().Add(time.Minute)})
	tests := []struct {
		name       string
		generation string
		wantOK     bool
	}{
		{name: "legacy element remains rollback compatible", wantOK: true},
		{name: "legacy rollback cannot delete a new generation", generation: "new-action", wantOK: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deleted := false
			owner := ""
			if test.generation != "" {
				owner, _ = temporaryBanGeneration(test.generation)
			}
			runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
				args := strings.Join(command.Args, " ")
				if strings.HasPrefix(args, "get element") {
					comment := ""
					if owner != "" {
						comment = ` comment "` + owner + `"`
					}
					return CommandResult{Stdout: "elements = { 8.8.8.8 expires 55s" + comment + " }"}, nil
				}
				if strings.HasPrefix(args, "delete element") {
					deleted = true
					return CommandResult{}, nil
				}
				return CommandResult{}, errors.New("unexpected command")
			}}
			playbook, err := NewTemporaryIPBanPlaybook(IPBanConfig{Runner: runner, NFTPath: "/fake/nft", MinTTL: time.Second, MaxTTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			_, rollbackErr := playbook.Rollback(context.Background(), Invocation{ActionID: "legacy-action", Parameters: parameters, State: legacyState})
			if test.wantOK && (rollbackErr != nil || !deleted) {
				t.Fatalf("legacy rollback err=%v deleted=%v", rollbackErr, deleted)
			}
			if !test.wantOK && (rollbackErr == nil || deleted) {
				t.Fatalf("new generation was not protected: err=%v deleted=%v", rollbackErr, deleted)
			}
		})
	}
}

func TestParseTemporaryBanElementHandlesNftMillisecondPrecision(t *testing.T) {
	owner, _ := temporaryBanGeneration("millisecond-action")
	generation, remaining, err := parseTemporaryBanElement(CommandResult{
		Stdout: `elements = { 8.8.8.8 timeout 2m expires 1m59s977ms comment "` + owner + `" }`,
	}, 24*time.Hour)
	if err != nil || generation != owner || remaining != time.Minute+59*time.Second+977*time.Millisecond {
		t.Fatalf("generation=%q remaining=%s err=%v", generation, remaining, err)
	}
}

func TestNFTElementMissingRequiresARealNftDiagnostic(t *testing.T) {
	missing, err := missingNFTElement()
	if !nftElementMissing(missing, err) {
		t.Fatal("exact nft missing-element diagnostic was rejected")
	}
	if nftElementMissing(CommandResult{}, errors.New("command failed: fork/exec /usr/sbin/nft: no such file or directory")) {
		t.Fatal("missing nft executable was misclassified as an absent ban")
	}
	if nftElementMissing(CommandResult{Stderr: missing.Stderr, ExitCode: 1, OutputTruncated: true}, err) {
		t.Fatal("truncated nft diagnostic was trusted")
	}
}

func TestTemporaryIPBanRefusesToShortenAnExistingBan(t *testing.T) {
	oldOwner, _ := temporaryBanGeneration("existing-long-ban")
	mutated := false
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		args := strings.Join(command.Args, " ")
		switch {
		case args == "list table inet witshield":
			return CommandResult{Stdout: "table inet witshield"}, nil
		case strings.HasPrefix(args, "list set"):
			kind := "ipv4_addr"
			if strings.Contains(args, nftBanSetV6) {
				kind = "ipv6_addr"
			}
			return CommandResult{Stdout: "type " + kind + "; flags timeout;"}, nil
		case args == "list chain inet witshield input":
			return CommandResult{Stdout: "hook input; policy accept; ip saddr @temporary_bans_v4 drop; ip6 saddr @temporary_bans_v6 drop"}, nil
		case strings.HasPrefix(args, "get element"):
			return CommandResult{Stdout: `elements = { 8.8.8.8 expires 2m comment "` + oldOwner + `" }`}, nil
		case args == "-f -":
			mutated = true
			return CommandResult{}, nil
		default:
			return CommandResult{}, errors.New("unexpected command: " + args)
		}
	}}
	playbook, err := NewTemporaryIPBanPlaybook(IPBanConfig{Runner: runner, NFTPath: "/fake/nft", MinTTL: time.Second, MaxTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_, err = playbook.Apply(context.Background(), Invocation{ActionID: "short-refresh", Parameters: json.RawMessage(`{"address":"8.8.8.8","ttlSeconds":60,"currentAdminIp":"1.1.1.1"}`)})
	if err == nil || !strings.Contains(err.Error(), "shorten") || mutated {
		t.Fatalf("short refresh crossed mutation boundary: mutated=%v err=%v", mutated, err)
	}
}

func TestTemporaryIPBanRollbackCapsPredecessorToRecordedWallHorizon(t *testing.T) {
	oldOwner, _ := temporaryBanGeneration("old-cap")
	newOwner, _ := temporaryBanGeneration("new-cap")
	restoredSeconds := 0
	runner := &fakeRunner{run: func(command Command) (CommandResult, error) {
		args := strings.Join(command.Args, " ")
		switch {
		case strings.HasPrefix(args, "get element"):
			return CommandResult{Stdout: `elements = { 8.8.8.8 expires 59s comment "` + newOwner + `" }`}, nil
		case args == "-f -":
			match := regexp.MustCompile(`8\.8\.8\.8 timeout ([0-9]+)s comment "` + regexp.QuoteMeta(oldOwner) + `"`).FindStringSubmatch(string(command.Stdin))
			if len(match) != 2 {
				return CommandResult{}, errors.New("restored script omitted predecessor")
			}
			restoredSeconds, _ = strconv.Atoi(match[1])
			return CommandResult{}, nil
		default:
			return CommandResult{}, errors.New("unexpected command: " + args)
		}
	}}
	playbook, err := NewTemporaryIPBanPlaybook(IPBanConfig{Runner: runner, NFTPath: "/fake/nft", MinTTL: time.Second, MaxTTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	wallHorizon := time.Now().UTC().Add(34 * time.Second)
	state, _ := encodeState(temporaryIPBanState{Address: "8.8.8.8", Set: nftBanSetV4, Generation: newOwner, AppliedTTLSeconds: 60, ExpiresAt: time.Now().UTC().Add(time.Minute), PreviousGeneration: oldOwner, PreviousRemainingMillis: 60_000, PreviousExpiresAt: &wallHorizon})
	_, err = playbook.Rollback(context.Background(), Invocation{ActionID: "new-cap", Parameters: json.RawMessage(`{"address":"8.8.8.8","ttlSeconds":60,"currentAdminIp":"1.1.1.1"}`), State: state})
	if err != nil || restoredSeconds < 1 || restoredSeconds > 34 {
		t.Fatalf("predecessor TTL was extended past its recorded horizon: seconds=%d err=%v", restoredSeconds, err)
	}
}

func missingNFTElement() (CommandResult, error) {
	return CommandResult{Stderr: "Error: Could not process rule: No such file or directory", ExitCode: 1}, errors.New("command failed with exit code 1")
}
