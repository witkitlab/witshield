package action

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
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
	runner := &fakeRunner{}
	runner.run = func(command Command) (CommandResult, error) {
		args := strings.Join(command.Args, " ")
		switch {
		case args == "--version":
			return CommandResult{Stdout: "nftables v1"}, nil
		case strings.HasPrefix(args, "get element"):
			if banned {
				return CommandResult{Stdout: "elements = { 8.8.8.8 expires 55s }"}, nil
			}
			return CommandResult{}, errors.New("not found")
		case strings.HasPrefix(args, "list "):
			return CommandResult{}, errors.New("not found")
		case strings.HasPrefix(args, "add element"):
			if !strings.Contains(args, "8.8.8.8 timeout 60s") {
				t.Fatalf("nft element lacks exact target or native timeout: %s", args)
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
