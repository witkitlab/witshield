package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
)

const (
	nftTable    = "witshield"
	nftChain    = "input"
	nftBanSetV4 = "temporary_bans_v4"
	nftBanSetV6 = "temporary_bans_v6"
)

var nonPublicBanTargets = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
}

type TemporaryIPBanParams struct {
	Address        string `json:"address"`
	TTLSeconds     int    `json:"ttlSeconds"`
	CurrentAdminIP string `json:"currentAdminIp"`
	Reason         string `json:"reason,omitempty"`
}

type IPBanConfig struct {
	Runner          Runner
	NFTPath         string
	Protected       []netip.Prefix
	CurrentAdminIPs []netip.Addr
	MinTTL          time.Duration
	MaxTTL          time.Duration
}

type temporaryIPBanState struct {
	Address   string    `json:"address"`
	Set       string    `json:"set"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type TemporaryIPBanPlaybook struct {
	config IPBanConfig
}

func NewTemporaryIPBanPlaybook(config IPBanConfig) (*TemporaryIPBanPlaybook, error) {
	if config.Runner == nil || config.NFTPath == "" {
		return nil, errors.New("temporary IP ban requires a runner and nft path")
	}
	if config.MinTTL <= 0 {
		config.MinTTL = 30 * time.Second
	}
	if config.MaxTTL <= 0 {
		config.MaxTTL = 24 * time.Hour
	}
	if config.MinTTL > config.MaxTTL {
		return nil, errors.New("minimum ban TTL exceeds maximum TTL")
	}
	for index, prefix := range config.Protected {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("protected prefix %d is invalid", index)
		}
		config.Protected[index] = prefix.Masked()
	}
	for index, address := range config.CurrentAdminIPs {
		if !address.IsValid() {
			return nil, fmt.Errorf("current administrator IP %d is invalid", index)
		}
		config.CurrentAdminIPs[index] = address.Unmap()
	}
	return &TemporaryIPBanPlaybook{config: config}, nil
}

func (p *TemporaryIPBanPlaybook) Type() Type { return TypeTemporaryIPBan }

func (p *TemporaryIPBanPlaybook) Validate(raw json.RawMessage) error {
	params, err := decodeStrict[TemporaryIPBanParams](raw)
	if err != nil {
		return err
	}
	minimumSeconds := int((p.config.MinTTL + time.Second - 1) / time.Second)
	maximumSeconds := int(p.config.MaxTTL / time.Second)
	if params.TTLSeconds < minimumSeconds || params.TTLSeconds > maximumSeconds {
		return fmt.Errorf("ttlSeconds must be between %d and %d", minimumSeconds, maximumSeconds)
	}
	if params.CurrentAdminIP == "" {
		return errors.New("currentAdminIp is required for lockout protection")
	}
	if len(params.Reason) > 256 || strings.IndexFunc(params.Reason, unicode.IsControl) >= 0 {
		return errors.New("reason is too long or contains control characters")
	}
	_, _, err = p.safeTarget(params)
	return err
}

func (p *TemporaryIPBanPlaybook) safeTarget(params TemporaryIPBanParams) (netip.Addr, string, error) {
	address, err := ValidateTemporaryIPBanTarget(params.Address)
	if err != nil {
		return netip.Addr{}, "", err
	}
	adminAddress, err := netip.ParseAddr(params.CurrentAdminIP)
	if err != nil || adminAddress.Zone() != "" {
		return netip.Addr{}, "", errors.New("currentAdminIp must be a valid address without a zone")
	}
	if address == adminAddress.Unmap() {
		return netip.Addr{}, "", errors.New("refusing to ban the current administrator IP")
	}
	for _, current := range p.config.CurrentAdminIPs {
		if address == current {
			return netip.Addr{}, "", errors.New("refusing to ban a protected administrator IP")
		}
	}
	for _, prefix := range p.config.Protected {
		if prefix.Contains(address) {
			return netip.Addr{}, "", errors.New("refusing to ban an address in a protected prefix")
		}
	}
	setName := nftBanSetV6
	if address.Is4() {
		setName = nftBanSetV4
	}
	return address, setName, nil
}

// ValidateTemporaryIPBanTarget is the shared Controller/Helper safety gate for
// addresses that can ever reach nftables. Keeping it in the action package
// prevents policy-created commands from being accepted by the Controller only
// to be rejected by the privileged Helper.
func ValidateTemporaryIPBanTarget(raw string) (netip.Addr, error) {
	address, err := netip.ParseAddr(raw)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, errors.New("address must be a canonical IPv4 or IPv6 address without a zone")
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return netip.Addr{}, errors.New("loopback, private, local, multicast, and non-unicast addresses are protected")
	}
	for _, prefix := range nonPublicBanTargets {
		if prefix.Contains(address) {
			return netip.Addr{}, errors.New("shared, reserved, benchmarking, and documentation addresses are protected")
		}
	}
	return address, nil
}

func (p *TemporaryIPBanPlaybook) Precheck(ctx context.Context, invocation Invocation) (Result, error) {
	params, _ := decodeStrict[TemporaryIPBanParams](invocation.Parameters)
	address, setName, err := p.safeTarget(params)
	if err != nil {
		return Result{}, err
	}
	if _, err := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: []string{"--version"}, Timeout: 15 * time.Second}); err != nil {
		return Result{}, fmt.Errorf("nftables is unavailable: %w", err)
	}
	if _, err := p.getElement(ctx, setName, address); err == nil {
		return Result{}, errors.New("address already has an active WitShield temporary ban")
	}
	return Result{Summary: "target is a public non-protected address and nftables is available", Details: map[string]any{
		"address": address.String(), "ttlSeconds": params.TTLSeconds,
	}}, nil
}

func (p *TemporaryIPBanPlaybook) Preview(_ context.Context, invocation Invocation) (Result, error) {
	params, _ := decodeStrict[TemporaryIPBanParams](invocation.Parameters)
	address, _, err := p.safeTarget(params)
	if err != nil {
		return Result{}, err
	}
	return Result{Summary: "temporarily drop inbound packets from one address using a kernel-enforced TTL", Details: map[string]any{
		"address": address.String(), "ttlSeconds": params.TTLSeconds, "automaticExpiry": true,
	}}, nil
}

func (p *TemporaryIPBanPlaybook) Apply(ctx context.Context, invocation Invocation) (ApplyResult, error) {
	params, _ := decodeStrict[TemporaryIPBanParams](invocation.Parameters)
	address, setName, err := p.safeTarget(params)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := p.ensureNFTables(ctx); err != nil {
		return ApplyResult{}, err
	}
	args := []string{"add", "element", "inet", nftTable, setName, "{", address.String(), "timeout", fmt.Sprintf("%ds", params.TTLSeconds), "}"}
	if _, err := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: args, Timeout: 30 * time.Second}); err != nil {
		return ApplyResult{}, fmt.Errorf("add temporary nftables element: %w", err)
	}
	state, err := encodeState(temporaryIPBanState{
		Address: address.String(), Set: setName, ExpiresAt: time.Now().UTC().Add(time.Duration(params.TTLSeconds) * time.Second),
	})
	if err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{Result: Result{Summary: "temporary IP ban installed with kernel-enforced expiry", Details: map[string]any{
		"address": address.String(), "ttlSeconds": params.TTLSeconds,
	}}, State: state}, nil
}

func (p *TemporaryIPBanPlaybook) Verify(ctx context.Context, invocation Invocation) (Result, error) {
	params, _ := decodeStrict[TemporaryIPBanParams](invocation.Parameters)
	address, setName, err := p.safeTarget(params)
	if err != nil {
		return Result{}, err
	}
	state, err := decodeStrict[temporaryIPBanState](invocation.State)
	if err != nil || state.Address != address.String() || state.Set != setName {
		return Result{}, errors.New("temporary ban state does not match the requested address")
	}
	if time.Now().UTC().After(state.ExpiresAt) {
		return Result{Summary: "temporary IP ban TTL has already expired", Details: map[string]any{"address": address.String()}}, nil
	}
	if _, err := p.getElement(ctx, setName, address); err != nil {
		return Result{}, fmt.Errorf("temporary nftables element is not present: %w", err)
	}
	return Result{Summary: "temporary IP ban is active and will expire automatically", Details: map[string]any{
		"address": address.String(), "expiresAt": state.ExpiresAt,
	}}, nil
}

func (p *TemporaryIPBanPlaybook) Rollback(ctx context.Context, invocation Invocation) (Result, error) {
	params, _ := decodeStrict[TemporaryIPBanParams](invocation.Parameters)
	address, setName, err := p.safeTarget(params)
	if err != nil {
		return Result{}, err
	}
	state, err := decodeStrict[temporaryIPBanState](invocation.State)
	if err != nil || state.Address != address.String() || state.Set != setName {
		return Result{}, errors.New("temporary ban rollback state does not match the request")
	}
	args := []string{"delete", "element", "inet", nftTable, setName, "{", address.String(), "}"}
	if _, err := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: args, Timeout: 30 * time.Second}); err != nil {
		// Expiration before an explicit rollback is already the desired state.
		if time.Now().UTC().After(state.ExpiresAt) {
			return Result{Summary: "temporary IP ban had already expired"}, nil
		}
		return Result{}, fmt.Errorf("remove temporary nftables element: %w", err)
	}
	return Result{Summary: "temporary IP ban removed before its TTL", Details: map[string]any{"address": address.String()}}, nil
}

func (p *TemporaryIPBanPlaybook) getElement(ctx context.Context, setName string, address netip.Addr) (CommandResult, error) {
	return p.config.Runner.Run(ctx, Command{
		Path:    p.config.NFTPath,
		Args:    []string{"get", "element", "inet", nftTable, setName, "{", address.String(), "}"},
		Timeout: 15 * time.Second,
	})
}

func (p *TemporaryIPBanPlaybook) ensureNFTables(ctx context.Context) error {
	if _, err := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: []string{"list", "table", "inet", nftTable}, Timeout: 15 * time.Second}); err != nil {
		if _, addErr := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: []string{"add", "table", "inet", nftTable}, Timeout: 15 * time.Second}); addErr != nil {
			return fmt.Errorf("create dedicated nftables table: %w", addErr)
		}
	}
	sets := []struct {
		name, addressType string
	}{{nftBanSetV4, "ipv4_addr"}, {nftBanSetV6, "ipv6_addr"}}
	for _, set := range sets {
		result, err := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: []string{"list", "set", "inet", nftTable, set.name}, Timeout: 15 * time.Second})
		if err == nil {
			if !strings.Contains(result.Stdout, "type "+set.addressType) || !strings.Contains(result.Stdout, "flags timeout") {
				return fmt.Errorf("existing nftables set %q has an unexpected definition", set.name)
			}
			continue
		}
		args := []string{"add", "set", "inet", nftTable, set.name, "{", "type", set.addressType, ";", "flags", "timeout", ";", "}"}
		if _, err := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: args, Timeout: 15 * time.Second}); err != nil {
			return fmt.Errorf("create nftables timeout set %q: %w", set.name, err)
		}
	}
	chainResult, err := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: []string{"list", "chain", "inet", nftTable, nftChain}, Timeout: 15 * time.Second})
	if err != nil {
		args := []string{"add", "chain", "inet", nftTable, nftChain, "{", "type", "filter", "hook", "input", "priority", "-10", ";", "policy", "accept", ";", "}"}
		if _, err := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: args, Timeout: 15 * time.Second}); err != nil {
			return fmt.Errorf("create dedicated nftables input chain: %w", err)
		}
		chainResult = CommandResult{}
	} else if !strings.Contains(chainResult.Stdout, "hook input") || !strings.Contains(chainResult.Stdout, "policy accept") {
		return errors.New("existing WitShield nftables chain does not have the expected input hook and accept policy")
	}
	rules := []struct {
		expression, set string
	}{{"ip", nftBanSetV4}, {"ip6", nftBanSetV6}}
	for _, rule := range rules {
		needle := rule.expression + " saddr @" + rule.set + " drop"
		if strings.Contains(chainResult.Stdout, needle) {
			continue
		}
		args := []string{"add", "rule", "inet", nftTable, nftChain, rule.expression, "saddr", "@" + rule.set, "drop"}
		if _, err := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: args, Timeout: 15 * time.Second}); err != nil {
			return fmt.Errorf("install nftables temporary-ban rule: %w", err)
		}
	}
	return nil
}
