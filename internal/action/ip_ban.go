package action

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	nftTable                    = "witshield"
	nftChain                    = "input"
	nftBanSetV4                 = "temporary_bans_v4"
	nftBanSetV6                 = "temporary_bans_v6"
	temporaryBanMutationTimeout = 30 * time.Second
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

var (
	nftElementExpiresPattern    = regexp.MustCompile(`\bexpires\s+((?:[0-9]+(?:ms|[dhms]))+)(?:\s|$)`)
	nftElementTimePartPattern   = regexp.MustCompile(`([0-9]+)(ms|[dhms])`)
	nftElementGenerationPattern = regexp.MustCompile(`\bcomment\s+"(witshield:[0-9a-f]{64})"`)
)

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
	Address                 string     `json:"address"`
	Set                     string     `json:"set"`
	Generation              string     `json:"generation,omitempty"`
	AppliedTTLSeconds       int        `json:"appliedTtlSeconds,omitempty"`
	ExpiresAt               time.Time  `json:"expiresAt"`
	PreviousGeneration      string     `json:"previousGeneration,omitempty"`
	PreviousRemainingMillis int64      `json:"previousRemainingMillis,omitempty"`
	PreviousExpiresAt       *time.Time `json:"previousExpiresAt,omitempty"`
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
	if err := p.checkNFTables(ctx); err != nil {
		return Result{}, fmt.Errorf("WitShield nftables infrastructure is not ready: %w", err)
	}
	if element, getErr := p.getElement(ctx, setName, address); getErr == nil {
		generation, remaining, parseErr := parseTemporaryBanElement(element, p.config.MaxTTL)
		if parseErr != nil {
			return Result{}, fmt.Errorf("existing temporary ban cannot be safely refreshed: %w", parseErr)
		}
		if remaining > time.Duration(params.TTLSeconds)*time.Second {
			return Result{}, errors.New("refusing to shorten an existing temporary ban; requested TTL must cover its remaining kernel TTL")
		}
		return Result{Summary: "target already has a bounded WitShield ban and can be atomically refreshed", Details: map[string]any{
			"address": address.String(), "ttlSeconds": params.TTLSeconds, "refreshExisting": true,
			"existingGeneration": generation, "existingRemainingSeconds": int(remaining / time.Second),
		}}, nil
	} else if !nftElementMissing(element, getErr) {
		return Result{}, fmt.Errorf("inspect existing temporary ban: %w", getErr)
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
	if err := p.checkNFTables(ctx); err != nil {
		return ApplyResult{}, err
	}
	var previousGeneration string
	var previousExpiresAt *time.Time
	var previousRemainingMillis int64
	var capturedAt time.Time
	if element, getErr := p.getElement(ctx, setName, address); getErr == nil {
		generation, remaining, parseErr := parseTemporaryBanElement(element, p.config.MaxTTL)
		if parseErr != nil {
			return ApplyResult{}, fmt.Errorf("existing temporary ban cannot be safely refreshed: %w", parseErr)
		}
		if remaining > time.Duration(params.TTLSeconds)*time.Second {
			return ApplyResult{}, errors.New("refusing to shorten an existing temporary ban; requested TTL must cover its remaining kernel TTL")
		}
		capturedAt = time.Now()
		capturedExpiry := time.Now().UTC().Add(remaining)
		previousGeneration = generation
		previousExpiresAt = &capturedExpiry
		previousRemainingMillis = remaining.Milliseconds()
	} else if !nftElementMissing(element, getErr) {
		return ApplyResult{}, fmt.Errorf("inspect existing temporary ban before refresh: %w", getErr)
	}
	generation, err := temporaryBanGeneration(invocation.ActionID)
	if err != nil {
		return ApplyResult{}, err
	}
	now := time.Now().UTC()
	recoveryState := temporaryIPBanState{
		Address: address.String(), Set: setName, Generation: generation, AppliedTTLSeconds: params.TTLSeconds,
		// The nft transaction may commit immediately before its command timeout
		// becomes observable. Cover the latest possible kernel TTL start on the
		// failure path; a successful result is narrowed to its observed end time.
		ExpiresAt:          now.Add(temporaryBanMutationTimeout + time.Duration(params.TTLSeconds)*time.Second),
		PreviousGeneration: previousGeneration, PreviousRemainingMillis: previousRemainingMillis, PreviousExpiresAt: previousExpiresAt,
	}
	mutationErr := p.installOrRefreshElement(ctx, setName, address, params.TTLSeconds, generation)
	observed, observedErr := p.getElement(ctx, setName, address)
	if observedErr != nil {
		if mutationErr != nil && nftElementMissing(observed, observedErr) && previousGeneration == "" {
			return ApplyResult{}, mutationErr
		}
		state, encodeErr := encodeState(recoveryState)
		if encodeErr != nil {
			return ApplyResult{}, fmt.Errorf("temporary ban outcome is unknown and recovery state could not be encoded: %w", errors.Join(mutationErr, observedErr, encodeErr))
		}
		return ApplyResult{State: state}, fmt.Errorf("temporary ban outcome could not be observed after the mutation boundary: %w", errors.Join(mutationErr, observedErr))
	}
	currentGeneration, currentRemaining, parseErr := parseTemporaryBanElement(observed, p.config.MaxTTL)
	if parseErr != nil {
		state, _ := encodeState(recoveryState)
		return ApplyResult{State: state}, fmt.Errorf("temporary ban outcome could not be parsed after the mutation boundary: %w", errors.Join(mutationErr, parseErr))
	}
	if currentGeneration != generation {
		if mutationErr != nil && currentGeneration == previousGeneration {
			return ApplyResult{}, mutationErr
		}
		state, _ := encodeState(recoveryState)
		return ApplyResult{State: state}, fmt.Errorf("temporary ban generation after the mutation boundary was unexpected: %w", mutationErr)
	}
	if previousRemainingMillis > 0 && !capturedAt.IsZero() {
		totalElapsed := time.Since(capturedAt)
		appliedTTL := time.Duration(params.TTLSeconds) * time.Second
		generationAge := appliedTTL - currentRemaining
		if generationAge < 0 {
			generationAge = 0
		}
		preCommitElapsed := totalElapsed - generationAge
		if preCommitElapsed < 0 {
			preCommitElapsed = 0
		}
		remaining := time.Duration(previousRemainingMillis)*time.Millisecond - preCommitElapsed
		if remaining <= 0 {
			recoveryState.PreviousGeneration = ""
			recoveryState.PreviousRemainingMillis = 0
			recoveryState.PreviousExpiresAt = nil
		} else {
			recoveryState.PreviousRemainingMillis = remaining.Milliseconds()
		}
	}
	recoveryState.ExpiresAt = time.Now().UTC().Add(currentRemaining)
	state, exactErr := encodeState(recoveryState)
	if exactErr != nil {
		return ApplyResult{}, fmt.Errorf("encode exact temporary ban state after apply: %w", exactErr)
	}
	if mutationErr != nil {
		return ApplyResult{State: state}, mutationErr
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
	generation, generationErr := temporaryBanGeneration(invocation.ActionID)
	state, err := decodeStrict[temporaryIPBanState](invocation.State)
	if generationErr != nil || err != nil || !p.validTemporaryBanState(state, address, setName, generation) {
		return Result{}, errors.New("temporary ban state does not match the requested address")
	}
	element, err := p.getElement(ctx, setName, address)
	if err != nil {
		return Result{}, fmt.Errorf("temporary nftables element is not present: %w", err)
	}
	currentGeneration, _, parseErr := parseTemporaryBanElement(element, p.config.MaxTTL)
	if parseErr != nil {
		return Result{}, fmt.Errorf("read temporary ban generation: %w", parseErr)
	}
	if state.Generation == "" && currentGeneration != "" {
		return Result{}, errors.New("legacy temporary ban was superseded by a newer action generation")
	}
	if state.Generation != "" && currentGeneration != generation {
		return Result{}, errors.New("temporary nftables element belongs to a newer action generation")
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
	generation, generationErr := temporaryBanGeneration(invocation.ActionID)
	state, err := decodeStrict[temporaryIPBanState](invocation.State)
	if generationErr != nil || err != nil || !p.validTemporaryBanState(state, address, setName, generation) {
		return Result{}, errors.New("temporary ban rollback state does not match the request")
	}
	now := time.Now().UTC()
	hadPredecessor := state.PreviousExpiresAt != nil || state.PreviousRemainingMillis > 0
	element, err := p.getElement(ctx, setName, address)
	if err != nil {
		if nftElementMissing(element, err) {
			if hadPredecessor {
				return Result{}, errors.New("temporary ban element is absent and the previous generation's remaining monotonic TTL cannot be proven; inspect nftables manually")
			}
			return Result{Summary: "temporary IP ban is already absent"}, nil
		}
		return Result{}, fmt.Errorf("read temporary nftables element before rollback: %w", err)
	}
	currentGeneration, currentRemaining, parseErr := parseTemporaryBanElement(element, p.config.MaxTTL)
	if parseErr != nil {
		return Result{}, fmt.Errorf("read temporary ban generation before rollback: %w", parseErr)
	}
	if hadPredecessor && currentGeneration == state.PreviousGeneration {
		return Result{Summary: "previous temporary IP ban generation was already intact", Details: map[string]any{
			"address": address.String(),
		}}, nil
	}
	if state.Generation == "" && currentGeneration != "" {
		return Result{}, errors.New("legacy temporary ban was superseded by a newer action and cannot be rolled back")
	}
	if state.Generation == "" && currentGeneration == "" && !now.Before(state.ExpiresAt) {
		return Result{}, errors.New("legacy temporary ban ownership cannot be proven after its recorded wall-clock horizon; inspect nftables manually")
	}
	if state.Generation != "" && currentGeneration != generation {
		return Result{}, errors.New("temporary ban was superseded by a newer action and cannot be rolled back")
	}
	if hadPredecessor {
		if state.PreviousRemainingMillis <= 0 || state.AppliedTTLSeconds <= 0 {
			return Result{}, errors.New("legacy predecessor rollback state lacks a monotonic TTL proof; inspect nftables manually")
		}
		appliedTTL := time.Duration(state.AppliedTTLSeconds) * time.Second
		elapsed := appliedTTL - currentRemaining
		if elapsed < -time.Second || elapsed > appliedTTL {
			return Result{}, errors.New("current temporary ban TTL is inconsistent with its rollback state")
		}
		if elapsed < 0 {
			elapsed = 0
		}
		remaining := time.Duration(state.PreviousRemainingMillis)*time.Millisecond - elapsed
		if state.PreviousExpiresAt != nil {
			wallRemaining := time.Until(*state.PreviousExpiresAt)
			if wallRemaining < remaining {
				remaining = wallRemaining
			}
		}
		if remaining > 0 {
			if remaining > p.config.MaxTTL {
				return Result{}, errors.New("previous temporary ban TTL exceeds the configured safety bound")
			}
			remainingSeconds := int((remaining + time.Second - 1) / time.Second)
			if err := p.installOrRefreshElement(ctx, setName, address, remainingSeconds, state.PreviousGeneration); err != nil {
				return Result{}, fmt.Errorf("restore previous temporary ban generation: %w", err)
			}
			return Result{Summary: "previous temporary IP ban generation restored", Details: map[string]any{
				"address": address.String(), "remainingSeconds": remainingSeconds,
			}}, nil
		}
	}
	args := []string{"delete", "element", "inet", nftTable, setName, "{", address.String(), "}"}
	if _, err := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: args, Timeout: 30 * time.Second}); err != nil {
		// Expiration racing with delete is safe only when a fresh read proves the
		// key is absent. Wall-clock expiry alone cannot prove a kernel mutation.
		observed, readErr := p.getElement(ctx, setName, address)
		if readErr != nil && nftElementMissing(observed, readErr) {
			return Result{Summary: "temporary IP ban is already absent"}, nil
		}
		return Result{}, fmt.Errorf("remove temporary nftables element: %w", err)
	}
	return Result{Summary: "temporary IP ban removed before its TTL", Details: map[string]any{"address": address.String()}}, nil
}

func (p *TemporaryIPBanPlaybook) validTemporaryBanState(state temporaryIPBanState, address netip.Addr, setName, generation string) bool {
	maximumSeconds := int(p.config.MaxTTL / time.Second)
	maximumMillis := p.config.MaxTTL.Milliseconds()
	if state.Address != address.String() || state.Set != setName || (state.Generation != "" && state.Generation != generation) || state.PreviousRemainingMillis < 0 || state.AppliedTTLSeconds < 0 || state.AppliedTTLSeconds > maximumSeconds || state.PreviousRemainingMillis > maximumMillis {
		return false
	}
	if state.PreviousGeneration != "" && state.PreviousExpiresAt == nil && state.PreviousRemainingMillis <= 0 {
		return false
	}
	if state.PreviousRemainingMillis > 0 && (state.AppliedTTLSeconds <= 0 || state.PreviousRemainingMillis > int64(state.AppliedTTLSeconds)*1000) {
		return false
	}
	return true
}

func temporaryBanGeneration(actionID string) (string, error) {
	if actionID == "" {
		return "", errors.New("temporary ban requires an action ID")
	}
	digest := sha256.Sum256([]byte(actionID))
	return fmt.Sprintf("witshield:%x", digest), nil
}

// installOrRefreshElement uses one nftables netlink transaction. The first
// non-exclusive add guarantees the key exists, delete removes the old timeout
// and generation, and the final add installs the new bounded generation. The
// kernel commits all three operations atomically, so a refresh never opens an
// unblocked interval and works whether the key existed before the transaction.
func (p *TemporaryIPBanPlaybook) installOrRefreshElement(ctx context.Context, setName string, address netip.Addr, ttlSeconds int, generation string) error {
	finalElement := fmt.Sprintf("%s timeout %ds", address.String(), ttlSeconds)
	if generation != "" {
		finalElement += fmt.Sprintf(" comment \"%s\"", generation)
	}
	script := fmt.Sprintf(
		"add element inet %s %s { %s }\n"+
			"delete element inet %s %s { %s }\n"+
			"add element inet %s %s { %s }\n",
		nftTable, setName, address.String(),
		nftTable, setName, address.String(),
		nftTable, setName, finalElement,
	)
	if _, err := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: []string{"-f", "-"}, Stdin: []byte(script), Timeout: temporaryBanMutationTimeout}); err != nil {
		return fmt.Errorf("atomically install temporary nftables element: %w", err)
	}
	return nil
}

func parseTemporaryBanElement(result CommandResult, maximum time.Duration) (string, time.Duration, error) {
	expiresMatch := nftElementExpiresPattern.FindStringSubmatch(result.Stdout)
	if len(expiresMatch) != 2 {
		return "", 0, errors.New("nftables element did not expose a remaining TTL")
	}
	remaining, err := parseNftTimespec(expiresMatch[1])
	if err != nil || remaining <= 0 || remaining > maximum {
		return "", 0, errors.New("nftables element exposed an invalid remaining TTL")
	}
	generation := ""
	if generationMatch := nftElementGenerationPattern.FindStringSubmatch(result.Stdout); len(generationMatch) == 2 {
		generation = generationMatch[1]
	} else if strings.Contains(result.Stdout, "comment ") {
		return "", 0, errors.New("nftables element has an unrecognized owner comment")
	}
	return generation, remaining, nil
}

func nftElementMissing(result CommandResult, err error) bool {
	if err == nil || result.ExitCode == 0 || result.OutputTruncated {
		return false
	}
	details := strings.ToLower(result.Stderr)
	return strings.Contains(details, "could not process rule") && strings.Contains(details, "no such file or directory")
}

func parseNftTimespec(value string) (time.Duration, error) {
	parts := nftElementTimePartPattern.FindAllStringSubmatch(value, -1)
	if len(parts) == 0 {
		return 0, errors.New("empty nftables time value")
	}
	var parsed strings.Builder
	var total time.Duration
	for _, part := range parts {
		parsed.WriteString(part[0])
		amount, err := strconv.ParseInt(part[1], 10, 64)
		if err != nil {
			return 0, err
		}
		unit := time.Second
		switch part[2] {
		case "d":
			unit = 24 * time.Hour
		case "h":
			unit = time.Hour
		case "m":
			unit = time.Minute
		case "ms":
			unit = time.Millisecond
		}
		if amount > int64((1<<63-1)/unit) {
			return 0, errors.New("nftables time value overflows duration")
		}
		total += time.Duration(amount) * unit
		if total < 0 {
			return 0, errors.New("nftables time value overflows duration")
		}
	}
	if parsed.String() != value {
		return 0, errors.New("nftables time value is malformed")
	}
	return total, nil
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
	return p.checkNFTables(ctx)
}

// Prepare reconciles WitShield's dedicated nftables infrastructure as a
// service-startup concern. Individual actions only perform their single
// element transaction, so a partial infrastructure setup can never be
// mistaken for a failed/no-change security action.
func (p *TemporaryIPBanPlaybook) Prepare(ctx context.Context) error {
	return p.ensureNFTables(ctx)
}

func (p *TemporaryIPBanPlaybook) checkNFTables(ctx context.Context) error {
	if _, err := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: []string{"list", "table", "inet", nftTable}, Timeout: 15 * time.Second}); err != nil {
		return errors.New("dedicated nftables table is absent")
	}
	sets := []struct {
		name, addressType string
	}{{nftBanSetV4, "ipv4_addr"}, {nftBanSetV6, "ipv6_addr"}}
	for _, set := range sets {
		result, err := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: []string{"list", "set", "inet", nftTable, set.name}, Timeout: 15 * time.Second})
		if err != nil || !strings.Contains(result.Stdout, "type "+set.addressType) || !strings.Contains(result.Stdout, "flags timeout") {
			return fmt.Errorf("dedicated nftables set %q is absent or has an unexpected definition", set.name)
		}
	}
	chain, err := p.config.Runner.Run(ctx, Command{Path: p.config.NFTPath, Args: []string{"list", "chain", "inet", nftTable, nftChain}, Timeout: 15 * time.Second})
	if err != nil || !strings.Contains(chain.Stdout, "hook input") || !strings.Contains(chain.Stdout, "policy accept") ||
		!strings.Contains(chain.Stdout, "ip saddr @"+nftBanSetV4+" drop") || !strings.Contains(chain.Stdout, "ip6 saddr @"+nftBanSetV6+" drop") {
		return errors.New("dedicated nftables input chain is absent or incomplete")
	}
	return nil
}
