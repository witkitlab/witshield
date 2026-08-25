package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	debianPackagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}(?::[a-z0-9][a-z0-9-]{0,31})?$`)
	debianVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,255}$`)
)

type PackageSecurityUpgradeParams struct {
	Packages []string `json:"packages"`
}

type packageUpgradeState struct {
	Versions map[string]string `json:"versions"`
}

type PackageSecurityUpgradePlaybook struct {
	runner    Runner
	aptGet    string
	dpkgQuery string
}

func NewPackageSecurityUpgradePlaybook(runner Runner, aptGet, dpkgQuery string) *PackageSecurityUpgradePlaybook {
	return &PackageSecurityUpgradePlaybook{runner: runner, aptGet: aptGet, dpkgQuery: dpkgQuery}
}

func (p *PackageSecurityUpgradePlaybook) Type() Type { return TypePackageSecurityUpgrade }

func (p *PackageSecurityUpgradePlaybook) Validate(raw json.RawMessage) error {
	params, err := decodeStrict[PackageSecurityUpgradeParams](raw)
	if err != nil {
		return err
	}
	return validatePackageList(params.Packages)
}

func validatePackageList(packages []string) error {
	if len(packages) == 0 || len(packages) > 64 {
		return errors.New("packages must contain between 1 and 64 explicit package names")
	}
	seen := make(map[string]struct{}, len(packages))
	for _, name := range packages {
		if !debianPackagePattern.MatchString(name) {
			return fmt.Errorf("invalid Debian package name %q", name)
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate package %q", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

func (p *PackageSecurityUpgradePlaybook) Precheck(ctx context.Context, invocation Invocation) (Result, error) {
	params, _ := decodeStrict[PackageSecurityUpgradeParams](invocation.Parameters)
	if p.runner == nil || p.aptGet == "" || p.dpkgQuery == "" {
		return Result{}, errors.New("package manager is not configured")
	}
	if _, err := p.runner.Run(ctx, Command{Path: p.aptGet, Args: []string{"--version"}, Timeout: 15 * time.Second}); err != nil {
		return Result{}, fmt.Errorf("apt-get is unavailable: %w", err)
	}
	versions, err := p.installedVersions(ctx, params.Packages)
	if err != nil {
		return Result{}, err
	}
	return Result{Summary: "all requested packages are installed and eligible for an explicit upgrade", Details: map[string]any{
		"packages": sortedKeys(versions), "count": len(versions),
	}}, nil
}

func (p *PackageSecurityUpgradePlaybook) Preview(ctx context.Context, invocation Invocation) (Result, error) {
	params, _ := decodeStrict[PackageSecurityUpgradeParams](invocation.Parameters)
	args := []string{"--simulate", "--no-remove", "--only-upgrade", "install"}
	args = append(args, params.Packages...)
	result, err := p.runner.Run(ctx, Command{Path: p.aptGet, Args: args, Timeout: 2 * time.Minute})
	if err != nil {
		return Result{}, fmt.Errorf("apt-get could not construct an upgrade plan: %w", err)
	}
	return Result{Summary: "validated apt upgrade plan for the explicit package list", Details: map[string]any{
		"packages": append([]string(nil), params.Packages...), "outputTruncated": result.OutputTruncated,
	}}, nil
}

func (p *PackageSecurityUpgradePlaybook) Apply(ctx context.Context, invocation Invocation) (ApplyResult, error) {
	params, _ := decodeStrict[PackageSecurityUpgradeParams](invocation.Parameters)
	versions, err := p.installedVersions(ctx, params.Packages)
	if err != nil {
		return ApplyResult{}, err
	}
	state, err := encodeState(packageUpgradeState{Versions: versions})
	if err != nil {
		return ApplyResult{}, err
	}
	args := []string{"-y", "--no-remove", "--only-upgrade", "install"}
	args = append(args, params.Packages...)
	if _, err := p.runner.Run(ctx, Command{Path: p.aptGet, Args: args, Timeout: 10 * time.Minute}); err != nil {
		return ApplyResult{}, fmt.Errorf("explicit package upgrade failed: %w", err)
	}
	return ApplyResult{Result: Result{Summary: "requested packages upgraded", Details: map[string]any{
		"packages": append([]string(nil), params.Packages...),
	}}, State: state}, nil
}

func (p *PackageSecurityUpgradePlaybook) Verify(ctx context.Context, invocation Invocation) (Result, error) {
	params, _ := decodeStrict[PackageSecurityUpgradeParams](invocation.Parameters)
	var state packageUpgradeState
	if err := json.Unmarshal(invocation.State, &state); err != nil || len(state.Versions) == 0 {
		return Result{}, errors.New("invalid package rollback state")
	}
	current, err := p.installedVersions(ctx, params.Packages)
	if err != nil {
		return Result{}, err
	}
	changed := make([]string, 0, len(current))
	unchanged := make([]string, 0, len(current))
	for name, version := range current {
		if previous, ok := state.Versions[name]; ok && previous != version {
			changed = append(changed, name)
		} else {
			unchanged = append(unchanged, name)
		}
	}
	sort.Strings(changed)
	sort.Strings(unchanged)
	return Result{Summary: "all requested packages remain installed after upgrade", Details: map[string]any{
		"upgraded": changed, "alreadyCurrent": unchanged,
	}}, nil
}

func (p *PackageSecurityUpgradePlaybook) Rollback(ctx context.Context, invocation Invocation) (Result, error) {
	params, _ := decodeStrict[PackageSecurityUpgradeParams](invocation.Parameters)
	var state packageUpgradeState
	if err := json.Unmarshal(invocation.State, &state); err != nil || len(state.Versions) == 0 {
		return Result{}, errors.New("invalid package rollback state")
	}
	args := []string{"-y", "--no-remove", "--allow-downgrades", "install"}
	for _, name := range params.Packages {
		version, exists := state.Versions[name]
		if !exists || !debianVersionPattern.MatchString(version) {
			return Result{}, fmt.Errorf("rollback version for %q is missing or unsafe", name)
		}
		args = append(args, name+"="+version)
	}
	if _, err := p.runner.Run(ctx, Command{Path: p.aptGet, Args: args, Timeout: 10 * time.Minute}); err != nil {
		return Result{}, fmt.Errorf("package rollback failed (the previous repository version may no longer be available): %w", err)
	}
	current, err := p.installedVersions(ctx, params.Packages)
	if err != nil {
		return Result{}, err
	}
	for name, expected := range state.Versions {
		if current[name] != expected {
			return Result{}, fmt.Errorf("package %q did not return to its recorded version", name)
		}
	}
	return Result{Summary: "packages restored to their recorded versions", Details: map[string]any{
		"packages": append([]string(nil), params.Packages...),
	}}, nil
}

func (p *PackageSecurityUpgradePlaybook) installedVersions(ctx context.Context, packages []string) (map[string]string, error) {
	versions := make(map[string]string, len(packages))
	for _, name := range packages {
		result, err := p.runner.Run(ctx, Command{
			Path: p.dpkgQuery, Args: []string{"-W", "-f=${db:Status-Abbrev}\t${Version}\n", name}, Timeout: 15 * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("package %q is not installed or dpkg-query failed: %w", name, err)
		}
		fields := strings.Fields(result.Stdout)
		if len(fields) != 2 || fields[0] != "ii" || !debianVersionPattern.MatchString(fields[1]) {
			return nil, fmt.Errorf("package %q did not return a safe installed version", name)
		}
		versions[name] = fields[1]
	}
	return versions, nil
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
