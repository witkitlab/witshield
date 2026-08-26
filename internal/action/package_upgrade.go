package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	debianPackagePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}(?::[a-z0-9][a-z0-9-]{0,31})?$`)
	debianBasePackagePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}$`)
	debianArchitecturePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	debianVersionPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,255}$`)
	packageHookPathPattern    = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)
)

type PackageSecurityUpgradeParams struct {
	Packages []string `json:"packages"`
}

type packageUpgradeState struct {
	Versions        map[string]string `json:"versions,omitempty"`
	AppliedVersions map[string]string `json:"appliedVersions,omitempty"`
	Guarded         bool              `json:"guarded"`
	NoOp            bool              `json:"noOp,omitempty"`
}

type PackageSecurityUpgradePlaybook struct {
	runner    Runner
	aptGet    string
	dpkgQuery string
	hookPath  string
	planDir   string
}

func NewPackageSecurityUpgradePlaybook(runner Runner, aptGet, dpkgQuery, hookPath, planDir string) (*PackageSecurityUpgradePlaybook, error) {
	if runner == nil || !filepath.IsAbs(aptGet) || !filepath.IsAbs(dpkgQuery) || !filepath.IsAbs(hookPath) || !filepath.IsAbs(planDir) {
		return nil, errors.New("package manager and plan guard require absolute configured paths")
	}
	cleanPlanDir := filepath.Clean(planDir)
	if !packageHookPathPattern.MatchString(cleanPlanDir) {
		return nil, errors.New("package plan directory path contains unsupported shell characters")
	}
	resolvedHook, err := filepath.EvalSymlinks(filepath.Clean(hookPath))
	if err != nil {
		return nil, fmt.Errorf("resolve package plan guard executable: %w", err)
	}
	if !packageHookPathPattern.MatchString(resolvedHook) {
		return nil, errors.New("package plan guard executable path contains unsupported shell characters")
	}
	info, err := os.Stat(resolvedHook)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("package plan guard executable is not a regular executable")
	}
	uid, _, ownerErr := ownership(info)
	if ownerErr != nil || uid != os.Geteuid() {
		return nil, errors.New("package plan guard executable has an unexpected owner")
	}
	if err = ensurePackagePlanBase(cleanPlanDir); err != nil {
		return nil, err
	}
	return &PackageSecurityUpgradePlaybook{
		runner: runner, aptGet: filepath.Clean(aptGet), dpkgQuery: filepath.Clean(dpkgQuery),
		hookPath: resolvedHook, planDir: cleanPlanDir,
	}, nil
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
	args := []string{"--simulate", "--no-remove", "--only-upgrade", "-o", "APT::Get::Mark-Auto=true", "install"}
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
	requested, err := p.installedVersions(ctx, params.Packages)
	if err != nil {
		return ApplyResult{}, err
	}
	baseline, err := p.installedPackageVersions(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	for name, version := range requested {
		if baseline[name] != version {
			return ApplyResult{}, fmt.Errorf("package %q changed while capturing its installed baseline", name)
		}
	}
	transactionDir, err := preparePackagePlanTransaction(p.planDir, packagePlanGuardSpec{
		Version: packagePlanGuardVersion, Mode: packagePlanGuardApply, Installed: baseline, Authorized: requested,
	})
	if err != nil {
		return ApplyResult{}, fmt.Errorf("prepare locked package plan guard: %w", err)
	}
	defer os.RemoveAll(transactionDir)
	boundaryState, err := encodeState(packageUpgradeState{Guarded: false})
	if err != nil {
		return ApplyResult{}, err
	}
	args := []string{"-y", "--no-remove", "--only-upgrade", "-o", "APT::Get::Mark-Auto=true"}
	args = append(args, p.packagePlanOptions(transactionDir)...)
	args = append(args, "install")
	args = append(args, params.Packages...)
	_, aptErr := p.runner.Run(ctx, Command{Path: p.aptGet, Args: args, Timeout: 10 * time.Minute})
	guard, guardErr := readPackagePlanGuardResult(transactionDir)
	if guardErr != nil {
		if aptErr != nil && errors.Is(guardErr, os.ErrNotExist) {
			// Once APT has been invoked, a missing hook receipt cannot prove that
			// it failed before every package or maintainer-script mutation. Keep
			// the outcome indeterminate even when APT itself returned an error.
			return ApplyResult{State: boundaryState}, fmt.Errorf("package upgrade stopped without a locked mutation plan receipt: %w", aptErr)
		}
		if aptErr == nil && errors.Is(guardErr, os.ErrNotExist) {
			noOp, noOpErr := p.noOpPackageApply(ctx, baseline, requested, params.Packages)
			if noOpErr != nil {
				// APT reported success after entering the mutation boundary, but the
				// locked hook left no receipt. Only an exact match with the baseline
				// captured before APT may be classified as a no-op. Preserve an
				// intentionally invalid boundary marker so the engine reports every
				// other outcome as indeterminate instead of claiming success.
				return ApplyResult{State: boundaryState}, noOpErr
			}
			return noOp, nil
		}
		return ApplyResult{State: boundaryState}, fmt.Errorf("locked package plan result is unavailable after entering APT: %w", guardErr)
	}
	if !guard.Allowed {
		if aptErr == nil {
			return ApplyResult{State: boundaryState}, errors.New("APT ignored a rejecting package plan guard")
		}
		return ApplyResult{}, fmt.Errorf("locked package plan rejected before mutation: %s", guard.Reason)
	}
	state := packageUpgradeState{Versions: make(map[string]string, len(guard.Plan)), AppliedVersions: make(map[string]string, len(guard.Plan)), Guarded: true}
	for name, transition := range guard.Plan {
		state.Versions[name] = transition.From
		state.AppliedVersions[name] = transition.To
	}
	encodedState, err := encodeState(state)
	if err != nil || len(encodedState) > maxRollbackStateBytes {
		return ApplyResult{State: boundaryState}, errors.New("locked package plan exceeds the bounded rollback state")
	}
	current, observeErr := p.installedPackageVersions(ctx)
	if observeErr != nil {
		return ApplyResult{State: encodedState}, fmt.Errorf("read package versions after the guarded transaction: %w", observeErr)
	}
	for name, transition := range guard.Plan {
		version, installed := current[name]
		if !installed || (version != transition.From && version != transition.To) {
			return ApplyResult{State: encodedState}, fmt.Errorf("package %q has a version outside the locked transaction plan", name)
		}
		if aptErr == nil && version != transition.To {
			return ApplyResult{State: encodedState}, fmt.Errorf("package %q did not reach its locked target version", name)
		}
	}
	if aptErr != nil {
		return ApplyResult{State: encodedState}, fmt.Errorf("guarded package upgrade failed after entering the package transaction: %w", aptErr)
	}
	return ApplyResult{Result: Result{Summary: "requested packages upgraded under the locked APT plan", Details: map[string]any{
		"packages": append([]string(nil), params.Packages...), "transactionPackages": sortedKeys(state.Versions),
	}}, State: encodedState}, nil
}

func (p *PackageSecurityUpgradePlaybook) noOpPackageApply(ctx context.Context, expectedInventory, expectedRequested map[string]string, packages []string) (ApplyResult, error) {
	current, err := p.installedPackageVersions(ctx)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("prove no-op package transaction: %w", err)
	}
	if len(current) != len(expectedInventory) {
		return ApplyResult{}, errors.New("APT completed without a locked package plan receipt and the installed package inventory changed")
	}
	for name, version := range expectedInventory {
		if current[name] != version {
			return ApplyResult{}, fmt.Errorf("APT completed without a locked package plan receipt and package %q changed", name)
		}
	}
	state := packageUpgradeState{Versions: cloneVersionMap(expectedRequested), AppliedVersions: cloneVersionMap(expectedRequested), Guarded: true, NoOp: true}
	encoded, err := encodeState(state)
	if err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{Result: Result{Summary: "requested packages were already current", Details: map[string]any{
		"packages": append([]string(nil), packages...), "transactionPackages": []string{},
	}}, State: encoded}, nil
}

func (p *PackageSecurityUpgradePlaybook) Verify(ctx context.Context, invocation Invocation) (Result, error) {
	state, err := decodePackageUpgradeState(invocation.State)
	if err != nil {
		return Result{}, err
	}
	current, err := p.installedVersions(ctx, sortedKeys(state.Versions))
	if err != nil {
		return Result{}, err
	}
	changed := make([]string, 0, len(current))
	unchanged := make([]string, 0, len(current))
	for name, version := range current {
		if state.AppliedVersions[name] != version {
			return Result{}, fmt.Errorf("package %q changed after apply before verification", name)
		}
		if state.Versions[name] != version {
			changed = append(changed, name)
		} else {
			unchanged = append(unchanged, name)
		}
	}
	sort.Strings(changed)
	sort.Strings(unchanged)
	return Result{Summary: "all transaction packages match the locked APT plan", Details: map[string]any{
		"upgraded": changed, "alreadyCurrent": unchanged,
	}}, nil
}

func (p *PackageSecurityUpgradePlaybook) Rollback(ctx context.Context, invocation Invocation) (Result, error) {
	state, err := decodePackageUpgradeState(invocation.State)
	if err != nil {
		return Result{}, err
	}
	if state.NoOp {
		return Result{Summary: "no package rollback was needed because the guarded action made no package change", Details: map[string]any{"packages": sortedKeys(state.Versions)}}, nil
	}
	current, err := p.installedPackageVersions(ctx)
	if err != nil {
		return Result{}, err
	}
	transitions := make(map[string]packageVersionTransition)
	for name, original := range state.Versions {
		applied := state.AppliedVersions[name]
		version, installed := current[name]
		if !installed || (version != original && version != applied) {
			return Result{}, fmt.Errorf("package %q changed after apply; refusing stale rollback", name)
		}
		if version != original {
			transitions[name] = packageVersionTransition{From: applied, To: original, Direction: ">"}
		}
	}
	if len(transitions) == 0 {
		return Result{Summary: "packages already match their recorded original versions", Details: map[string]any{"packages": sortedKeys(state.Versions)}}, nil
	}
	transactionDir, err := preparePackagePlanTransaction(p.planDir, packagePlanGuardSpec{
		Version: packagePlanGuardVersion, Mode: packagePlanGuardRollback, Transitions: transitions,
	})
	if err != nil {
		return Result{}, fmt.Errorf("prepare locked package rollback guard: %w", err)
	}
	defer os.RemoveAll(transactionDir)
	args := []string{"-y", "--no-remove", "--allow-downgrades", "-o", "APT::Get::Mark-Auto=true"}
	args = append(args, p.packagePlanOptions(transactionDir)...)
	args = append(args, "install")
	for _, name := range sortedTransitionKeys(transitions) {
		args = append(args, name+"="+transitions[name].To)
	}
	_, aptErr := p.runner.Run(ctx, Command{Path: p.aptGet, Args: args, Timeout: 10 * time.Minute})
	guard, guardErr := readPackagePlanGuardResult(transactionDir)
	if guardErr != nil {
		return Result{}, fmt.Errorf("locked package rollback plan is unavailable: %w", guardErr)
	}
	if !guard.Allowed {
		return Result{}, fmt.Errorf("locked package rollback rejected before mutation: %s", guard.Reason)
	}
	current, err = p.installedPackageVersions(ctx)
	if err != nil {
		return Result{}, err
	}
	for name, expected := range state.Versions {
		if current[name] != expected {
			return Result{}, fmt.Errorf("package %q did not return to its recorded version", name)
		}
	}
	if aptErr != nil {
		return Result{}, fmt.Errorf("package rollback command failed even though the recorded versions were observed: %w", aptErr)
	}
	return Result{Summary: "packages restored to their locked pre-transaction versions", Details: map[string]any{
		"packages": sortedKeys(state.Versions),
	}}, nil
}

func (p *PackageSecurityUpgradePlaybook) packagePlanOptions(transactionDir string) []string {
	hookCommand := p.hookPath + " apt-plan-guard " + transactionDir
	return []string{
		"-o", "DPkg::Pre-Install-Pkgs::=" + hookCommand,
		"-o", "DPkg::Tools::options::" + p.hookPath + "::Version=3",
	}
}

func decodePackageUpgradeState(raw json.RawMessage) (packageUpgradeState, error) {
	state, err := decodeStrict[packageUpgradeState](raw)
	if err != nil || !state.Guarded || !validPackageVersionMap(state.Versions) || !validPackageVersionMap(state.AppliedVersions) || len(state.Versions) != len(state.AppliedVersions) {
		return packageUpgradeState{}, errors.New("invalid guarded package rollback state")
	}
	for name := range state.Versions {
		if _, exists := state.AppliedVersions[name]; !exists {
			return packageUpgradeState{}, errors.New("package rollback state lacks an applied-version guard")
		}
	}
	return state, nil
}

func (p *PackageSecurityUpgradePlaybook) installedPackageVersions(ctx context.Context) (map[string]string, error) {
	result, err := p.runner.Run(ctx, Command{
		Path: p.dpkgQuery, Args: []string{"-W", "-f=${db:Status-Abbrev}\t${Package}\t${Architecture}\t${Version}\n"}, Timeout: 45 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("read installed package baseline: %w", err)
	}
	if result.OutputTruncated {
		return nil, errors.New("installed package baseline exceeded the bounded command output")
	}
	versions := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(result.Stdout), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 || !validDpkgStatusAbbrev(fields[0]) || !debianBasePackagePattern.MatchString(fields[1]) || !debianArchitecturePattern.MatchString(fields[2]) {
			return nil, errors.New("dpkg-query returned a malformed installed package baseline")
		}
		status := fields[0]
		if status[1] == 'n' || status[1] == 'c' {
			if fields[3] != "" && !debianVersionPattern.MatchString(fields[3]) {
				return nil, errors.New("dpkg-query returned an unsafe residual package version")
			}
			continue
		}
		if status[1] != 'i' || !debianVersionPattern.MatchString(fields[3]) {
			return nil, errors.New("dpkg-query reported a package in a non-installed or incomplete state")
		}
		name := fields[1] + ":" + fields[2]
		if _, duplicate := versions[name]; duplicate {
			return nil, errors.New("dpkg-query returned a duplicate installed package")
		}
		versions[name] = fields[3]
		if len(versions) > 20_000 {
			return nil, errors.New("installed package baseline exceeds the supported package count")
		}
	}
	if len(versions) == 0 {
		return nil, errors.New("dpkg-query returned an empty installed package baseline")
	}
	return versions, nil
}

func (p *PackageSecurityUpgradePlaybook) installedVersions(ctx context.Context, packages []string) (map[string]string, error) {
	versions := make(map[string]string, len(packages))
	for _, name := range packages {
		result, err := p.runner.Run(ctx, Command{
			Path: p.dpkgQuery, Args: []string{"-W", "-f=${db:Status-Abbrev}\t${Package}\t${Architecture}\t${Version}\n", name}, Timeout: 15 * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("package %q is not installed or dpkg-query failed: %w", name, err)
		}
		lines := strings.Split(strings.TrimSpace(result.Stdout), "\n")
		if len(lines) != 1 {
			return nil, fmt.Errorf("package %q resolved to multiple installed architectures; qualify it explicitly", name)
		}
		fields := strings.Fields(lines[0])
		if len(fields) != 4 || len(fields[0]) != 2 || fields[0][1] != 'i' || !strings.ContainsRune("uihrp", rune(fields[0][0])) ||
			!debianBasePackagePattern.MatchString(fields[1]) || !debianArchitecturePattern.MatchString(fields[2]) || !debianVersionPattern.MatchString(fields[3]) {
			return nil, fmt.Errorf("package %q did not return a safe installed version", name)
		}
		requestedParts := strings.SplitN(name, ":", 2)
		if fields[1] != requestedParts[0] || (len(requestedParts) == 2 && fields[2] != requestedParts[1]) {
			return nil, fmt.Errorf("package %q resolved to an unexpected architecture", name)
		}
		canonical := fields[1] + ":" + fields[2]
		if _, duplicate := versions[canonical]; duplicate {
			return nil, fmt.Errorf("package %q duplicates another requested architecture", name)
		}
		versions[canonical] = fields[3]
	}
	return versions, nil
}

func validDpkgStatusAbbrev(status string) bool {
	return len(status) == 3 && strings.ContainsRune("uihrp", rune(status[0])) && status[2] == ' '
}

func validPackageVersionMap(versions map[string]string) bool {
	if len(versions) == 0 || len(versions) > 20_000 {
		return false
	}
	for name, version := range versions {
		if !isCanonicalDebianPackage(name) || !debianVersionPattern.MatchString(version) {
			return false
		}
	}
	return true
}

func isCanonicalDebianPackage(name string) bool {
	base, architecture, found := strings.Cut(name, ":")
	return found && !strings.Contains(architecture, ":") && debianBasePackagePattern.MatchString(base) && debianArchitecturePattern.MatchString(architecture)
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedTransitionKeys(values map[string]packageVersionTransition) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func cloneVersionMap(values map[string]string) map[string]string {
	clone := make(map[string]string, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}
