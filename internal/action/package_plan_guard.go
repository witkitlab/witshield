package action

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	packagePlanGuardVersion = 1
	packagePlanSpecName     = "spec.json"
	packagePlanResultName   = "result.json"
	maxPackagePlanBytes     = 4 << 20
)

type packagePlanGuardMode string

const (
	packagePlanGuardApply    packagePlanGuardMode = "apply"
	packagePlanGuardRollback packagePlanGuardMode = "rollback"
)

// packageVersionTransition is copied from APT's version-3
// DPkg::Pre-Install-Pkgs stream while APT owns the package-manager lock.  It
// is therefore the authority for both transaction ownership and rollback
// freshness; a pre-lock dpkg-query observation is never enough by itself.
type packageVersionTransition struct {
	From      string `json:"from"`
	To        string `json:"to"`
	Direction string `json:"direction"`
}

type packagePlanGuardSpec struct {
	Version     int                                 `json:"version"`
	Mode        packagePlanGuardMode                `json:"mode"`
	Installed   map[string]string                   `json:"installed,omitempty"`
	Authorized  map[string]string                   `json:"authorized,omitempty"`
	Transitions map[string]packageVersionTransition `json:"transitions,omitempty"`
}

type packagePlanGuardResult struct {
	Version int                                 `json:"version"`
	Allowed bool                                `json:"allowed"`
	Plan    map[string]packageVersionTransition `json:"plan,omitempty"`
	Reason  string                              `json:"reason,omitempty"`
}

func preparePackagePlanTransaction(base string, spec packagePlanGuardSpec) (string, error) {
	if err := validatePackagePlanGuardSpec(spec); err != nil {
		return "", err
	}
	if err := ensurePackagePlanBase(base); err != nil {
		return "", err
	}
	directory, err := os.MkdirTemp(base, "transaction-")
	if err != nil {
		return "", fmt.Errorf("create package plan transaction: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(directory)
		}
	}()
	root, err := os.OpenRoot(directory)
	if err != nil {
		return "", err
	}
	defer root.Close()
	file, err := root.OpenFile(packagePlanSpecName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", err
	}
	encodeErr := json.NewEncoder(file).Encode(spec)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(encodeErr, syncErr, closeErr); err != nil {
		return "", err
	}
	directoryFile, err := root.Open(".")
	if err != nil {
		return "", err
	}
	err = errors.Join(directoryFile.Sync(), directoryFile.Close())
	if err != nil {
		return "", err
	}
	cleanup = false
	return directory, nil
}

func ensurePackagePlanBase(base string) error {
	if !filepath.IsAbs(base) {
		return errors.New("package plan base must be absolute")
	}
	if err := os.MkdirAll(filepath.Clean(base), 0o700); err != nil {
		return fmt.Errorf("create package plan base: %w", err)
	}
	info, err := os.Lstat(filepath.Clean(base))
	if err != nil {
		return err
	}
	uid, _, ownerErr := ownership(info)
	if ownerErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 || uid != os.Geteuid() {
		return errors.New("package plan base is not a private directory owned by the helper")
	}
	return nil
}

func readPackagePlanGuardResult(directory string) (packagePlanGuardResult, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return packagePlanGuardResult{}, err
	}
	defer root.Close()
	file, err := root.OpenFile(packagePlanResultName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return packagePlanGuardResult{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return packagePlanGuardResult{}, err
	}
	uid, _, ownerErr := ownership(info)
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || uid != os.Geteuid() || !statOK || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > maxPackagePlanBytes {
		return packagePlanGuardResult{}, errors.New("package plan guard result failed ownership or shape validation")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxPackagePlanBytes+1))
	decoder.DisallowUnknownFields()
	var result packagePlanGuardResult
	if err = decoder.Decode(&result); err != nil {
		return packagePlanGuardResult{}, err
	}
	if err = ensureJSONReaderEOF(decoder); err != nil {
		return packagePlanGuardResult{}, err
	}
	if result.Version != packagePlanGuardVersion || (len(result.Plan) > 0 && !validPackageTransitions(result.Plan)) || (result.Allowed && len(result.Plan) == 0) || (!result.Allowed && result.Reason == "") {
		return packagePlanGuardResult{}, errors.New("invalid package plan guard result")
	}
	return result, nil
}

// RunPackagePlanGuard is the deliberately tiny APT hook entry point used by
// witshield-helper. APT invokes it after acquiring its frontend lock and
// before dpkg mutates the host. The hook durably records the exact plan and
// exits non-zero whenever it cannot prove that the transaction is fresh and
// reversible.
func RunPackagePlanGuard(input io.Reader, transactionDir, allowedBase string) error {
	directory, err := validatePackagePlanDirectory(transactionDir, allowedBase)
	if err != nil {
		return err
	}
	spec, err := readPackagePlanGuardSpec(directory)
	if err != nil {
		return err
	}
	plan, parseErr := parseAPTVersion3Plan(input)
	result := packagePlanGuardResult{Version: packagePlanGuardVersion}
	if parseErr != nil {
		result.Reason = "APT supplied an invalid or incomplete locked transaction plan"
	} else if validateErr := validateLockedPackagePlan(spec, plan); validateErr != nil {
		result.Reason = validateErr.Error()
	} else {
		result.Allowed = true
		result.Plan = plan
	}
	if writeErr := writePackagePlanGuardResult(directory, result); writeErr != nil {
		return fmt.Errorf("persist locked APT plan: %w", writeErr)
	}
	if !result.Allowed {
		return errors.New(result.Reason)
	}
	return nil
}

func validatePackagePlanDirectory(transactionDir, allowedBase string) (string, error) {
	if !filepath.IsAbs(transactionDir) || !filepath.IsAbs(allowedBase) {
		return "", errors.New("package plan paths must be absolute")
	}
	base, err := filepath.EvalSymlinks(filepath.Clean(allowedBase))
	if err != nil {
		return "", fmt.Errorf("resolve package plan base: %w", err)
	}
	directory, err := filepath.EvalSymlinks(filepath.Clean(transactionDir))
	if err != nil {
		return "", fmt.Errorf("resolve package plan transaction: %w", err)
	}
	if !pathWithin(base, directory) {
		return "", errors.New("package plan transaction escaped its private base directory")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return "", fmt.Errorf("inspect package plan transaction: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("package plan transaction directory is not a private real directory")
	}
	uid, _, err := ownership(info)
	if err != nil || uid != os.Geteuid() {
		return "", errors.New("package plan transaction directory has an unexpected owner")
	}
	return directory, nil
}

func readPackagePlanGuardSpec(directory string) (packagePlanGuardSpec, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return packagePlanGuardSpec{}, fmt.Errorf("open package plan guard root: %w", err)
	}
	defer root.Close()
	file, err := root.OpenFile(packagePlanSpecName, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return packagePlanGuardSpec{}, fmt.Errorf("open package plan guard specification: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return packagePlanGuardSpec{}, err
	}
	uid, _, ownerErr := ownership(info)
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if ownerErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || uid != os.Geteuid() || !statOK || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > maxPackagePlanBytes {
		return packagePlanGuardSpec{}, errors.New("package plan guard specification failed ownership or shape validation")
	}
	limited := io.LimitReader(file, maxPackagePlanBytes+1)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var spec packagePlanGuardSpec
	if err = decoder.Decode(&spec); err != nil {
		return packagePlanGuardSpec{}, fmt.Errorf("decode package plan guard specification: %w", err)
	}
	if err = ensureJSONReaderEOF(decoder); err != nil {
		return packagePlanGuardSpec{}, fmt.Errorf("decode package plan guard specification: %w", err)
	}
	if err = validatePackagePlanGuardSpec(spec); err != nil {
		return packagePlanGuardSpec{}, err
	}
	return spec, nil
}

func validatePackagePlanGuardSpec(spec packagePlanGuardSpec) error {
	if spec.Version != packagePlanGuardVersion {
		return errors.New("unsupported package plan guard specification version")
	}
	switch spec.Mode {
	case packagePlanGuardApply:
		if !validPackageVersionMap(spec.Installed) || !validPackageVersionMap(spec.Authorized) || len(spec.Authorized) > 64 || len(spec.Transitions) != 0 {
			return errors.New("invalid apply package plan guard baseline")
		}
		for name, version := range spec.Authorized {
			if spec.Installed[name] != version {
				return errors.New("authorized package set does not match the installed baseline")
			}
		}
	case packagePlanGuardRollback:
		if len(spec.Installed) != 0 || len(spec.Authorized) != 0 || len(spec.Transitions) == 0 || len(spec.Transitions) > 512 || !validPackageTransitions(spec.Transitions) {
			return errors.New("invalid rollback package plan guard transitions")
		}
	default:
		return errors.New("invalid package plan guard mode")
	}
	return nil
}

func parseAPTVersion3Plan(input io.Reader) (map[string]packageVersionTransition, error) {
	reader := bufio.NewReader(io.LimitReader(input, maxPackagePlanBytes+1))
	line, err := readBoundedPlanLine(reader)
	if err != nil || line != "VERSION 3" {
		return nil, errors.New("APT plan is not version 3")
	}
	for {
		line, err = readBoundedPlanLine(reader)
		if err != nil {
			return nil, errors.New("APT plan ended before its configuration delimiter")
		}
		if line == "" {
			break
		}
		if !strings.Contains(line, "=") || strings.ContainsRune(line, '\x00') {
			return nil, errors.New("APT plan contains a malformed configuration line")
		}
	}
	plan := make(map[string]packageVersionTransition)
	configured := make(map[string]packageVersionTransition)
	for {
		line, err = readBoundedPlanLine(reader)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 9 || !debianBasePackagePattern.MatchString(fields[0]) || (fields[4] != "<" && fields[4] != "=" && fields[4] != ">") {
			return nil, errors.New("APT plan contains a malformed package action")
		}
		oldSide, oldErr := parseAPTVersion3Side(fields[1], fields[2], fields[3])
		newSide, newErr := parseAPTVersion3Side(fields[5], fields[6], fields[7])
		if oldErr != nil || newErr != nil || (!oldSide.present && !newSide.present) {
			return nil, errors.New("APT plan contains an invalid version, architecture, or Multi-Arch tuple")
		}
		if oldSide.present && newSide.present && (oldSide.architecture != newSide.architecture || oldSide.multiArch != newSide.multiArch) {
			return nil, errors.New("APT plan changes package architecture or Multi-Arch type")
		}
		architecture := oldSide.architecture
		if !oldSide.present {
			architecture = newSide.architecture
		}
		name := fields[0] + ":" + architecture
		transition := packageVersionTransition{From: fields[1], To: fields[5], Direction: fields[4]}
		if fields[8] == "**CONFIGURE**" {
			if previous, duplicate := configured[name]; duplicate && previous != transition {
				return nil, errors.New("APT plan contains conflicting configure actions")
			}
			configured[name] = transition
			continue
		}
		if fields[8] != "**REMOVE**" && (!filepath.IsAbs(fields[8]) || !strings.HasSuffix(fields[8], ".deb")) {
			return nil, errors.New("APT plan contains an unsupported package action")
		}
		if previous, duplicate := plan[name]; duplicate && previous != transition {
			return nil, errors.New("APT plan contains conflicting package transitions")
		}
		plan[name] = transition
		if len(plan) > 512 {
			return nil, errors.New("APT plan exceeds the supported transaction size")
		}
	}
	for name, transition := range configured {
		if archived, exists := plan[name]; !exists || archived != transition {
			return nil, errors.New("APT plan contains an unpaired configure action")
		}
	}
	if len(plan) == 0 {
		return nil, errors.New("APT plan did not contain a package transition")
	}
	return plan, nil
}

func readBoundedPlanLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if len(line) > 64<<10 {
		return "", errors.New("APT plan contains an oversized line")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if errors.Is(err, io.EOF) && line != "" {
		return line, nil
	}
	return line, err
}

type aptVersion3Side struct {
	present      bool
	architecture string
	multiArch    string
}

func parseAPTVersion3Side(version, architecture, multiArch string) (aptVersion3Side, error) {
	if version == "-" {
		if architecture != "-" || (multiArch != "none" && multiArch != "no") {
			return aptVersion3Side{}, errors.New("absent APT version has inconsistent metadata")
		}
		return aptVersion3Side{}, nil
	}
	if !debianVersionPattern.MatchString(version) || !debianArchitecturePattern.MatchString(architecture) {
		return aptVersion3Side{}, errors.New("invalid APT version or architecture")
	}
	if multiArch == "none" {
		multiArch = "no"
	}
	if multiArch != "same" && multiArch != "foreign" && multiArch != "allowed" && multiArch != "no" {
		return aptVersion3Side{}, errors.New("invalid APT Multi-Arch type")
	}
	return aptVersion3Side{present: true, architecture: architecture, multiArch: multiArch}, nil
}

func validateLockedPackagePlan(spec packagePlanGuardSpec, plan map[string]packageVersionTransition) error {
	switch spec.Mode {
	case packagePlanGuardApply:
		for name, transition := range plan {
			authorizedVersion, authorized := spec.Authorized[name]
			if !authorized {
				return fmt.Errorf("package %q is outside the explicitly authorized package set", name)
			}
			baseline, installed := spec.Installed[name]
			if !installed || transition.From == "-" || transition.To == "-" {
				return fmt.Errorf("package %q would be newly installed or removed; refusing a non-reversible upgrade", name)
			}
			if transition.From != baseline || transition.From != authorizedVersion {
				return fmt.Errorf("package %q changed while waiting for the APT lock", name)
			}
			if transition.From == transition.To || transition.Direction != "<" {
				return fmt.Errorf("package %q would not be upgraded monotonically", name)
			}
		}
	case packagePlanGuardRollback:
		for name, transition := range plan {
			expected, exists := spec.Transitions[name]
			if !exists {
				return fmt.Errorf("rollback would mutate unrecorded package %q", name)
			}
			if transition != expected {
				return fmt.Errorf("package %q changed while waiting for the APT rollback lock", name)
			}
			if transition.From == "-" || transition.To == "-" || transition.From == transition.To || transition.Direction != ">" {
				return fmt.Errorf("rollback would install or remove package %q", name)
			}
		}
	default:
		return errors.New("invalid package plan guard mode")
	}
	return nil
}

func validPackageTransitions(transitions map[string]packageVersionTransition) bool {
	for name, transition := range transitions {
		if !isCanonicalDebianPackage(name) || !debianVersionPattern.MatchString(transition.From) || !debianVersionPattern.MatchString(transition.To) ||
			transition.From == transition.To || (transition.Direction != "<" && transition.Direction != ">") {
			return false
		}
	}
	return true
}

func writePackagePlanGuardResult(directory string, result packagePlanGuardResult) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := root.OpenFile(packagePlanResultName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encodeErr := encoder.Encode(result)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(encodeErr, syncErr, closeErr); err != nil {
		return err
	}
	directoryFile, err := root.Open(".")
	if err != nil {
		return err
	}
	err = directoryFile.Sync()
	return errors.Join(err, directoryFile.Close())
}

func ensureJSONReaderEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}
