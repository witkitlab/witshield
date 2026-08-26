package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type FilePermissionRepairParams struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	UID  *int   `json:"uid,omitempty"`
	GID  *int   `json:"gid,omitempty"`
}

const (
	DefaultPermissionRepairSSHPath   = "/etc/ssh/sshd_config"
	DefaultPermissionRepairTokenPath = "/etc/witshield/helper.token"
)

// DefaultPermissionRepairRoots is the shared privilege boundary used by both
// the Controller's pre-approval validation and the root Helper. Return a fresh
// slice so callers cannot mutate the process-wide policy.
func DefaultPermissionRepairRoots() []string {
	return []string{"/etc/witshield", "/var/lib/witshield", "/var/lib/witshield-agent"}
}

// IsDefaultPermissionRepairPath reports whether a single target is within the
// default Helper allowlist. It deliberately excludes the Helper's own state;
// the network-facing Controller must never authorize changes to that trust
// boundary.
func IsDefaultPermissionRepairPath(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	cleaned := filepath.Clean(path)
	if protectedPermissionRepairPath(cleaned) {
		return false
	}
	if cleaned == DefaultPermissionRepairSSHPath {
		return true
	}
	for _, root := range DefaultPermissionRepairRoots() {
		if cleaned == root || pathWithin(root, cleaned) {
			return true
		}
	}
	return false
}

// ApprovedPath is an explicit privilege boundary. Descendants does not mean a
// recursive chmod; it only permits a single requested descendant per action.
type ApprovedPath struct {
	Path           string
	Descendants    bool
	FileModes      []fs.FileMode
	DirectoryModes []fs.FileMode
	UIDs           []int
	GIDs           []int
	resolved       string
}

type filePermissionState struct {
	Path            string      `json:"path"`
	Device          uint64      `json:"device"`
	Inode           uint64      `json:"inode"`
	Mode            fs.FileMode `json:"mode"`
	UID             int         `json:"uid"`
	GID             int         `json:"gid"`
	AppliedMode     fs.FileMode `json:"appliedMode"`
	AppliedUID      int         `json:"appliedUid"`
	AppliedGID      int         `json:"appliedGid"`
	AppliedComplete bool        `json:"appliedComplete,omitempty"`
}

type FilePermissionRepairPlaybook struct {
	approved            []ApprovedPath
	beforeOpen          func(Operation)
	beforeMetadataWrite func(Operation)
	afterMetadataWrite  func(Operation)
}

func NewFilePermissionRepairPlaybook(approved []ApprovedPath) (*FilePermissionRepairPlaybook, error) {
	if len(approved) == 0 {
		return nil, errors.New("at least one approved path is required")
	}
	prepared := make([]ApprovedPath, len(approved))
	for index, rule := range approved {
		if !filepath.IsAbs(rule.Path) || filepath.Clean(rule.Path) == string(filepath.Separator) {
			return nil, fmt.Errorf("approved path %d must be an absolute non-root path", index)
		}
		rule.Path = filepath.Clean(rule.Path)
		resolved, err := filepath.EvalSymlinks(rule.Path)
		if err != nil {
			return nil, fmt.Errorf("resolve approved path %q: %w", rule.Path, err)
		}
		rule.resolved = filepath.Clean(resolved)
		if len(rule.FileModes) == 0 && len(rule.DirectoryModes) == 0 {
			return nil, fmt.Errorf("approved path %q has no allowed modes", rule.Path)
		}
		if err := validateAllowedModes(rule.FileModes); err != nil {
			return nil, fmt.Errorf("approved path %q file modes: %w", rule.Path, err)
		}
		if err := validateAllowedModes(rule.DirectoryModes); err != nil {
			return nil, fmt.Errorf("approved path %q directory modes: %w", rule.Path, err)
		}
		prepared[index] = rule
	}
	sort.Slice(prepared, func(i, j int) bool { return len(prepared[i].resolved) > len(prepared[j].resolved) })
	return &FilePermissionRepairPlaybook{approved: prepared}, nil
}

func validateAllowedModes(modes []fs.FileMode) error {
	for _, mode := range modes {
		if mode&^fs.FileMode(0777) != 0 {
			return fmt.Errorf("mode %v includes non-permission or special bits", mode)
		}
	}
	return nil
}

func (p *FilePermissionRepairPlaybook) Type() Type { return TypeFilePermissionRepair }

func (p *FilePermissionRepairPlaybook) Validate(raw json.RawMessage) error {
	params, err := decodeStrict[FilePermissionRepairParams](raw)
	if err != nil {
		return err
	}
	_, _, _, err = p.validateTarget(params)
	return err
}

func (p *FilePermissionRepairPlaybook) validateTarget(params FilePermissionRepairParams) (string, fs.FileMode, ApprovedPath, error) {
	if !filepath.IsAbs(params.Path) {
		return "", 0, ApprovedPath{}, errors.New("path must be absolute")
	}
	cleaned := filepath.Clean(params.Path)
	if protectedPermissionRepairPath(cleaned) {
		return "", 0, ApprovedPath{}, errors.New("permission target is protected Helper trust state")
	}
	info, err := os.Lstat(cleaned)
	if err != nil {
		return "", 0, ApprovedPath{}, fmt.Errorf("inspect permission target: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || (!info.Mode().IsRegular() && !info.IsDir()) {
		return "", 0, ApprovedPath{}, errors.New("permission target must be a regular file or directory, not a symlink or special file")
	}
	if hasSpecialModeBits(info.Mode()) {
		return "", 0, ApprovedPath{}, errors.New("permission target has setuid, setgid, or sticky bits and is outside the repair model")
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", 0, ApprovedPath{}, fmt.Errorf("resolve permission target: %w", err)
	}
	resolved = filepath.Clean(resolved)
	if protectedPermissionRepairPath(resolved) {
		return "", 0, ApprovedPath{}, errors.New("permission target resolves to protected Helper trust state")
	}
	var selected *ApprovedPath
	for index := range p.approved {
		rule := &p.approved[index]
		if resolved == rule.resolved || (rule.Descendants && pathWithin(rule.resolved, resolved)) {
			selected = rule
			break
		}
	}
	if selected == nil {
		return "", 0, ApprovedPath{}, errors.New("path is outside the approved permission-repair roots")
	}
	modeValue := strings.TrimPrefix(params.Mode, "0o")
	if len(modeValue) < 3 || len(modeValue) > 4 || strings.Trim(modeValue, "01234567") != "" {
		return "", 0, ApprovedPath{}, errors.New("mode must be a three or four digit octal permission value")
	}
	parsed, err := strconv.ParseUint(modeValue, 8, 12)
	if err != nil || parsed > 0777 {
		return "", 0, ApprovedPath{}, errors.New("special permission bits are not allowed")
	}
	mode := fs.FileMode(parsed)
	allowedModes := selected.FileModes
	if info.IsDir() {
		allowedModes = selected.DirectoryModes
	}
	if !modeAllowed(mode, allowedModes) {
		return "", 0, ApprovedPath{}, fmt.Errorf("mode %04o is not approved for this target type", mode)
	}
	if params.UID != nil && (*params.UID < 0 || !integerAllowed(*params.UID, selected.UIDs)) {
		return "", 0, ApprovedPath{}, errors.New("requested UID is not approved for this path")
	}
	if params.GID != nil && (*params.GID < 0 || !integerAllowed(*params.GID, selected.GIDs)) {
		return "", 0, ApprovedPath{}, errors.New("requested GID is not approved for this path")
	}
	return resolved, mode, *selected, nil
}

func protectedPermissionRepairPath(path string) bool {
	return filepath.Clean(path) == DefaultPermissionRepairTokenPath
}

func (p *FilePermissionRepairPlaybook) Precheck(_ context.Context, invocation Invocation) (Result, error) {
	params, _ := decodeStrict[FilePermissionRepairParams](invocation.Parameters)
	path, mode, _, err := p.validateTarget(params)
	if err != nil {
		return Result{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return Result{}, err
	}
	return Result{Summary: "permission target is inside an approved root", Details: map[string]any{
		"path": path, "currentMode": fmt.Sprintf("%04o", info.Mode().Perm()), "requestedMode": fmt.Sprintf("%04o", mode),
	}}, nil
}

func (p *FilePermissionRepairPlaybook) Preview(_ context.Context, invocation Invocation) (Result, error) {
	params, _ := decodeStrict[FilePermissionRepairParams](invocation.Parameters)
	path, mode, _, err := p.validateTarget(params)
	if err != nil {
		return Result{}, err
	}
	details := map[string]any{"path": path, "mode": fmt.Sprintf("%04o", mode), "singleTarget": true}
	if params.UID != nil {
		details["uid"] = *params.UID
	}
	if params.GID != nil {
		details["gid"] = *params.GID
	}
	return Result{Summary: "repair permissions on one approved file or directory", Details: details}, nil
}

func (p *FilePermissionRepairPlaybook) Apply(_ context.Context, invocation Invocation) (ApplyResult, error) {
	params, _ := decodeStrict[FilePermissionRepairParams](invocation.Parameters)
	path, mode, rule, err := p.validateTarget(params)
	if err != nil {
		return ApplyResult{}, err
	}
	if p.beforeOpen != nil {
		p.beforeOpen(OperationApply)
	}
	file, err := openValidatedTarget(rule.resolved, path)
	if err != nil {
		return ApplyResult{}, fmt.Errorf("open permission target: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return ApplyResult{}, err
	}
	if hasSpecialModeBits(info.Mode()) {
		return ApplyResult{}, errors.New("permission target gained setuid, setgid, or sticky bits during validation")
	}
	if !modeAllowedForTarget(info, mode, rule) {
		return ApplyResult{}, errors.New("permission target type changed after validation and the requested mode is not approved for its actual type")
	}
	uid, gid, err := ownership(info)
	if err != nil {
		return ApplyResult{}, err
	}
	device, inode, err := fileIdentity(info)
	if err != nil {
		return ApplyResult{}, err
	}
	targetUID, targetGID := uid, gid
	if params.UID != nil {
		targetUID = *params.UID
	}
	if params.GID != nil {
		targetGID = *params.GID
	}
	stateValue := filePermissionState{
		Path: path, Device: device, Inode: inode, Mode: info.Mode().Perm(), UID: uid, GID: gid,
		AppliedMode: mode, AppliedUID: targetUID, AppliedGID: targetGID,
	}
	state, err := encodeState(stateValue)
	if err != nil {
		return ApplyResult{}, err
	}
	if p.beforeMetadataWrite != nil {
		p.beforeMetadataWrite(OperationApply)
	}
	original := openedPermissionTuple{Device: device, Inode: inode, Mode: info.Mode().Perm(), UID: uid, GID: gid, Directory: info.IsDir()}
	target := original
	target.Mode, target.UID, target.GID = mode, targetUID, targetGID
	if err := verifyPermissionPath(rule.resolved, path, original); err != nil {
		return ApplyResult{}, fmt.Errorf("permission target changed before metadata mutation: %w", err)
	}
	if err := mutateOpenedPermissionTuple(file, original, target); err != nil {
		if restoreErr := restoreRecognizedOpenedPermissionTuple(file, original, target, original); restoreErr == nil {
			return ApplyResult{}, fmt.Errorf("change approved target permissions failed and the opened inode was restored: %w", err)
		} else {
			return ApplyResult{State: state}, fmt.Errorf("change approved target permissions failed and direct restoration was incomplete: %w", errors.Join(err, restoreErr))
		}
	}
	if p.afterMetadataWrite != nil {
		p.afterMetadataWrite(OperationApply)
	}
	if err := verifyPermissionPath(rule.resolved, path, target); err != nil {
		if restoreErr := restoreExactOpenedPermissionTuple(file, target, original); restoreErr == nil {
			return ApplyResult{}, fmt.Errorf("permission target pathname changed during apply; the opened inode was restored: %w", err)
		} else {
			return ApplyResult{State: state}, fmt.Errorf("permission target pathname changed during apply and the opened inode could not be safely restored: %w", errors.Join(err, restoreErr))
		}
	}
	stateValue.AppliedComplete = true
	state, err = encodeState(stateValue)
	if err != nil {
		return ApplyResult{State: state}, fmt.Errorf("encode completed permission rollback state: %w", err)
	}
	return ApplyResult{Result: Result{Summary: "approved file permissions repaired", Details: map[string]any{
		"path": path, "mode": fmt.Sprintf("%04o", mode),
	}}, State: state}, nil
}

func (p *FilePermissionRepairPlaybook) Verify(_ context.Context, invocation Invocation) (Result, error) {
	state, err := decodeStrict[filePermissionState](invocation.State)
	if err != nil {
		return Result{}, errors.New("invalid file permission rollback state")
	}
	params, _ := decodeStrict[FilePermissionRepairParams](invocation.Parameters)
	path, mode, rule, err := p.validateTarget(params)
	if err != nil {
		return Result{}, err
	}
	if state.Path != path || state.AppliedMode != mode {
		return Result{}, errors.New("file permission state does not match the request")
	}
	if p.beforeOpen != nil {
		p.beforeOpen(OperationVerify)
	}
	file, err := openValidatedTarget(rule.resolved, path)
	if err != nil {
		return Result{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Result{}, err
	}
	uid, gid, err := ownership(info)
	if err != nil {
		return Result{}, err
	}
	device, inode, err := fileIdentity(info)
	if err != nil {
		return Result{}, err
	}
	if device != state.Device || inode != state.Inode {
		return Result{}, errors.New("permission target was replaced after apply")
	}
	if hasSpecialModeBits(info.Mode()) {
		return Result{}, errors.New("permission target gained special bits after apply")
	}
	if info.Mode().Perm() != state.AppliedMode || uid != state.AppliedUID || gid != state.AppliedGID {
		return Result{}, errors.New("file permission verification did not observe the requested mode and ownership")
	}
	return Result{Summary: "file mode and ownership match the approved request", Details: map[string]any{
		"path": path, "mode": fmt.Sprintf("%04o", info.Mode().Perm()),
	}}, nil
}

func (p *FilePermissionRepairPlaybook) Rollback(_ context.Context, invocation Invocation) (Result, error) {
	state, err := decodeStrict[filePermissionState](invocation.State)
	if err != nil || state.Mode&^fs.FileMode(0777) != 0 || state.UID < 0 || state.GID < 0 {
		return Result{}, errors.New("invalid file permission rollback state")
	}
	params, _ := decodeStrict[FilePermissionRepairParams](invocation.Parameters)
	path, _, rule, err := p.validateTarget(params)
	if err != nil {
		return Result{}, err
	}
	if state.Path != path {
		return Result{}, errors.New("file permission rollback target does not match the request")
	}
	if p.beforeOpen != nil {
		p.beforeOpen(OperationRollback)
	}
	file, err := openValidatedTarget(rule.resolved, path)
	if err != nil {
		return Result{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Result{}, err
	}
	uid, gid, err := ownership(info)
	if err != nil {
		return Result{}, err
	}
	device, inode, err := fileIdentity(info)
	if err != nil {
		return Result{}, err
	}
	if device != state.Device || inode != state.Inode {
		return Result{}, errors.New("permission target was replaced after apply; refusing stale rollback")
	}
	if hasSpecialModeBits(info.Mode()) {
		return Result{}, errors.New("permission target gained special bits after apply; refusing stale rollback")
	}
	if !permissionRollbackMetadataRecognized(state, info.Mode().Perm(), uid, gid) {
		return Result{}, errors.New("permission target has an unrecognized partial state; refusing rollback")
	}
	if p.beforeMetadataWrite != nil {
		p.beforeMetadataWrite(OperationRollback)
	}
	guard := openedPermissionTuple{Device: device, Inode: inode, Mode: info.Mode().Perm(), UID: uid, GID: gid, Directory: info.IsDir()}
	original := openedPermissionTuple{Device: state.Device, Inode: state.Inode, Mode: state.Mode, UID: state.UID, GID: state.GID, Directory: info.IsDir()}
	if err := verifyPermissionPath(rule.resolved, path, guard); err != nil {
		return Result{}, fmt.Errorf("permission target changed before rollback metadata mutation: %w", err)
	}
	if err := mutateOpenedPermissionTuple(file, guard, original); err != nil {
		if restoreErr := restoreRecognizedOpenedPermissionTuple(file, guard, original, guard); restoreErr != nil {
			return Result{}, fmt.Errorf("restore file permissions failed and the opened inode could not return to its pre-rollback tuple: %w", errors.Join(err, restoreErr))
		}
		return Result{}, fmt.Errorf("restore file permissions failed without leaving the opened inode changed: %w", err)
	}
	if p.afterMetadataWrite != nil {
		p.afterMetadataWrite(OperationRollback)
	}
	if err := verifyPermissionPath(rule.resolved, path, original); err != nil {
		if restoreErr := restoreExactOpenedPermissionTuple(file, original, guard); restoreErr != nil {
			return Result{}, fmt.Errorf("permission pathname changed during rollback and the opened inode could not return to its pre-rollback tuple: %w", errors.Join(err, restoreErr))
		}
		return Result{}, fmt.Errorf("permission pathname changed during rollback; the opened inode was returned to its pre-rollback tuple: %w", err)
	}
	return Result{Summary: "original file mode and ownership restored", Details: map[string]any{
		"path": path, "mode": fmt.Sprintf("%04o", state.Mode),
	}}, nil
}

type openedPermissionTuple struct {
	Device    uint64
	Inode     uint64
	Mode      fs.FileMode
	UID       int
	GID       int
	Directory bool
}

func openedPermissionTupleFor(file *os.File) (openedPermissionTuple, error) {
	info, err := file.Stat()
	if err != nil {
		return openedPermissionTuple{}, err
	}
	if hasSpecialModeBits(info.Mode()) || (!info.Mode().IsRegular() && !info.IsDir()) {
		return openedPermissionTuple{}, errors.New("opened permission target has unsupported type or special bits")
	}
	device, inode, err := fileIdentity(info)
	if err != nil {
		return openedPermissionTuple{}, err
	}
	uid, gid, err := ownership(info)
	if err != nil {
		return openedPermissionTuple{}, err
	}
	return openedPermissionTuple{Device: device, Inode: inode, Mode: info.Mode().Perm(), UID: uid, GID: gid, Directory: info.IsDir()}, nil
}

func verifyExactOpenedPermissionTuple(file *os.File, expected openedPermissionTuple) error {
	observed, err := openedPermissionTupleFor(file)
	if err != nil {
		return err
	}
	if observed != expected {
		return errors.New("opened permission target changed since its metadata guard")
	}
	return nil
}

func mutateOpenedPermissionTuple(file *os.File, expected, target openedPermissionTuple) error {
	if expected.Device != target.Device || expected.Inode != target.Inode || expected.Directory != target.Directory {
		return errors.New("permission metadata mutation cannot change target identity or type")
	}
	if err := verifyExactOpenedPermissionTuple(file, expected); err != nil {
		return err
	}
	if expected.UID != target.UID || expected.GID != target.GID {
		if err := file.Chown(target.UID, target.GID); err != nil {
			return fmt.Errorf("change opened target ownership: %w", err)
		}
	}
	if expected.Mode != target.Mode {
		if err := file.Chmod(target.Mode); err != nil {
			return fmt.Errorf("change opened target mode: %w", err)
		}
	}
	return verifyExactOpenedPermissionTuple(file, target)
}

func restoreExactOpenedPermissionTuple(file *os.File, expected, target openedPermissionTuple) error {
	if err := verifyExactOpenedPermissionTuple(file, expected); err != nil {
		return err
	}
	return setAndVerifyOpenedPermissionTuple(file, target)
}

func restoreRecognizedOpenedPermissionTuple(file *os.File, first, second, target openedPermissionTuple) error {
	observed, err := openedPermissionTupleFor(file)
	if err != nil {
		return err
	}
	ownershipRecognized := (observed.UID == first.UID && observed.GID == first.GID) || (observed.UID == second.UID && observed.GID == second.GID)
	if observed.Device != target.Device || observed.Inode != target.Inode || observed.Directory != target.Directory ||
		(observed.Mode != first.Mode && observed.Mode != second.Mode) || !ownershipRecognized {
		return errors.New("opened permission target entered an unrecognized metadata state")
	}
	return setAndVerifyOpenedPermissionTuple(file, target)
}

func setAndVerifyOpenedPermissionTuple(file *os.File, target openedPermissionTuple) error {
	observed, err := openedPermissionTupleFor(file)
	if err != nil {
		return err
	}
	if observed.Device != target.Device || observed.Inode != target.Inode || observed.Directory != target.Directory {
		return errors.New("opened permission target identity changed before restoration")
	}
	if observed.UID != target.UID || observed.GID != target.GID {
		if err = file.Chown(target.UID, target.GID); err != nil {
			return err
		}
	}
	if observed.Mode != target.Mode {
		if err = file.Chmod(target.Mode); err != nil {
			return err
		}
	}
	return verifyExactOpenedPermissionTuple(file, target)
}

func verifyPermissionPath(approvedRoot, path string, expected openedPermissionTuple) error {
	file, err := openValidatedTarget(approvedRoot, path)
	if err != nil {
		return err
	}
	defer file.Close()
	observed, err := openedPermissionTupleFor(file)
	if err != nil {
		return err
	}
	if observed.Device != expected.Device || observed.Inode != expected.Inode {
		return errors.New("permission target pathname now resolves to a replacement inode")
	}
	if observed != expected {
		return errors.New("permission target pathname does not expose the expected mode and ownership")
	}
	return nil
}

func hasSpecialModeBits(mode fs.FileMode) bool {
	return mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0
}

func modeAllowedForTarget(info fs.FileInfo, mode fs.FileMode, rule ApprovedPath) bool {
	if info.IsDir() {
		return modeAllowed(mode, rule.DirectoryModes)
	}
	return info.Mode().IsRegular() && modeAllowed(mode, rule.FileModes)
}

func permissionRollbackMetadataRecognized(state filePermissionState, mode fs.FileMode, uid, gid int) bool {
	originalMetadata := mode == state.Mode && uid == state.UID && gid == state.GID
	appliedMetadata := mode == state.AppliedMode && uid == state.AppliedUID && gid == state.AppliedGID
	if state.AppliedComplete {
		return originalMetadata || appliedMetadata
	}
	ownershipRecognized := (uid == state.UID && gid == state.GID) || (uid == state.AppliedUID && gid == state.AppliedGID)
	return (mode == state.Mode || mode == state.AppliedMode) && ownershipRecognized
}

func pathWithin(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func modeAllowed(mode fs.FileMode, allowed []fs.FileMode) bool {
	for _, candidate := range allowed {
		if mode == candidate {
			return true
		}
	}
	return false
}

func integerAllowed(value int, allowed []int) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func ownership(info fs.FileInfo) (int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("file ownership is unavailable on this platform")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

func fileIdentity(info fs.FileInfo) (uint64, uint64, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("file identity is unavailable on this platform")
	}
	device, err := strconv.ParseUint(fmt.Sprint(stat.Dev), 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid file device identifier: %w", err)
	}
	inode, err := strconv.ParseUint(fmt.Sprint(stat.Ino), 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid file inode identifier: %w", err)
	}
	return device, inode, nil
}

func openValidatedTarget(approvedRoot, path string) (*os.File, error) {
	file, err := openBeneath(approvedRoot, path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !opened.Mode().IsRegular() && !opened.IsDir() {
		file.Close()
		return nil, errors.New("permission target changed to a special file during validation")
	}
	return file, nil
}
