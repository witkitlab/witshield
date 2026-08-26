package action

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFilePermissionRepairIsConstrainedAndReversible(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "secret.env")
	if err := os.WriteFile(target, []byte("not-a-real-secret"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0666); err != nil {
		t.Fatal(err)
	}
	playbook, err := NewFilePermissionRepairPlaybook([]ApprovedPath{{
		Path: root, Descendants: true, FileModes: []os.FileMode{0600, 0640}, DirectoryModes: []os.FileMode{0700},
	}})
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := NewEngine(playbook)
	parameters, _ := json.Marshal(FilePermissionRepairParams{Path: target, Mode: "0600"})
	receipt := engine.Run(context.Background(), Request{
		ActionID: "permission-action", Actor: "tester", Type: TypeFilePermissionRepair,
		Operation: OperationExecute, Parameters: parameters,
	})
	if !receipt.Success {
		t.Fatalf("permission repair failed: %s", receipt.Error)
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}
	rollback := engine.Run(context.Background(), Request{
		ActionID: "permission-action", Actor: "tester", Type: TypeFilePermissionRepair,
		Operation: OperationRollback, Parameters: parameters, State: receipt.State,
	})
	if !rollback.Success {
		t.Fatalf("permission rollback failed: %s", rollback.Error)
	}
	info, _ = os.Stat(target)
	if info.Mode().Perm() != 0666 {
		t.Fatalf("restored mode = %04o, want 0666", info.Mode().Perm())
	}
	retry := engine.Run(context.Background(), Request{
		ActionID: "permission-action", Actor: "tester", Type: TypeFilePermissionRepair,
		Operation: OperationRollback, Parameters: parameters, State: receipt.State,
	})
	if !retry.Success {
		t.Fatalf("idempotent permission rollback retry failed: %s", retry.Error)
	}
}

func TestFilePermissionRepairRejectsOutsideSymlinkAndUnapprovedModes(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "inside")
	outsideRoot := t.TempDir()
	outside := filepath.Join(outsideRoot, "outside")
	if err := os.WriteFile(inside, []byte("inside"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("outside"), 0644); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "link")
	if err := os.Symlink(outside, symlink); err != nil {
		t.Fatal(err)
	}
	playbook, err := NewFilePermissionRepairPlaybook([]ApprovedPath{{
		Path: root, Descendants: true, FileModes: []os.FileMode{0600}, DirectoryModes: []os.FileMode{0700},
	}})
	if err != nil {
		t.Fatal(err)
	}
	requests := []FilePermissionRepairParams{
		{Path: outside, Mode: "0600"},
		{Path: symlink, Mode: "0600"},
		{Path: inside, Mode: "0644"},
		{Path: inside, Mode: "4755"},
	}
	for _, request := range requests {
		parameters, _ := json.Marshal(request)
		if err := playbook.Validate(parameters); err == nil {
			t.Errorf("unsafe permission request accepted: %+v", request)
		}
	}
	outsideInfo, _ := os.Stat(outside)
	if outsideInfo.Mode().Perm() != 0644 {
		t.Fatalf("outside file was mutated: %04o", outsideInfo.Mode().Perm())
	}
}

func TestFilePermissionRepairRejectsExistingSpecialBitsBeforeMutation(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "setuid-tool")
	if err := os.WriteFile(target, []byte("tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !hasSpecialModeBits(before.Mode()) {
		t.Skip("filesystem does not preserve setuid in this test environment")
	}
	playbook, err := NewFilePermissionRepairPlaybook([]ApprovedPath{{
		Path: root, Descendants: true, FileModes: []os.FileMode{0o600}, DirectoryModes: []os.FileMode{0o700},
	}})
	if err != nil {
		t.Fatal(err)
	}
	parameters, _ := json.Marshal(FilePermissionRepairParams{Path: target, Mode: "0600"})
	engine, _ := NewEngine(playbook)
	receipt := engine.Run(context.Background(), Request{ActionID: "special-mode", Actor: "tester", Type: TypeFilePermissionRepair, Operation: OperationExecute, Parameters: parameters})
	after, statErr := os.Lstat(target)
	if receipt.Success || statErr != nil || after.Mode() != before.Mode() {
		t.Fatalf("special-bit target was not rejected unchanged: receipt=%#v before=%v after=%v err=%v", receipt, before.Mode(), after.Mode(), statErr)
	}
}

func TestFilePermissionRollbackRefusesToOverwriteNewerAdministratorChange(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "managed.env")
	if err := os.WriteFile(target, []byte("value"), 0o644); err != nil {
		t.Fatal(err)
	}
	playbook, err := NewFilePermissionRepairPlaybook([]ApprovedPath{{
		Path: root, Descendants: true, FileModes: []os.FileMode{0o600, 0o640}, DirectoryModes: []os.FileMode{0o700},
	}})
	if err != nil {
		t.Fatal(err)
	}
	parameters, _ := json.Marshal(FilePermissionRepairParams{Path: target, Mode: "0600"})
	engine, _ := NewEngine(playbook)
	apply := engine.Run(context.Background(), Request{ActionID: "stale-permission", Actor: "tester", Type: TypeFilePermissionRepair, Operation: OperationExecute, Parameters: parameters})
	if !apply.Success {
		t.Fatal(apply.Error)
	}
	if err := os.Chmod(target, 0o640); err != nil {
		t.Fatal(err)
	}
	rollback := engine.Run(context.Background(), Request{ActionID: "stale-permission", Actor: "tester", Type: TypeFilePermissionRepair, Operation: OperationRollback, Parameters: parameters, State: apply.State})
	info, statErr := os.Stat(target)
	if rollback.Success || !rollback.Indeterminate || statErr != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("stale rollback overwrote a newer change: receipt=%#v mode=%v err=%v", rollback, info.Mode().Perm(), statErr)
	}
}

func TestFilePermissionRollbackRefusesAReplacementInodeWithMatchingMetadata(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "managed.env")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	playbook, err := NewFilePermissionRepairPlaybook([]ApprovedPath{{Path: root, Descendants: true, FileModes: []os.FileMode{0o600}, DirectoryModes: []os.FileMode{0o700}}})
	if err != nil {
		t.Fatal(err)
	}
	parameters, _ := json.Marshal(FilePermissionRepairParams{Path: target, Mode: "0600"})
	engine, _ := NewEngine(playbook)
	apply := engine.Run(context.Background(), Request{ActionID: "replaced-permission", Actor: "tester", Type: TypeFilePermissionRepair, Operation: OperationExecute, Parameters: parameters})
	if !apply.Success {
		t.Fatal(apply.Error)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	rollback := engine.Run(context.Background(), Request{ActionID: "replaced-permission", Actor: "tester", Type: TypeFilePermissionRepair, Operation: OperationRollback, Parameters: parameters, State: apply.State})
	content, readErr := os.ReadFile(target)
	if rollback.Success || !rollback.Indeterminate || readErr != nil || string(content) != "replacement" {
		t.Fatalf("replacement inode was modified by stale rollback: receipt=%#v content=%q err=%v", rollback, content, readErr)
	}
}

func TestFilePermissionApplyDoesNotReportSuccessAfterConcurrentPathReplacement(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "managed.env")
	detached := filepath.Join(root, "managed.detached")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	playbook, err := NewFilePermissionRepairPlaybook([]ApprovedPath{{Path: root, Descendants: true, FileModes: []os.FileMode{0o600}, DirectoryModes: []os.FileMode{0o700}}})
	if err != nil {
		t.Fatal(err)
	}
	fired := false
	playbook.afterMetadataWrite = func(operation Operation) {
		if fired || operation != OperationApply {
			return
		}
		fired = true
		if renameErr := os.Rename(target, detached); renameErr != nil {
			t.Errorf("rename guarded target: %v", renameErr)
			return
		}
		if writeErr := os.WriteFile(target, []byte("replacement"), 0o644); writeErr != nil {
			t.Errorf("create replacement: %v", writeErr)
		}
	}
	engine, _ := NewEngine(playbook)
	parameters, _ := json.Marshal(FilePermissionRepairParams{Path: target, Mode: "0600"})
	receipt := engine.Run(context.Background(), Request{ActionID: "apply-path-race", Actor: "tester", Type: TypeFilePermissionRepair, Operation: OperationExecute, Parameters: parameters})
	content, readErr := os.ReadFile(target)
	info, statErr := os.Stat(target)
	detachedInfo, detachedErr := os.Stat(detached)
	if !fired || receipt.Success || receipt.Indeterminate || len(receipt.State) != 0 || readErr != nil || statErr != nil || detachedErr != nil || string(content) != "replacement" || info.Mode().Perm() != 0o644 || detachedInfo.Mode().Perm() != 0o644 {
		t.Fatalf("concurrent replacement was modified or falsely reported: receipt=%#v content=%q mode=%v readErr=%v statErr=%v", receipt, content, info.Mode().Perm(), readErr, statErr)
	}
}

func TestFilePermissionApplyRechecksActualTypeAfterValidation(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "managed.env")
	detached := filepath.Join(root, "managed.detached")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	playbook, err := NewFilePermissionRepairPlaybook([]ApprovedPath{{
		Path: root, Descendants: true, FileModes: []os.FileMode{0o600}, DirectoryModes: []os.FileMode{0o700},
	}})
	if err != nil {
		t.Fatal(err)
	}
	fired := false
	playbook.beforeOpen = func(operation Operation) {
		if fired || operation != OperationApply {
			return
		}
		fired = true
		if renameErr := os.Rename(target, detached); renameErr != nil {
			t.Errorf("rename validated file: %v", renameErr)
			return
		}
		if mkdirErr := os.Mkdir(target, 0o700); mkdirErr != nil {
			t.Errorf("replace file with directory: %v", mkdirErr)
		}
	}
	engine, _ := NewEngine(playbook)
	parameters, _ := json.Marshal(FilePermissionRepairParams{Path: target, Mode: "0600"})
	receipt := engine.Run(context.Background(), Request{ActionID: "permission-type-race", Actor: "tester", Type: TypeFilePermissionRepair, Operation: OperationExecute, Parameters: parameters})
	info, statErr := os.Stat(target)
	if !fired || receipt.Success || receipt.Indeterminate || statErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("file mode was applied to a replacement directory: receipt=%#v info=%#v err=%v", receipt, info, statErr)
	}
}

func TestFilePermissionApplyRefusesSameInodeMetadataChangeBeforeMutation(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "managed.env")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	playbook, err := NewFilePermissionRepairPlaybook([]ApprovedPath{{Path: root, Descendants: true, FileModes: []os.FileMode{0o600, 0o640}, DirectoryModes: []os.FileMode{0o700}}})
	if err != nil {
		t.Fatal(err)
	}
	playbook.beforeMetadataWrite = func(operation Operation) {
		if operation == OperationApply {
			if chmodErr := os.Chmod(target, 0o640); chmodErr != nil {
				t.Errorf("inject metadata race: %v", chmodErr)
			}
		}
	}
	engine, _ := NewEngine(playbook)
	parameters, _ := json.Marshal(FilePermissionRepairParams{Path: target, Mode: "0600"})
	receipt := engine.Run(context.Background(), Request{ActionID: "apply-metadata-race", Actor: "tester", Type: TypeFilePermissionRepair, Operation: OperationExecute, Parameters: parameters})
	info, statErr := os.Stat(target)
	if receipt.Success || receipt.Indeterminate || len(receipt.State) != 0 || statErr != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("apply overwrote a same-inode administrator change: receipt=%#v info=%#v err=%v", receipt, info, statErr)
	}
}

func TestFilePermissionRollbackRefusesSameInodeMetadataChangeBeforeMutation(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "managed.env")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	playbook, err := NewFilePermissionRepairPlaybook([]ApprovedPath{{Path: root, Descendants: true, FileModes: []os.FileMode{0o600, 0o640}, DirectoryModes: []os.FileMode{0o700}}})
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := NewEngine(playbook)
	parameters, _ := json.Marshal(FilePermissionRepairParams{Path: target, Mode: "0600"})
	apply := engine.Run(context.Background(), Request{ActionID: "rollback-metadata-race", Actor: "tester", Type: TypeFilePermissionRepair, Operation: OperationExecute, Parameters: parameters})
	if !apply.Success {
		t.Fatal(apply.Error)
	}
	playbook.beforeMetadataWrite = func(operation Operation) {
		if operation == OperationRollback {
			if chmodErr := os.Chmod(target, 0o640); chmodErr != nil {
				t.Errorf("inject metadata race: %v", chmodErr)
			}
		}
	}
	rollback := engine.Run(context.Background(), Request{ActionID: "rollback-metadata-race", Actor: "tester", Type: TypeFilePermissionRepair, Operation: OperationRollback, Parameters: parameters, State: apply.State})
	info, statErr := os.Stat(target)
	if rollback.Success || !rollback.Indeterminate || statErr != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("rollback overwrote a same-inode administrator change: receipt=%#v info=%#v err=%v", rollback, info, statErr)
	}
}

func TestCompletedFilePermissionStateRejectsMixedOriginalAndAppliedTuple(t *testing.T) {
	state := filePermissionState{
		Mode: 0o644, UID: 1000, GID: 1000,
		AppliedMode: 0o600, AppliedUID: 2000, AppliedGID: 2000, AppliedComplete: true,
	}
	if permissionRollbackMetadataRecognized(state, 0o644, 2000, 2000) || permissionRollbackMetadataRecognized(state, 0o600, 1000, 1000) {
		t.Fatal("completed rollback state accepted a mixed tuple that Apply cannot produce")
	}
	if !permissionRollbackMetadataRecognized(state, 0o644, 1000, 1000) || !permissionRollbackMetadataRecognized(state, 0o600, 2000, 2000) {
		t.Fatal("completed rollback state rejected an exact original or applied tuple")
	}
}

func TestFilePermissionVerifyRejectsSpecialBitsAddedAfterApply(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "managed.env")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	playbook, err := NewFilePermissionRepairPlaybook([]ApprovedPath{{Path: root, Descendants: true, FileModes: []os.FileMode{0o600}, DirectoryModes: []os.FileMode{0o700}}})
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := NewEngine(playbook)
	parameters, _ := json.Marshal(FilePermissionRepairParams{Path: target, Mode: "0600"})
	apply := engine.Run(context.Background(), Request{ActionID: "permission-special-verify", Actor: "tester", Type: TypeFilePermissionRepair, Operation: OperationExecute, Parameters: parameters})
	if !apply.Success {
		t.Fatal(apply.Error)
	}
	if err = os.Chmod(target, 0o600|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	info, statErr := os.Lstat(target)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if !hasSpecialModeBits(info.Mode()) {
		t.Skip("filesystem does not preserve setuid in this test environment")
	}
	verify := engine.Run(context.Background(), Request{ActionID: "permission-special-verify", Actor: "tester", Type: TypeFilePermissionRepair, Operation: OperationVerify, Parameters: parameters, State: apply.State})
	if verify.Success {
		t.Fatalf("verification accepted special bits added after apply: %#v", verify)
	}
}

func TestFilePermissionRollbackDoesNotReportSuccessAfterConcurrentPathReplacement(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "managed.env")
	detached := filepath.Join(root, "managed.detached")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	playbook, err := NewFilePermissionRepairPlaybook([]ApprovedPath{{Path: root, Descendants: true, FileModes: []os.FileMode{0o600}, DirectoryModes: []os.FileMode{0o700}}})
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := NewEngine(playbook)
	parameters, _ := json.Marshal(FilePermissionRepairParams{Path: target, Mode: "0600"})
	apply := engine.Run(context.Background(), Request{ActionID: "rollback-path-race", Actor: "tester", Type: TypeFilePermissionRepair, Operation: OperationExecute, Parameters: parameters})
	if !apply.Success {
		t.Fatal(apply.Error)
	}
	fired := false
	playbook.afterMetadataWrite = func(operation Operation) {
		if fired || operation != OperationRollback {
			return
		}
		fired = true
		if renameErr := os.Rename(target, detached); renameErr != nil {
			t.Errorf("rename guarded target: %v", renameErr)
			return
		}
		if writeErr := os.WriteFile(target, []byte("replacement"), 0o600); writeErr != nil {
			t.Errorf("create replacement: %v", writeErr)
		}
	}
	rollback := engine.Run(context.Background(), Request{ActionID: "rollback-path-race", Actor: "tester", Type: TypeFilePermissionRepair, Operation: OperationRollback, Parameters: parameters, State: apply.State})
	content, readErr := os.ReadFile(target)
	info, statErr := os.Stat(target)
	detachedInfo, detachedErr := os.Stat(detached)
	if !fired || rollback.Success || !rollback.Indeterminate || readErr != nil || statErr != nil || detachedErr != nil || string(content) != "replacement" || info.Mode().Perm() != 0o600 || detachedInfo.Mode().Perm() != 0o600 {
		t.Fatalf("rollback replacement was modified or falsely reported: receipt=%#v content=%q mode=%v readErr=%v statErr=%v", rollback, content, info.Mode().Perm(), readErr, statErr)
	}
}

func TestFilePermissionRepairOpenRejectsAncestorSwapAfterValidation(t *testing.T) {
	root := t.TempDir()
	insideDir := filepath.Join(root, "inside")
	if err := os.Mkdir(insideDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(insideDir, "target")
	if err := os.WriteFile(target, []byte("inside"), 0o640); err != nil {
		t.Fatal(err)
	}
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "target")
	if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	playbook, err := NewFilePermissionRepairPlaybook([]ApprovedPath{{
		Path: root, Descendants: true, FileModes: []os.FileMode{0o600, 0o640}, DirectoryModes: []os.FileMode{0o700},
	}})
	if err != nil {
		t.Fatal(err)
	}
	parameters := FilePermissionRepairParams{Path: target, Mode: "0600"}
	validatedPath, _, rule, err := playbook.validateTarget(parameters)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(insideDir, filepath.Join(root, "inside-original")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outsideDir, insideDir); err != nil {
		t.Fatal(err)
	}
	if file, openErr := openValidatedTarget(rule.resolved, validatedPath); openErr == nil {
		_ = file.Close()
		t.Fatal("ancestor symlink swap escaped the approved root")
	}
	info, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("outside target changed: mode=%v", info.Mode().Perm())
	}
}

func TestFilePermissionRepairDoesNotApplyRecursively(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.WriteFile(child, []byte("child"), 0666); err != nil {
		t.Fatal(err)
	}
	playbook, err := NewFilePermissionRepairPlaybook([]ApprovedPath{{
		Path: root, Descendants: true, FileModes: []os.FileMode{0600}, DirectoryModes: []os.FileMode{0700},
	}})
	if err != nil {
		t.Fatal(err)
	}
	parameters, _ := json.Marshal(FilePermissionRepairParams{Path: root, Mode: "0700"})
	engine, _ := NewEngine(playbook)
	receipt := engine.Run(context.Background(), Request{
		ActionID: "directory-mode", Actor: "tester", Type: TypeFilePermissionRepair,
		Operation: OperationExecute, Parameters: parameters,
	})
	if !receipt.Success {
		t.Fatal(receipt.Error)
	}
	childInfo, _ := os.Stat(child)
	if childInfo.Mode().Perm() != 0644 && childInfo.Mode().Perm() != 0666 {
		t.Fatalf("child mode was unexpectedly changed recursively: %04o", childInfo.Mode().Perm())
	}
}

func TestDefaultPermissionRepairPolicyExcludesHelperCredential(t *testing.T) {
	if IsDefaultPermissionRepairPath(DefaultPermissionRepairTokenPath) {
		t.Fatal("Helper authentication token is inside the default repair policy")
	}
	if !protectedPermissionRepairPath(DefaultPermissionRepairTokenPath) {
		t.Fatal("Helper final validation does not protect its authentication token")
	}
}
