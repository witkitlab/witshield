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
