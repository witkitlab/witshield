package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/witkitlab/witshield/internal/action"
)

func TestReceiptCacheSurvivesRestartAndRejectsConflictingReplay(t *testing.T) {
	dir := t.TempDir()
	cache, err := newReceiptCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	params := json.RawMessage(`{"packages":["openssl"]}`)
	response := helperResponse{OK: true, RollbackPayload: json.RawMessage(`{"signed":"state"}`)}
	if err = cache.begin("cmd-1", "act-1", action.TypePackageSecurityUpgrade, action.OperationExecute, params, nil); err != nil {
		t.Fatal(err)
	}
	if err = cache.save("cmd-1", "act-1", action.TypePackageSecurityUpgrade, action.OperationExecute, params, nil, response); err != nil {
		t.Fatal(err)
	}
	restarted, err := newReceiptCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, found, err := restarted.load("cmd-1", "act-1", action.TypePackageSecurityUpgrade, action.OperationExecute, params, nil)
	if err != nil || !found || !got.OK || string(got.RollbackPayload) != string(response.RollbackPayload) {
		t.Fatalf("%#v %v %v", got, found, err)
	}
	if _, _, err = restarted.load("cmd-1", "act-1", action.TypePackageSecurityUpgrade, action.OperationExecute, json.RawMessage(`{"packages":["curl"]}`), nil); err == nil {
		t.Fatal("conflicting replay accepted")
	}
	if err = restarted.begin("cmd-crashed", "act-crashed", action.TypePackageSecurityUpgrade, action.OperationExecute, params, nil); err != nil {
		t.Fatal(err)
	}
	crashed, found, err := restarted.load("cmd-crashed", "act-crashed", action.TypePackageSecurityUpgrade, action.OperationExecute, params, nil)
	if err != nil || !found || crashed.OK || !strings.Contains(crashed.Error, "interrupted") {
		t.Fatalf("crash marker not replay-safe: %#v found=%v err=%v", crashed, found, err)
	}
}

func TestReceiptCacheReplaysOneCommandButAllowsANewManualAttempt(t *testing.T) {
	cache, err := newReceiptCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	params := json.RawMessage(`{"packages":["openssl"]}`)
	failed := helperResponse{OK: false, Error: action.ExecutionIndeterminateMessage}
	if err = cache.begin("cmd-rollback-1", "act-shared", action.TypePackageSecurityUpgrade, action.OperationRollback, params, json.RawMessage(`{"state":1}`)); err != nil {
		t.Fatal(err)
	}
	if err = cache.save("cmd-rollback-1", "act-shared", action.TypePackageSecurityUpgrade, action.OperationRollback, params, json.RawMessage(`{"state":1}`), failed); err != nil {
		t.Fatal(err)
	}
	if replay, found, loadErr := cache.load("cmd-rollback-1", "act-shared", action.TypePackageSecurityUpgrade, action.OperationRollback, params, json.RawMessage(`{"state":1}`)); loadErr != nil || !found || replay.Error != failed.Error {
		t.Fatalf("same command did not replay: response=%#v found=%v err=%v", replay, found, loadErr)
	}
	if _, found, loadErr := cache.load("cmd-rollback-2", "act-shared", action.TypePackageSecurityUpgrade, action.OperationRollback, params, json.RawMessage(`{"state":1}`)); loadErr != nil || found {
		t.Fatalf("new manual attempt was blocked by an old receipt: found=%v err=%v", found, loadErr)
	}
	if err = cache.begin("cmd-rollback-2", "act-shared", action.TypePackageSecurityUpgrade, action.OperationRollback, params, json.RawMessage(`{"state":1}`)); err != nil {
		t.Fatalf("new manual attempt could not enter the helper: %v", err)
	}
}

func TestReceiptCacheBoundsPruneOnlyFinalReceipts(t *testing.T) {
	cache, err := newReceiptCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cache.maxItems = 2
	params := json.RawMessage(`{"packages":["openssl"]}`)
	for _, id := range []string{"final-1", "final-2"} {
		if err = cache.begin("cmd-"+id, id, action.TypePackageSecurityUpgrade, action.OperationExecute, params, nil); err != nil {
			t.Fatal(err)
		}
		if err = cache.save("cmd-"+id, id, action.TypePackageSecurityUpgrade, action.OperationExecute, params, nil, helperResponse{OK: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err = cache.begin("cmd-started", "started", action.TypePackageSecurityUpgrade, action.OperationExecute, params, nil); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(cache.dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries=%d err=%v", len(entries), err)
	}
	cache.maxItems = 1
	if err = cache.begin("cmd-another-started", "another-started", action.TypePackageSecurityUpgrade, action.OperationExecute, params, nil); err == nil {
		t.Fatal("cache evicted an unresolved started action")
	}
}
