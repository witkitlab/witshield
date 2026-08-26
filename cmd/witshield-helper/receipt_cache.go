package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/witkitlab/witshield/internal/action"
)

type receiptCache struct {
	dir      string
	maxItems int
	maxBytes int64
}

type cachedReceipt struct {
	AttemptID     string           `json:"attemptId"`
	ActionID      string           `json:"actionId"`
	Type          action.Type      `json:"type"`
	Operation     action.Operation `json:"operation"`
	RequestDigest string           `json:"requestDigest"`
	State         string           `json:"state"`
	Response      helperResponse   `json:"response"`
}

func newReceiptCache(dir string) (*receiptCache, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("receipt directory must be absolute")
	}
	if err := prepareOwnedDirectory(dir, 0o700, -1); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("receipt directory must be a non-symlink mode 0700 directory")
	}
	uid, _, err := fileOwner(info)
	if err != nil || uid != os.Geteuid() {
		return nil, errors.New("receipt directory must be owned by the helper user")
	}
	cache := &receiptCache{dir: dir, maxItems: 10_000, maxBytes: 128 << 20}
	if err = cache.ensureCapacity(0, "", false); err != nil {
		return nil, err
	}
	return cache, nil
}

func requestDigest(t action.Type, operation action.Operation, parameters, state json.RawMessage) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(t))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(operation))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(parameters)
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(state)
	return hex.EncodeToString(hash.Sum(nil))
}

func (c *receiptCache) path(attemptID string) string {
	sum := sha256.Sum256([]byte(attemptID))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:])+".json")
}

func (c *receiptCache) load(attemptID, actionID string, t action.Type, operation action.Operation, parameters, state json.RawMessage) (helperResponse, bool, error) {
	var out helperResponse
	path := c.path(attemptID)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return out, false, nil
	}
	if err != nil {
		return out, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return out, false, errors.New("unsafe cached receipt")
	}
	uid, _, err := fileOwner(info)
	if err != nil || uid != os.Geteuid() {
		return out, false, errors.New("cached receipt has an unexpected owner")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return out, false, err
	}
	if len(b) > 4<<20 {
		return out, false, errors.New("cached receipt too large")
	}
	var item cachedReceipt
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&item); err != nil {
		return out, false, err
	}
	if err = dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return out, false, errors.New("invalid cached receipt")
	}
	if item.AttemptID != attemptID || item.ActionID != actionID || item.Type != t || item.Operation != operation || item.RequestDigest != requestDigest(t, operation, parameters, state) {
		return out, false, errors.New("action ID replayed with different operation or parameters")
	}
	if item.State != "started" && item.State != "final" {
		return out, false, errors.New("cached receipt has invalid state")
	}
	return item.Response, true, nil
}

func (c *receiptCache) begin(attemptID, actionID string, t action.Type, operation action.Operation, parameters, state json.RawMessage) error {
	item := cachedReceipt{
		AttemptID: attemptID, ActionID: actionID, Type: t, Operation: operation,
		RequestDigest: requestDigest(t, operation, parameters, state), State: "started",
		Response: helperResponse{OK: false, Error: action.ExecutionIndeterminateMessage},
	}
	return c.write(c.path(attemptID), item, true)
}

func (c *receiptCache) save(attemptID, actionID string, t action.Type, operation action.Operation, parameters, state json.RawMessage, response helperResponse) error {
	item := cachedReceipt{AttemptID: attemptID, ActionID: actionID, Type: t, Operation: operation, RequestDigest: requestDigest(t, operation, parameters, state), State: "final", Response: response}
	return c.write(c.path(attemptID), item, false)
}

func (c *receiptCache) write(path string, item cachedReceipt, exclusive bool) error {
	b, err := json.Marshal(item)
	if err != nil {
		return err
	}
	if err = c.ensureCapacity(int64(len(b)), path, true); err != nil {
		return err
	}
	if exclusive {
		file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if openErr != nil {
			return openErr
		}
		ok := false
		defer func() {
			_ = file.Close()
			if !ok {
				_ = os.Remove(path)
			}
		}()
		if err = writeAndSync(file, b); err != nil {
			return err
		}
		if err = syncDirectory(c.dir); err != nil {
			return err
		}
		ok = true
		return nil
	}
	tmp, err := os.CreateTemp(c.dir, ".receipt-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return err
	}
	if err = writeAndSync(tmp, b); err != nil {
		return err
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return err
	}
	if err = syncDirectory(c.dir); err != nil {
		return err
	}
	ok = true
	return nil
}

type finalReceiptFile struct {
	path    string
	size    int64
	modTime time.Time
}

func (c *receiptCache) ensureCapacity(required int64, replacingPath string, add bool) error {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}
	var count int
	var total int64
	var removable []finalReceiptFile
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(c.dir, entry.Name())
		if path == replacingPath {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return infoErr
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return errors.New("receipt cache contains an unsafe file")
		}
		uid, _, ownerErr := fileOwner(info)
		if ownerErr != nil || uid != os.Geteuid() {
			return errors.New("receipt cache contains a foreign-owned file")
		}
		count++
		total += info.Size()
		if info.Size() > 4<<20 {
			return errors.New("receipt cache contains an oversized file")
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		var metadata struct {
			State string `json:"state"`
		}
		if json.Unmarshal(data, &metadata) != nil || (metadata.State != "started" && metadata.State != "final") {
			return errors.New("receipt cache contains an invalid file")
		}
		if metadata.State == "final" {
			removable = append(removable, finalReceiptFile{path: path, size: info.Size(), modTime: info.ModTime()})
		}
	}
	if add {
		count++
		total += required
	}
	if count <= c.maxItems && total <= c.maxBytes {
		return nil
	}
	sort.Slice(removable, func(i, j int) bool { return removable[i].modTime.Before(removable[j].modTime) })
	for _, candidate := range removable {
		if count <= c.maxItems && total <= c.maxBytes {
			break
		}
		if err = os.Remove(candidate.path); err != nil {
			return err
		}
		count--
		total -= candidate.size
	}
	if count > c.maxItems || total > c.maxBytes {
		return errors.New("receipt cache capacity reached; unresolved started actions are retained")
	}
	return syncDirectory(c.dir)
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func writeAndSync(file *os.File, b []byte) error {
	if n, err := file.Write(b); err != nil || n != len(b) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return file.Close()
}
