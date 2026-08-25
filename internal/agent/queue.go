package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/witkitlab/witshield/internal/ids"
)

const maxQueuedPayloadBytes = 4 << 20

type queuedRequest struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	CommandID string          `json:"commandId,omitempty"`
	Body      json.RawMessage `json:"body"`
	CreatedAt time.Time       `json:"createdAt"`
}

type Queue struct {
	mu       sync.Mutex
	dir      string
	maxItems int
	maxBytes int64
}

func NewQueue(dir string) (*Queue, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("queue path must be absolute")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	return &Queue{dir: dir, maxItems: 5000, maxBytes: 128 << 20}, nil
}
func (q *Queue) Enqueue(kind, commandID string, body any) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	switch kind {
	case "report", "events", "command_result":
	default:
		return errors.New("unsupported queue kind")
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	if len(b) > maxQueuedPayloadBytes {
		return errors.New("queued payload is too large")
	}
	files, total, err := q.files()
	if err != nil {
		return err
	}
	if len(files) >= q.maxItems || total+int64(len(b)) > q.maxBytes {
		return errors.New("offline queue capacity reached")
	}
	item := queuedRequest{ID: ids.New("q"), Kind: kind, CommandID: commandID, Body: b, CreatedAt: time.Now().UTC()}
	encoded, _ := json.Marshal(item)
	name := item.CreatedAt.Format("20060102T150405.000000000") + "_" + item.ID + ".json"
	tmp := filepath.Join(q.dir, "."+name+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if n, err := f.Write(encoded); err != nil || n != len(encoded) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(q.dir, name)); err != nil {
		return err
	}
	if err = syncDirectory(q.dir); err != nil {
		return err
	}
	ok = true
	return nil
}
func (q *Queue) files() ([]string, int64, error) {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, 0, err
	}
	var files []string
	var total int64
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 || e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, 0, err
		}
		files = append(files, e.Name())
		total += info.Size()
	}
	sort.Strings(files)
	return files, total, nil
}
func (q *Queue) Flush(ctx context.Context, c *Client) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	files, _, err := q.files()
	if err != nil {
		return err
	}
	for _, name := range files {
		if err = ctx.Err(); err != nil {
			return err
		}
		full := filepath.Join(q.dir, name)
		info, err := os.Lstat(full)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe queue entry")
		}
		b, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		var item queuedRequest
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err = dec.Decode(&item); err != nil {
			return err
		}
		if err = dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) || item.ID == "" || item.CreatedAt.IsZero() || !json.Valid(item.Body) {
			return errors.New("invalid queue entry")
		}
		switch item.Kind {
		case "report":
			err = c.doRaw(ctx, "POST", "/agent/v1/reports", item.Body, true, nil)
		case "events":
			err = c.doRaw(ctx, "POST", "/agent/v1/events", item.Body, true, nil)
		case "command_result":
			if item.CommandID == "" {
				return errors.New("invalid queued command result")
			}
			err = c.doRaw(ctx, "POST", "/agent/v1/commands/"+url.PathEscape(item.CommandID)+"/result", item.Body, true, nil)
			var apiErr *APIError
			if errors.As(err, &apiErr) && apiErr.Status == http.StatusGone && apiErr.Code == "command_result_expired" {
				// The Controller authenticated the device request but no longer
				// retains this command identity. This one exact protocol code is a
				// terminal receipt; removing it prevents an ancient result from
				// blocking every newer report/event in the durable FIFO.
				err = nil
			}
		default:
			return errors.New("invalid queue kind")
		}
		if err != nil {
			return err
		}
		if err = os.Remove(full); err != nil {
			return err
		}
		if err = syncDirectory(q.dir); err != nil {
			return err
		}
	}
	return nil
}
