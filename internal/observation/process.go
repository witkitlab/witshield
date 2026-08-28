package observation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	maxObservedProcesses = 32_768
	maxCandidates        = 256
	ProcessQueryKind     = "observe_suspicious_processes_v1"
)

// Process is a deliberately narrow observation. Command lines, environments,
// open files and process output are never collected because they frequently
// contain credentials. Identity is a stable digest used only for replay-safe
// local baselining.
type Process struct {
	Identity   string `json:"identity"`
	EventType  string `json:"eventType"`
	Reason     string `json:"reason"`
	Name       string `json:"name"`
	Executable string `json:"executable"`
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	UID        uint64 `json:"uid"`
}

// ProcessSnapshot reports whether the deliberately bounded observation was
// complete. Callers must surface Truncated as sensor-health evidence rather
// than silently treating the partial result as an all-clear.
type ProcessSnapshot struct {
	Processes []Process `json:"processes"`
	Observed  int       `json:"observed"`
	Truncated bool      `json:"truncated"`
}

// SuspiciousProcesses reads only the procfs fields required to recognize two
// high-value states. Native installations call it inside the root Helper;
// observer-only installations can use it on their actually visible procfs.
func SuspiciousProcesses(ctx context.Context, hostRoot string) (ProcessSnapshot, error) {
	rootPath := filepath.Clean(hostRoot)
	if rootPath == "." || rootPath == "" {
		rootPath = "/"
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return ProcessSnapshot{}, err
	}
	defer root.Close()
	entries, err := fs.ReadDir(root.FS(), "proc")
	if err != nil {
		return ProcessSnapshot{}, fmt.Errorf("read procfs: %w", err)
	}
	processes := make([]Process, 0)
	observed := 0
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return ProcessSnapshot{}, err
		}
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid < 1 || !entry.IsDir() {
			continue
		}
		observed++
		if observed > maxObservedProcesses {
			return ProcessSnapshot{Processes: processes, Observed: observed, Truncated: true}, nil
		}
		process, ok := inspectProcess(root, pid)
		if !ok {
			continue
		}
		processes = append(processes, process)
		if len(processes) >= maxCandidates {
			sort.Slice(processes, func(i, j int) bool { return processes[i].Identity < processes[j].Identity })
			return ProcessSnapshot{Processes: processes, Observed: observed, Truncated: true}, nil
		}
	}
	sort.Slice(processes, func(i, j int) bool { return processes[i].Identity < processes[j].Identity })
	return ProcessSnapshot{Processes: processes, Observed: observed}, nil
}

func inspectProcess(root *os.Root, pid int) (Process, bool) {
	prefix := "proc/" + strconv.Itoa(pid)
	statusData, err := readRootFileLimit(root, prefix+"/status", 64<<10)
	if err != nil {
		return Process{}, false
	}
	name, ppid, uid, ok := parseStatus(statusData)
	if !ok {
		return Process{}, false
	}
	executable, err := root.Readlink(prefix + "/exe")
	if err != nil || executable == "" || len(executable) > 4096 {
		return Process{}, false
	}
	statData, err := readRootFileLimit(root, prefix+"/stat", 64<<10)
	if err != nil {
		return Process{}, false
	}
	startTime, ok := ParseStartTime(string(statData))
	if !ok {
		return Process{}, false
	}
	eventType, reason := "", ""
	cleanExecutable := strings.TrimSuffix(executable, " (deleted)")
	if strings.HasSuffix(executable, " (deleted)") {
		eventType, reason = "deleted_executable_process_running", "running executable was removed from the filesystem"
	} else if uid == 0 && executableInTransientPath(cleanExecutable) {
		eventType, reason = "suspicious_privileged_process_started", "UID 0 process executable is in a transient writable path"
	}
	if eventType == "" {
		return Process{}, false
	}
	identityInput := fmt.Sprintf("%d\x00%d\x00%d\x00%s", pid, startTime, uid, executable)
	sum := sha256.Sum256([]byte(identityInput))
	return Process{
		Identity: hex.EncodeToString(sum[:]), EventType: eventType, Reason: reason,
		Name: truncateField(name, 128), Executable: truncateField(executable, 1024),
		PID: pid, PPID: ppid, UID: uid,
	}, true
}

func readRootFileLimit(root *os.Root, path string, limit int64) ([]byte, error) {
	file, err := root.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("procfs field exceeds safe limit")
	}
	return data, nil
}

func parseStatus(data []byte) (string, int, uint64, bool) {
	var name string
	ppid := -1
	var uid uint64
	haveUID := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "Name":
			name = fields[1]
		case "PPid":
			ppid, _ = strconv.Atoi(fields[1])
		case "Uid":
			value, parseErr := strconv.ParseUint(fields[1], 10, 32)
			if parseErr == nil {
				uid, haveUID = value, true
			}
		}
	}
	return name, ppid, uid, name != "" && ppid >= 0 && haveUID
}

// ParseStartTime parses /proc/<pid>/stat without assuming the process name has
// no spaces or closing parentheses.
func ParseStartTime(raw string) (uint64, bool) {
	closeParen := strings.LastIndex(raw, ") ")
	if closeParen < 0 {
		return 0, false
	}
	fields := strings.Fields(raw[closeParen+2:])
	// fields[0] is proc stat field 3 (state); starttime is field 22.
	if len(fields) <= 19 {
		return 0, false
	}
	value, err := strconv.ParseUint(fields[19], 10, 64)
	return value, err == nil
}

func executableInTransientPath(path string) bool {
	clean := filepath.Clean(path)
	for _, prefix := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
		if strings.HasPrefix(clean, prefix) {
			return true
		}
	}
	return false
}

func truncateField(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
	if len(value) > limit {
		return value[:limit] + "…"
	}
	return value
}
