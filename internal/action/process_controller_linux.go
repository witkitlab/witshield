package action

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/witkitlab/witshield/internal/observation"
)

type systemProcessController struct{}

func NewSystemProcessController() ProcessController { return systemProcessController{} }

func (systemProcessController) Inspect(pid int) (ProcessRuntimeIdentity, error) {
	if pid < 1 {
		return ProcessRuntimeIdentity{}, ErrProcessNotFound
	}
	proc, err := os.OpenRoot("/proc")
	if err != nil {
		return ProcessRuntimeIdentity{}, errors.New("procfs is unavailable")
	}
	defer proc.Close()
	prefix := strconv.Itoa(pid)
	executable, err := proc.Readlink(prefix + "/exe")
	if errors.Is(err, os.ErrNotExist) {
		return ProcessRuntimeIdentity{}, ErrProcessNotFound
	}
	if err != nil {
		return ProcessRuntimeIdentity{}, err
	}
	stat, err := proc.ReadFile(prefix + "/stat")
	if errors.Is(err, os.ErrNotExist) {
		return ProcessRuntimeIdentity{}, ErrProcessNotFound
	}
	if err != nil || len(stat) > 64<<10 {
		return ProcessRuntimeIdentity{}, errors.New("process stat is unavailable")
	}
	startTime, ok := observation.ParseStartTime(string(stat))
	if !ok {
		return ProcessRuntimeIdentity{}, errors.New("process start time is invalid")
	}
	status, err := proc.ReadFile(prefix + "/status")
	if err != nil || len(status) > 64<<10 {
		return ProcessRuntimeIdentity{}, errors.New("process status is unavailable")
	}
	identity := ProcessRuntimeIdentity{PID: pid, StartTime: startTime, Executable: executable}
	havePPID, haveUID, haveState := false, false, false
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "PPid":
			identity.PPID, err = strconv.Atoi(fields[1])
			havePPID = err == nil
		case "Uid":
			identity.UID, err = strconv.ParseUint(fields[1], 10, 32)
			haveUID = err == nil
		case "State":
			identity.Stopped = fields[1] == "T" || fields[1] == "t"
			haveState = true
		}
	}
	if !havePPID || !haveUID || !haveState || identity.PPID < 0 {
		return ProcessRuntimeIdentity{}, fmt.Errorf("process %d identity is incomplete", pid)
	}
	return identity, nil
}

func (systemProcessController) Stop(pid int) error     { return syscall.Kill(pid, syscall.SIGSTOP) }
func (systemProcessController) Continue(pid int) error { return syscall.Kill(pid, syscall.SIGCONT) }
