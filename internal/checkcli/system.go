package checkcli

import (
	"context"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/action"
)

const (
	aptGetPath    = "/usr/bin/apt-get"
	dpkgQueryPath = "/usr/bin/dpkg-query"
	sshdPath      = "/usr/sbin/sshd"
	systemctlPath = "/usr/bin/systemctl"
)

// OSRelease contains only the fields used by the CLI.
type OSRelease struct {
	Name   string
	Debian bool
}

// ParseOSRelease recognizes Debian derivatives via both ID and ID_LIKE.
func ParseOSRelease(data []byte) OSRelease {
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			values[key] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	out := OSRelease{Name: values["PRETTY_NAME"]}
	for _, id := range strings.Fields(values["ID"] + " " + values["ID_LIKE"]) {
		if id == "ubuntu" || id == "debian" {
			out.Debian = true
		}
	}
	return out
}

func detectSSHService(ctx context.Context, runner action.Runner) string {
	for _, service := range []string{"ssh", "sshd"} {
		result, err := runner.Run(ctx, action.Command{
			Path: systemctlPath, Args: []string{"show", "-p", "LoadState", "--value", service + ".service"}, Timeout: 5 * time.Second,
		})
		if err == nil && !result.OutputTruncated {
			switch strings.TrimSpace(result.Stdout) {
			case "loaded", "masked":
				return service
			}
		}
	}
	return ""
}

func fullHelperActive(ctx context.Context, runner action.Runner) bool {
	r, err := runner.Run(ctx, action.Command{
		Path: systemctlPath, Args: []string{"is-active", "witshield-helper.service"}, Timeout: 5 * time.Second,
	})
	return err == nil && !r.OutputTruncated && strings.TrimSpace(r.Stdout) == "active"
}
