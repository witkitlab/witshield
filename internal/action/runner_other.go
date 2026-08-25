//go:build !linux && !darwin

package action

import "os/exec"

func configureProcessGroup(_ *exec.Cmd) {}
