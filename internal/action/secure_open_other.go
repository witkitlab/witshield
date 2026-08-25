//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package action

import (
	"errors"
	"os"
)

func openBeneath(_, _ string) (*os.File, error) {
	return nil, errors.New("file permission repair requires a platform with safe openat support")
}
