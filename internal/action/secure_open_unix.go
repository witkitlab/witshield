//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package action

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openBeneath resolves a target from a kernel-held approved-root descriptor.
// Every component is opened with O_NOFOLLOW, so renaming an ancestor to a
// symlink between policy validation and mutation cannot escape the root.
func openBeneath(approvedRoot, target string) (*os.File, error) {
	relative, err := filepath.Rel(approvedRoot, target)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("permission target is outside its approved root")
	}
	finalFlags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if relative == "." {
		fd, openErr := unix.Open(approvedRoot, finalFlags, 0)
		if openErr != nil {
			return nil, openErr
		}
		return os.NewFile(uintptr(fd), approvedRoot), nil
	}
	rootFD, err := unix.Open(approvedRoot, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	currentFD := rootFD
	components := strings.Split(relative, string(filepath.Separator))
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(currentFD)
			return nil, errors.New("permission target contains an invalid path component")
		}
		flags := finalFlags
		if index < len(components)-1 {
			flags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_DIRECTORY
		}
		nextFD, openErr := unix.Openat(currentFD, component, flags, 0)
		_ = unix.Close(currentFD)
		if openErr != nil {
			return nil, openErr
		}
		currentFD = nextFD
	}
	return os.NewFile(uintptr(currentFD), target), nil
}
