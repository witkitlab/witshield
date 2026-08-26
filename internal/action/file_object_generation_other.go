//go:build !linux && !darwin

package action

import (
	"errors"
	"io/fs"
	"os"
)

type fileObjectGenerationValue struct {
	Kind  string
	Token string
}

func fileObjectGeneration(_ *os.File, _ fs.FileInfo, _ string) (fileObjectGenerationValue, error) {
	return fileObjectGenerationValue{}, errors.New("stable file generation guards are unavailable on this platform")
}
