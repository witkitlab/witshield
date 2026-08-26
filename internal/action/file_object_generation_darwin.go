//go:build darwin

package action

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

const darwinFileGenerationKind = "darwin-birth-generation-v1"

type fileObjectGenerationValue struct {
	Kind  string
	Token string
}

func fileObjectGeneration(_ *os.File, info fs.FileInfo, requiredKind string) (fileObjectGenerationValue, error) {
	if requiredKind != "" && requiredKind != darwinFileGenerationKind {
		return fileObjectGenerationValue{}, errors.New("unsupported Darwin file-object generation kind")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileObjectGenerationValue{}, errors.New("opened target filesystem generation is unavailable")
	}
	digest := sha256.New()
	_, _ = fmt.Fprintf(digest, "%s\x00%d\x00%d\x00%d", darwinFileGenerationKind, stat.Birthtimespec.Sec, stat.Birthtimespec.Nsec, stat.Gen)
	return fileObjectGenerationValue{Kind: darwinFileGenerationKind, Token: hex.EncodeToString(digest.Sum(nil))}, nil
}
