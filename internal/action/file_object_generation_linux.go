//go:build linux

package action

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

const (
	linuxFileHandleFIDKind     = "linux-file-handle-fid-v1"
	linuxFileHandleClassicKind = "linux-file-handle-classic-v1"
	linuxATHandleFID           = 0x200 // Linux UAPI AT_HANDLE_FID, available since Linux 6.5.
	maxFileHandleBytes         = 128
)

type fileObjectGenerationValue struct {
	Kind  string
	Token string
}

func fileObjectGeneration(file *os.File, _ fs.FileInfo, requiredKind string) (fileObjectGenerationValue, error) {
	switch requiredKind {
	case "":
		fid, fidErr := linuxFileHandleGeneration(file, linuxFileHandleFIDKind, unix.AT_EMPTY_PATH|linuxATHandleFID)
		if fidErr == nil {
			return fid, nil
		}
		classic, classicErr := linuxFileHandleGeneration(file, linuxFileHandleClassicKind, unix.AT_EMPTY_PATH)
		if classicErr == nil {
			return classic, nil
		}
		return fileObjectGenerationValue{}, fmt.Errorf("filesystem exposes no stable file handle: %w", errors.Join(fidErr, classicErr))
	case linuxFileHandleFIDKind:
		return linuxFileHandleGeneration(file, requiredKind, unix.AT_EMPTY_PATH|linuxATHandleFID)
	case linuxFileHandleClassicKind:
		return linuxFileHandleGeneration(file, requiredKind, unix.AT_EMPTY_PATH)
	default:
		return fileObjectGenerationValue{}, errors.New("unsupported Linux file-object generation kind")
	}
}

func linuxFileHandleGeneration(file *os.File, kind string, flags int) (fileObjectGenerationValue, error) {
	handle, _, err := unix.NameToHandleAt(int(file.Fd()), "", flags)
	if err != nil {
		return fileObjectGenerationValue{}, err
	}
	bytes := handle.Bytes()
	if len(bytes) == 0 || len(bytes) > maxFileHandleBytes {
		return fileObjectGenerationValue{}, errors.New("filesystem returned an invalid file handle")
	}
	digest := sha256.New()
	// mountID is intentionally excluded: it identifies a mount inside the
	// caller's namespace and can change across Helper restarts. Device identity
	// is bound separately; the opaque handle carries the file generation.
	_, _ = fmt.Fprintf(digest, "%s\x00%d\x00%d\x00", kind, handle.Type(), len(bytes))
	_, _ = digest.Write(bytes)
	return fileObjectGenerationValue{Kind: kind, Token: hex.EncodeToString(digest.Sum(nil))}, nil
}
