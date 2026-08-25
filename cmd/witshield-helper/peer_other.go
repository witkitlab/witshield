//go:build !linux

package main

import (
	"errors"
	"net"
)

func peerUID(_ *net.UnixConn) (uint32, error) {
	return 0, errors.New("SO_PEERCRED is unavailable on this platform; strong token authentication is required")
}
