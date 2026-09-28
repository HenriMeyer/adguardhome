//go:build !linux

package iona

import (
	"errors"
	"net/netip"
)

// kernelNeighbors is only implemented on Linux.
func kernelNeighbors() (m map[netip.Addr]string, err error) {
	return nil, errors.New("neighbor table not supported on this platform")
}
