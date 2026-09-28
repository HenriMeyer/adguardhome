//go:build linux

package iona

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
)

// Neighbor table constants from linux/neighbour.h.
const (
	ndaDst    = 1
	ndaLLAddr = 2

	nudIncomplete = 0x01
	nudFailed     = 0x20
	nudNoARP      = 0x40

	ndmsgLen = 12
)

// kernelNeighbors dumps the kernel neighbor table (IPv4 ARP and IPv6 NDP) over
// rtnetlink.
func kernelNeighbors() (m map[netip.Addr]string, err error) {
	tab, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}

	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, err
	}

	m = map[netip.Addr]string{}
	for _, msg := range msgs {
		if msg.Header.Type != syscall.RTM_NEWNEIGH || len(msg.Data) < ndmsgLen {
			continue
		}

		state := binary.NativeEndian.Uint16(msg.Data[8:])
		if state&(nudIncomplete|nudFailed|nudNoARP) != 0 {
			continue
		}

		ip, mac := parseNeighAttrs(msg.Data[ndmsgLen:])
		if ip.IsValid() && mac != "" {
			m[ip.Unmap()] = mac
		}
	}

	return m, nil
}

// parseNeighAttrs returns the destination and link-layer address attributes.
func parseNeighAttrs(b []byte) (ip netip.Addr, mac string) {
	for len(b) >= 4 {
		l := int(binary.NativeEndian.Uint16(b[0:]))
		typ := binary.NativeEndian.Uint16(b[2:])
		if l < 4 || l > len(b) {
			break
		}

		val := b[4:l]
		switch typ {
		case ndaDst:
			ip, _ = netip.AddrFromSlice(val)
		case ndaLLAddr:
			if len(val) == 6 && !allZero(val) {
				mac = net.HardwareAddr(val).String()
			}
		}

		// Attributes are aligned to 4 bytes.
		l = (l + 3) &^ 3
		if l > len(b) {
			break
		}

		b = b[l:]
	}

	return ip, mac
}

// allZero returns true if b has only zero bytes.
func allZero(b []byte) (ok bool) {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}

	return true
}
