//go:build iona_slim && !windows

package dhcpd

// Iona: with the iona_slim tag the legacy DHCP server is replaced by the no-op
// implementation AdGuard Home uses on Windows.  The router's DHCP is served by
// dnsmasq and odhcpd, and dropping the server removes ~2 MB of dependencies
// (gopacket) from the binary.

import (
	"context"
	"net"
	"net/netip"

	"github.com/AdguardTeam/AdGuardHome/internal/dhcpsvc"
)

type winServer struct{}

// type check
var _ DHCPServer = winServer{}

func (winServer) ResetLeases(_ []*dhcpsvc.Lease) (err error)           { return nil }
func (winServer) GetLeases(_ GetLeasesFlags) (leases []*dhcpsvc.Lease) { return nil }
func (winServer) getLeasesRef() []*dhcpsvc.Lease                       { return nil }
func (winServer) AddStaticLease(_ *dhcpsvc.Lease) (err error)          { return nil }
func (winServer) RemoveStaticLease(_ *dhcpsvc.Lease) (err error)       { return nil }
func (winServer) UpdateStaticLease(_ *dhcpsvc.Lease) (err error)       { return nil }
func (winServer) FindMACbyIP(_ netip.Addr) (mac net.HardwareAddr)      { return nil }
func (winServer) WriteDiskConfig4(_ *V4ServerConf)                     {}
func (winServer) WriteDiskConfig6(_ *V6ServerConf)                     {}
func (winServer) Start(_ context.Context) (err error)                  { return nil }
func (winServer) Stop() (err error)                                    { return nil }
func (winServer) HostByIP(_ netip.Addr) (host string)                  { return "" }
func (winServer) IPByHost(_ string) (ip netip.Addr)                    { return netip.Addr{} }

func v4Create(_ *V4ServerConf) (s DHCPServer, err error) { return winServer{}, nil }
func v6Create(_ V6ServerConf) (s DHCPServer, err error)  { return winServer{}, nil }
