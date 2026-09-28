package dnsforward

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
)

// IonaDNSSettings are the DNS settings the Iona router controls through files
// instead of the HTTP API.  Nil fields are left as they are.
type IonaDNSSettings struct {
	// Upstreams replaces the upstream servers.
	Upstreams []string

	// Fallbacks replaces the fallback servers.
	Fallbacks []string

	// Blocking replaces the blocking mode and addresses.
	Blocking *IonaBlocking
}

// IonaBlocking is a blocking mode with its custom addresses.
type IonaBlocking struct {
	Mode filtering.BlockingMode
	IPv4 netip.Addr
	IPv6 netip.Addr
}

// ApplyIona validates and applies st the same way the dns_config HTTP handler
// does, and reports whether anything changed.
func (s *Server) ApplyIona(ctx context.Context, st *IonaDNSSettings) (changed bool, err error) {
	req := &jsonDNSConfig{}

	s.serverLock.RLock()
	if st.Upstreams != nil && !slices.Equal(st.Upstreams, s.conf.UpstreamDNS) {
		req.Upstreams = &st.Upstreams
	}

	if st.Fallbacks != nil && !slices.Equal(st.Fallbacks, s.conf.FallbackDNS) {
		req.Fallbacks = &st.Fallbacks
	}
	s.serverLock.RUnlock()

	if b := st.Blocking; b != nil {
		mode, ip4, ip6 := s.dnsFilter.BlockingMode()
		if b.Mode != mode || b.IPv4 != ip4 || b.IPv6 != ip6 {
			req.BlockingMode, req.BlockingIPv4, req.BlockingIPv6 = &b.Mode, b.IPv4, b.IPv6
		}
	}

	if req.Upstreams == nil && req.Fallbacks == nil && req.BlockingMode == nil {
		return false, nil
	}

	ourAddrs, err := s.conf.ourAddrsSet(ctx, s.logger)
	if err != nil {
		return false, fmt.Errorf("getting our addresses: %w", err)
	}

	err = req.validate(ctx, s.logger, ourAddrs, s.sysResolvers, s.privateNets, s.conf.CacheSize)
	if err != nil {
		return false, err
	}

	restart := s.setConfig(req)
	s.conf.ConfModifier.Apply(ctx)

	if restart {
		err = s.Reconfigure(ctx, nil)
	}

	return true, err
}

// IonaDNSState returns the applied upstreams and blocking settings for the
// status file.
func (s *Server) IonaDNSState() (upstreams, fallbacks []string, blocking IonaBlocking) {
	s.serverLock.RLock()
	upstreams = slices.Clone(s.conf.UpstreamDNS)
	fallbacks = slices.Clone(s.conf.FallbackDNS)
	s.serverLock.RUnlock()

	blocking.Mode, blocking.IPv4, blocking.IPv6 = s.dnsFilter.BlockingMode()

	return upstreams, fallbacks, blocking
}

// IonaClearCache clears the DNS cache and the per-client upstream caches, as
// the cache_clear HTTP handler does, so that answers cached under the old
// filtering state don't outlive a reload.
func (s *Server) IonaClearCache() {
	s.serverLock.RLock()
	p := s.dnsProxy
	s.serverLock.RUnlock()

	if p != nil {
		p.ClearCache()
	}

	if cc := s.conf.ClientsContainer; cc != nil {
		cc.ClearUpstreamCache()
	}
}
