package filtering

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering/rulelist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// applyIona resolves the client's Iona list policy.  The exclusion tags are
// added to a copy of the client tags, so the residual rules of excluded lists
// don't apply to the client either.
func (d *DNSFilter) applyIona(cliAddr netip.Addr, setts *Settings) {
	e := d.conf.Iona
	if e == nil {
		return
	}

	setts.IonaPolicy = e.ClientPolicy(cliAddr)
	if len(setts.IonaPolicy.Tags) > 0 {
		setts.ClientTags = slices.Concat(setts.ClientTags, setts.IonaPolicy.Tags)
	}
}

// matchIona checks host against the Iona list table.  It is consulted only
// when no urlfilter rule matched, so allowlists, user rules, and the lists'
// residual exceptions keep taking precedence over plain list entries, exactly
// as when every list was loaded into urlfilter.
func (d *DNSFilter) matchIona(host string, setts *Settings) (res Result) {
	e := d.conf.Iona
	if e == nil || !setts.ProtectionEnabled {
		return Result{}
	}

	m, ok := e.Match(host, setts.IonaPolicy)
	if !ok {
		return Result{}
	}

	return Result{
		Rules: []*ResultRule{{
			Text:         m.Rule,
			FilterListID: rulelist.APIID(m.ListID),
		}},
		Reason:     FilteredBlockList,
		IsFiltered: true,
	}
}

// ionaResidualFilters returns the residual rules of the enabled Iona lists as
// in-memory filters.
func (d *DNSFilter) ionaResidualFilters() (filters []Filter) {
	e := d.conf.Iona
	if e == nil {
		return nil
	}

	for _, r := range e.ResidualRules() {
		filters = append(filters, Filter{ID: rules.ListID(r.ID), Data: r.Text})
	}

	return filters
}

// RefreshLocalFilters re-reads every configured filter from its source and
// rebuilds the engines that changed.  On the router all remaining filters are
// small local files (user allowlist, global allowlist), so this is cheap; an
// allowlist-only change rebuilds only the allowlist engine.
func (d *DNSFilter) RefreshLocalFilters() (updated int, ok bool) {
	updated, _, ok = d.tryRefreshFilters(true, true, true)

	return updated, ok
}

// IonaRewrite is a legacy rewrite as set from an Iona control file.
type IonaRewrite struct {
	Domain string
	Answer string
}

// SetIonaRewrites replaces all legacy rewrites with rws, if they differ, and
// saves the configuration.
func (d *DNSFilter) SetIonaRewrites(ctx context.Context, rws []IonaRewrite) (changed bool, err error) {
	next := make([]*LegacyRewrite, 0, len(rws))
	for _, rw := range rws {
		lr := &LegacyRewrite{Domain: rw.Domain, Answer: rw.Answer, Enabled: true}
		err = lr.normalize(ctx, d.logger)
		if err != nil {
			return false, fmt.Errorf("rewrite %q: %w", rw.Domain, err)
		}

		next = append(next, lr)
	}

	d.confMu.Lock()
	changed = !slices.EqualFunc(d.conf.Rewrites, next, func(a, b *LegacyRewrite) bool {
		return a.Domain == b.Domain && a.Answer == b.Answer && a.Enabled == b.Enabled
	})
	if changed {
		d.conf.Rewrites = next
	}
	d.confMu.Unlock()

	if changed {
		d.conf.ConfModifier.Apply(ctx)
	}

	return changed, nil
}

// IonaRewrites returns the enabled legacy rewrites.
func (d *DNSFilter) IonaRewrites() (rws []IonaRewrite) {
	d.confMu.RLock()
	defer d.confMu.RUnlock()

	for _, r := range d.conf.Rewrites {
		if r.Enabled {
			rws = append(rws, IonaRewrite{Domain: r.Domain, Answer: r.Answer})
		}
	}

	return rws
}
