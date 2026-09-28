// Package iona holds the Iona router extensions of AdGuard Home: the compact
// list table with per-device list exclusions, file-based control through
// SIGHUP, and the status file that shows what is applied.
//
// Control files, all in [Config.Dir]:
//
//	lists.tbl        active table (see package listtable)
//	lists.tbl.new    staged table, raw or transport form; picked up on reload
//	lists.tbl.prev   the previously active table, used if lists.tbl is broken
//	keys/*.pub       trusted Ed25519 public keys, one base64 key per file
//	selected         enabled list names, one per line; empty or missing
//	                 means every list of the table
//	devices          per-device exclusions: "<mac> <list>[,<list>…]" per line
//
// See the README in iona/ at the repository root for the router side.
package iona

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/iona/listtable"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// File names inside [Config.Dir].
const (
	TableFile         = "lists.tbl"
	NewTableFile      = "lists.tbl.new"
	PrevTableFile     = "lists.tbl.prev"
	RejectedTableFile = "lists.tbl.rejected"
	tmpTableFile      = "lists.tbl.tmp"
	SelectedFile      = "selected"
	DevicesFile       = "devices"
	KeysDir           = "keys"
)

// ListIDBase is added to a list's bit to form the filter list ID reported for
// its matches, far above the IDs AdGuard Home assigns to configured filters.
const ListIDBase = 1_000_000

// Config is the configuration for [New].
type Config struct {
	// Logger is used for logging.  It must not be nil.
	Logger *slog.Logger

	// Neighbors resolves client addresses to MAC addresses.  If nil, the
	// kernel neighbor table is used.
	Neighbors NeighborFunc

	// Dir is the control directory.
	Dir string

	// StatusPath is where the applied state is written as JSON.  Empty
	// disables the status file.
	StatusPath string

	// MinEntries is the minimum number of entries a table must have.
	MinEntries int
}

// Engine applies the list table to queries.  Its methods are safe for
// concurrent use.
type Engine struct {
	logger *slog.Logger
	conf   *Config
	neigh  *neighborCache

	// reloadMu serializes reloads.
	reloadMu sync.Mutex

	// mu protects the fields below.  Readers hold it while using the table.
	mu       sync.RWMutex
	table    *listtable.Table
	st       state
	devices  map[string]*device
	residual []Residual
	extra    statusExtra
	applied  uint64

	// started tells a restarted daemon apart in the status file, since the
	// PID is always 1 inside procd's jail.
	started time.Time
}

// state is the applied state reported in the status file.
type state struct {
	Selected        []string `json:"selected"`
	UnknownSelected []string `json:"unknown_selected"`
	Enabled         []string `json:"enabled"`
	Errors          []string `json:"errors"`
	TableSource     string   `json:"table_source"`
	Generation      uint64   `json:"generation"`
	EnabledMask     uint64   `json:"-"`
}

// device is the resolved exclusion profile of one MAC address.
type device struct {
	names []string
	tags  []string
	mask  uint64
}

// Residual is a list's residual rules, ready for urlfilter.
type Residual struct {
	// Text is the rule text.
	Text []byte

	// ID is the filter list ID.
	ID int
}

// New returns a new engine.  Call [Engine.Reload] to load the control files.
func New(c *Config) (e *Engine) {
	nf := c.Neighbors
	if nf == nil {
		nf = kernelNeighbors
	}

	return &Engine{
		logger:  c.Logger,
		conf:    c,
		neigh:   newNeighborCache(nf),
		devices: map[string]*device{},
		started: time.Now(),
	}
}

// Policy is the per-query filtering decision input for one client.
type Policy struct {
	// mac is the client's MAC address, or empty if unknown.
	mac string

	// gen is the generation the mask was computed for.
	gen uint64

	// mask is the effective list mask: enabled lists minus the device's
	// exclusions.
	mask uint64

	// Tags are the exclusion tags of the device, for residual rules.
	Tags []string
}

// ClientPolicy returns the policy for a query from addr.
func (e *Engine) ClientPolicy(addr netip.Addr) (p Policy) {
	e.mu.RLock()
	hasDevices := len(e.devices) > 0
	e.mu.RUnlock()

	if hasDevices && addr.IsValid() {
		p.mac, _ = e.neigh.MAC(addr.Unmap())
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	e.fillPolicyLocked(&p)

	return p
}

// fillPolicyLocked computes p's mask and tags for the current generation.
// e.mu must be held.
func (e *Engine) fillPolicyLocked(p *Policy) {
	p.gen = e.st.Generation
	p.mask = e.st.EnabledMask
	p.Tags = nil
	if d, ok := e.devices[p.mac]; ok && p.mac != "" {
		p.mask &^= d.mask
		p.Tags = d.tags
	}
}

// Match is the result of a table match.
type Match struct {
	// List is the name of the list that blocks the host.
	List string

	// Rule is the rule text as it would appear in the list.
	Rule string

	// ListID is the filter list ID of the list.
	ListID int
}

// Match checks host, lowercase and without a trailing dot, against the table
// under p.
func (e *Engine) Match(host string, p Policy) (m Match, ok bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.table == nil {
		return Match{}, false
	}

	if p.gen != e.st.Generation {
		e.fillPolicyLocked(&p)
	}

	bit, matched, ok := e.table.Match(host, p.mask)
	if !ok {
		return Match{}, false
	}

	return Match{
		List:   e.table.Lists()[bit].Name,
		Rule:   "||" + matched + "^",
		ListID: ListIDBase + bit,
	}, true
}

// ListName returns the name of the list behind a filter list ID reported for a
// table or residual match, or "" if id is none of them.
func (e *Engine) ListName(id int64) (name string) {
	bit := id - ListIDBase
	if bit < 0 {
		return ""
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.table == nil || bit >= int64(len(e.table.Lists())) {
		return ""
	}

	return e.table.Lists()[bit].Name
}

// ResidualRules returns the residual rules of the enabled lists.
func (e *Engine) ResidualRules() (rs []Residual) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.residual
}

// Reload re-reads the control files, promotes a staged table, and writes the
// status file.  changed is true if the enabled lists, the residual rules, or
// the table changed, so that the caller must rebuild its urlfilter engine.
func (e *Engine) Reload(ctx context.Context) (changed bool, err error) {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()

	var errs []string
	addErr := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		errs = append(errs, msg)
		e.logger.WarnContext(ctx, msg)
	}

	keys, err := readKeys(e.conf.Dir)
	if err != nil {
		addErr("reading keys: %s", err)
	}

	selected, err := readSelected(e.conf.Dir)
	if err != nil {
		addErr("reading %s: %s", SelectedFile, err)
	}

	profiles, err := readDevices(e.conf.Dir)
	if err != nil {
		addErr("reading %s: %s", DevicesFile, err)
	}

	e.mu.RLock()
	cur, curSource := e.table, e.st.TableSource
	e.mu.RUnlock()

	next, source, tableErrs := e.loadTable(ctx, keys, cur, curSource)
	errs = append(errs, tableErrs...)

	return e.apply(ctx, next, source, selected, profiles, errs), nil
}

// apply installs the new state and writes the status file.
func (e *Engine) apply(
	ctx context.Context,
	next *listtable.Table,
	source string,
	selected []string,
	profiles map[string][]string,
	errs []string,
) (changed bool) {
	st := state{Selected: selected, TableSource: source, Errors: errs}
	devices := map[string]*device{}
	var residual []Residual
	if next != nil {
		st.EnabledMask, st.UnknownSelected = enabledMask(next, selected)
		for _, l := range next.Lists() {
			if st.EnabledMask&(1<<uint(l.Bit)) != 0 {
				st.Enabled = append(st.Enabled, l.Name)
			}
		}

		devices = resolveDevices(next, profiles)
		residual = residualRules(next, st.EnabledMask)
	}

	e.mu.Lock()
	old := e.table
	changed = old != next || e.st.EnabledMask != st.EnabledMask ||
		!slices.EqualFunc(e.residual, residual, func(a, b Residual) bool {
			return a.ID == b.ID && string(a.Text) == string(b.Text)
		})
	st.Generation = e.st.Generation + 1
	e.table, e.st, e.devices, e.residual = next, st, devices, residual
	e.mu.Unlock()

	if old != nil && old != next {
		err := old.Close()
		if err != nil {
			e.logger.ErrorContext(ctx, "closing old table", slogutil.KeyError, err)
		}
	}

	e.writeStatus(ctx)

	return changed
}

// enabledMask returns the mask of the selected lists; an empty selection
// enables every list, like the router scripts always did.
func enabledMask(t *listtable.Table, selected []string) (mask uint64, unknown []string) {
	if len(selected) == 0 {
		return t.AllMask(), nil
	}

	return t.Mask(selected)
}

// resolveDevices resolves exclusion profiles against t.
func resolveDevices(t *listtable.Table, profiles map[string][]string) (devs map[string]*device) {
	devs = make(map[string]*device, len(profiles))
	for mac, names := range profiles {
		d := &device{names: names}
		for _, n := range names {
			bit, ok := t.Bit(n)
			if !ok {
				continue
			}

			d.mask |= 1 << uint(bit)
			d.tags = append(d.tags, ExclusionTag(n))
		}

		devs[mac] = d
	}

	return devs
}

// ExclusionTag returns the client tag that excludes a device from the residual
// rules of the named list.
func ExclusionTag(list string) (tag string) {
	key := strings.TrimSuffix(strings.ToLower(list), ".txt")
	b := []byte("iona_x_" + key)
	for i := len("iona_x_"); i < len(b); i++ {
		c := b[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			b[i] = '_'
		}
	}

	return string(b)
}

// residualRules returns the residual rules of the lists in mask, each rule
// limited to clients not excluded from its list.
func residualRules(t *listtable.Table, mask uint64) (rs []Residual) {
	for _, l := range t.Lists() {
		if mask&(1<<uint(l.Bit)) == 0 || len(l.Residual) == 0 {
			continue
		}

		tag := ExclusionTag(l.Name)
		var sb strings.Builder
		for _, r := range l.Residual {
			sb.WriteString(withExclusionTag(r, tag))
			sb.WriteByte('\n')
		}

		rs = append(rs, Residual{ID: ListIDBase + l.Bit, Text: []byte(sb.String())})
	}

	return rs
}

// withExclusionTag adds "ctag=~tag" to rule's modifiers, replacing a legacy
// negated $ctag that hagezi-sync used to append.
func withExclusionTag(rule, tag string) (out string) {
	if i := strings.LastIndex(rule, "$ctag=~"); i >= 0 && !strings.ContainsAny(rule[i+7:], ",$") {
		rule = rule[:i]
	} else if i = strings.LastIndex(rule, ",ctag=~"); i >= 0 && !strings.ContainsAny(rule[i+7:], ",$") {
		rule = rule[:i]
	}

	// A regex rule without modifiers ends with its closing slash; a "$"
	// inside the regex doesn't start a modifier list.
	pattern := strings.TrimPrefix(rule, "@@")
	isBareRegex := len(pattern) > 1 && pattern[0] == '/' && strings.HasSuffix(pattern, "/")
	if strings.Contains(rule, "$") && !isBareRegex {
		return rule + ",ctag=~" + tag
	}

	return rule + "$ctag=~" + tag
}

// TableInfo describes the active table.
type TableInfo struct {
	Created  time.Time
	Lists    []string
	Sequence uint64
	Entries  int
	Size     int
	Loaded   bool
}

// Table returns information about the active table.
func (e *Engine) Table() (ti TableInfo) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.table == nil {
		return TableInfo{}
	}

	for _, l := range e.table.Lists() {
		ti.Lists = append(ti.Lists, l.Name)
	}

	return TableInfo{
		Created:  e.table.Created(),
		Lists:    ti.Lists,
		Sequence: e.table.Sequence(),
		Entries:  e.table.Entries(),
		Size:     e.table.Size(),
		Loaded:   true,
	}
}

// Close releases the table.
func (e *Engine) Close() (err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.neigh.stop()
	if e.table == nil {
		return nil
	}

	err = e.table.Close()
	e.table = nil

	return err
}
