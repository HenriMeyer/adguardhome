package home

import (
	"cmp"
	"context"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/dnsforward"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/iona"
	"github.com/AdguardTeam/AdGuardHome/internal/iona/history"
	"github.com/AdguardTeam/AdGuardHome/internal/querylog"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// Environment variables of the Iona router mode.  procd sets them from
// /etc/init.d/adguardhome.
const (
	// ionaDirEnv enables Iona mode and names the control directory.
	ionaDirEnv = "AGH_IONA_DIR"

	// ionaStatusEnv names the status file.
	ionaStatusEnv = "AGH_IONA_STATUS"

	// ionaMinEntriesEnv overrides the minimum table size.
	ionaMinEntriesEnv = "AGH_IONA_MIN_ENTRIES"

	// ionaHistoryEnv names the DNS history directory; "off" disables it.
	ionaHistoryEnv = "AGH_IONA_HISTORY"

	// ionaRouterIPEnv is the router's LAN address for the history.
	ionaRouterIPEnv = "AGH_IONA_ROUTER_IP"

	// ionaTZEnv is the router's IANA time zone for the history's dates.
	ionaTZEnv = "AGH_IONA_TZ"
)

// Defaults of the Iona router mode.
const (
	defaultIonaStatus     = "/tmp/adguardhome/iona-status.json"
	defaultIonaMinEntries = 10000
	defaultIonaHistory    = "/etc/adguardhome/history"

	// ionaHistory24hIvl and ionaHistory7dIvl are the write intervals of the
	// history files, as the router's cron ran the scripts.
	ionaHistory24hIvl = 5 * time.Minute
	ionaHistory7dIvl  = time.Hour
)

// ionaState is the Iona router mode: the list engine plus the DNS settings
// controlled through files.  Reloads are triggered by SIGHUP.
type ionaState struct {
	logger *slog.Logger
	engine *iona.Engine
	dir    string

	// mu serializes reloads.
	mu sync.Mutex

	// dnsErr is the last error applying the DNS control files.
	dnsErr string

	// history counts the DNS history; nil if disabled.
	history *history.History

	// histMu protects the fields below.
	histMu     sync.Mutex
	hist24hAt  time.Time
	hist7dAt   time.Time
	histErr    string
	histWrites uint64
}

// newIonaFromEnv returns the Iona state if Iona mode is enabled.
func newIonaFromEnv(ctx context.Context, baseLogger *slog.Logger) (s *ionaState) {
	dir := os.Getenv(ionaDirEnv)
	if dir == "" {
		return nil
	}

	statusPath := os.Getenv(ionaStatusEnv)
	if statusPath == "" {
		statusPath = defaultIonaStatus
	}

	minEntries := defaultIonaMinEntries
	if v, err := strconv.Atoi(os.Getenv(ionaMinEntriesEnv)); err == nil && v >= 0 {
		minEntries = v
	}

	l := baseLogger.With(slogutil.KeyPrefix, "iona")
	s = &ionaState{
		logger: l,
		dir:    dir,
		engine: iona.New(&iona.Config{
			Logger:     l,
			Dir:        dir,
			StatusPath: statusPath,
			MinEntries: minEntries,
		}),
	}

	s.engine.SetStatusExtra(s.statusExtra)
	l.InfoContext(ctx, "iona mode enabled", "dir", dir, "status", statusPath)

	if hdir := cmp.Or(os.Getenv(ionaHistoryEnv), defaultIonaHistory); hdir != "off" {
		loc := time.UTC
		if tz := os.Getenv(ionaTZEnv); tz != "" {
			var err error
			loc, err = time.LoadLocation(tz)
			if err != nil {
				l.WarnContext(ctx, "history time zone", "tz", tz, slogutil.KeyError, err)
				loc = time.UTC
			}
		}

		s.history = history.New(&history.Config{
			Logger:      l.With("part", "history"),
			Location:    loc,
			OutDir:      hdir,
			RegistryDir: hdir,
			RouterIP:    os.Getenv(ionaRouterIPEnv),
			ListName:    s.engine.ListName,
		})
	}

	return s
}

// loadHistory reads the existing query log into the history before the DNS
// server starts, so that no entry is counted twice.
func (s *ionaState) loadHistory(ctx context.Context, querylogDir string) {
	start := time.Now()
	s.history.SetQueryLogDir(querylogDir)
	n, err := s.history.Load()
	if err != nil {
		s.logger.ErrorContext(ctx, "loading history from query log", slogutil.KeyError, err)
	}

	s.logger.InfoContext(ctx, "history loaded", "entries", n, "took", time.Since(start))
}

// addHistory counts one query log entry.
func (s *ionaState) addHistory(e *querylog.HistoryEntry) {
	ip := ""
	if e.ClientIP != nil {
		ip = e.ClientIP.String()
	}

	var listID int64
	if len(e.Result.Rules) > 0 {
		listID = int64(e.Result.Rules[0].FilterListID)
	}

	s.history.Add(history.EntryFromLog(
		e.Time, e.Host, ip, e.ClientID, e.Result.IsFiltered, int(e.Result.Reason), listID,
	))
}

// writeHistory writes both history files now (SIGUSR1).
func (s *ionaState) writeHistory(ctx context.Context) {
	if s.history == nil {
		return
	}

	s.write24h(ctx)
	s.write7d(ctx)

	s.histMu.Lock()
	s.histWrites++
	s.histMu.Unlock()

	s.engine.WriteStatus(ctx)
}

// write24h writes the 24-hour history and records the outcome.
func (s *ionaState) write24h(ctx context.Context) {
	err := s.history.Write24h()

	s.histMu.Lock()
	defer s.histMu.Unlock()

	s.hist24hAt, s.histErr = time.Now(), ""
	if err != nil {
		s.histErr = err.Error()
		s.logger.ErrorContext(ctx, "writing 24h history", slogutil.KeyError, err)
	}
}

// write7d writes the 7-day history and records the outcome.
func (s *ionaState) write7d(ctx context.Context) {
	err := s.history.Write7d()

	s.histMu.Lock()
	defer s.histMu.Unlock()

	s.hist7dAt = time.Now()
	if err != nil {
		s.histErr = err.Error()
		s.logger.ErrorContext(ctx, "writing 7d history", slogutil.KeyError, err)
	}
}

// runHistory writes the history files at start and then periodically.
func (s *ionaState) runHistory(ctx context.Context) {
	if s.history == nil {
		return
	}

	defer slogutil.RecoverAndLog(ctx, s.logger)

	s.writeHistory(ctx)

	t24 := time.NewTicker(ionaHistory24hIvl)
	t7 := time.NewTicker(ionaHistory7dIvl)
	defer t24.Stop()
	defer t7.Stop()

	for {
		select {
		case <-t24.C:
			s.write24h(ctx)
		case <-t7.C:
			s.write7d(ctx)
		}
	}
}

// initialLoad loads the table and overlays the DNS control files onto the
// configuration before the filtering and DNS modules are created from it.
// config must be locked for writing or not yet shared.
func (s *ionaState) initialLoad(ctx context.Context) {
	_, err := s.engine.Reload(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "loading", slogutil.KeyError, err)
	}

	c, err := iona.ReadDNSControl(s.dir)
	if err != nil {
		s.dnsErr = err.Error()
		s.logger.ErrorContext(ctx, "reading dns control files", slogutil.KeyError, err)
	}

	if c.Upstreams != nil {
		config.DNS.UpstreamDNS = c.Upstreams
	}

	if c.Fallbacks != nil {
		config.DNS.FallbackDNS = c.Fallbacks
	}

	if b := c.Blocking; b != nil {
		config.Filtering.BlockingMode = filtering.BlockingMode(b.Mode)
		config.Filtering.BlockingIPv4, config.Filtering.BlockingIPv6 = b.IPv4, b.IPv6
	}

	if c.Rewrites != nil {
		config.Filtering.Rewrites = config.Filtering.Rewrites[:0]
		for _, rw := range c.Rewrites {
			config.Filtering.Rewrites = append(config.Filtering.Rewrites, &filtering.LegacyRewrite{
				Domain: rw[0], Answer: rw[1], Enabled: true,
			})
		}
	}

	config.Filtering.Iona = s.engine
}

// reload applies all control files to the running modules.  It is called on
// SIGHUP.
func (s *ionaState) reload(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	filters, dnsServer := globalContext.filters, globalContext.dnsServer
	if filters == nil || dnsServer == nil {
		s.logger.WarnContext(ctx, "reload before start, ignoring")

		return
	}

	changed, err := s.engine.Reload(ctx)
	if err != nil {
		s.logger.ErrorContext(ctx, "reloading", slogutil.KeyError, err)
	}

	// The user allowlist, the global allowlist, and user rules are small
	// local files; an allowlist-only change is applied without touching the
	// other engines.
	updated, ok := filters.RefreshLocalFilters()
	if !ok {
		s.logger.WarnContext(ctx, "filter refresh already running")
	}

	if changed {
		filters.EnableFilters(false)
	}

	s.dnsErr = ""
	err = s.applyDNS(ctx, filters, dnsServer)
	if err != nil {
		s.dnsErr = err.Error()
		s.logger.ErrorContext(ctx, "applying dns control files", slogutil.KeyError, err)
	}

	// Answers cached under the old state would outlive the change, e.g. a
	// freshly allowlisted domain would stay blocked until its TTL expired.
	dnsServer.IonaClearCache()

	s.engine.Applied(ctx)
	s.logger.InfoContext(ctx, "reloaded", "lists_changed", changed, "filters_updated", updated)
}

// applyDNS applies the DNS control files to the running modules.
func (s *ionaState) applyDNS(
	ctx context.Context,
	filters *filtering.DNSFilter,
	dnsServer *dnsforward.Server,
) (err error) {
	c, err := iona.ReadDNSControl(s.dir)
	if err != nil {
		return err
	}

	st := &dnsforward.IonaDNSSettings{Upstreams: c.Upstreams, Fallbacks: c.Fallbacks}
	if b := c.Blocking; b != nil {
		st.Blocking = &dnsforward.IonaBlocking{
			Mode: filtering.BlockingMode(b.Mode), IPv4: b.IPv4, IPv6: b.IPv6,
		}
	}

	_, err = dnsServer.ApplyIona(ctx, st)
	if err != nil {
		return err
	}

	if c.Rewrites == nil {
		return nil
	}

	rws := make([]filtering.IonaRewrite, 0, len(c.Rewrites))
	for _, rw := range c.Rewrites {
		rws = append(rws, filtering.IonaRewrite{Domain: rw[0], Answer: rw[1]})
	}

	_, err = filters.SetIonaRewrites(ctx, rws)

	return err
}

// statusExtra adds the applied DNS settings to the status file.
func (s *ionaState) statusExtra() (m map[string]any) {
	m = map[string]any{}
	if s.history != nil {
		s.histMu.Lock()
		m["history"] = map[string]any{
			"entries":    s.history.Len(),
			"written24h": unixOrZero(s.hist24hAt),
			"written7d":  unixOrZero(s.hist7dAt),
			"writes":     s.histWrites,
			"error":      s.histErr,
		}
		s.histMu.Unlock()
	}

	if s.dnsErr != "" {
		m["dns_error"] = s.dnsErr
	}

	if srv := globalContext.dnsServer; srv != nil {
		up, fb, b := srv.IonaDNSState()
		m["upstreams"], m["fallbacks"] = up, fb
		m["blocking"] = map[string]string{
			"mode": string(b.Mode), "ipv4": addrString(b.IPv4), "ipv6": addrString(b.IPv6),
		}
	}

	if f := globalContext.filters; f != nil {
		rws := []map[string]string{}
		for _, rw := range f.IonaRewrites() {
			rws = append(rws, map[string]string{"domain": rw.Domain, "answer": rw.Answer})
		}

		m["rewrites"] = rws
	}

	return m
}

// unixOrZero returns t as Unix seconds, or 0 for the zero time.
func unixOrZero(t time.Time) (u int64) {
	if t.IsZero() {
		return 0
	}

	return t.Unix()
}

// addrString returns a's string form, or "" if it is invalid.
func addrString(a netip.Addr) (s string) {
	if !a.IsValid() {
		return ""
	}

	return a.String()
}
