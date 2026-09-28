// Package history counts the router's DNS history inside AdGuard Home and
// writes the same JSON files the router scripts router-dns-build-24h-history
// and router-dns-build-7d-history built from the query log every 5 minutes and
// every hour (KAN-119, stage 3).  The web UI and the CGI read those files
// unchanged.
//
// The package keeps the recent query log entries (both log generations, up to
// 49 hours) in a compact form and recomputes the aggregates from them, exactly
// like the scripts did over querylog.json.1 and querylog.json: the same time
// window, the same client keys from the registry snapshot, the same top-N
// truncation and tie order, the same per-day files with their high-water mark.
// Only the source differs: entries come from the running daemon instead of
// re-reading up to 10 MiB of log every five minutes.
package history

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Entry is one query log entry as the history counts it.
type Entry struct {
	// Host is the lowercase question host.
	Host string

	// IP is the client address as written to the log.
	IP string

	// CID is the client ID, if any.
	CID string

	// Day is the date part of the log timestamp.
	Day string

	// Epoch is the log timestamp's wall-clock time read as UTC, which is
	// what the scripts computed; the log is written in UTC on the router.
	Epoch int64

	// Blocked is true for filtered answers (IsFiltered or Reason 3..8).
	Blocked bool
}

// Config is the configuration for [New].
type Config struct {
	// Logger is used for logging.  It must not be nil.
	Logger *slog.Logger

	// Now returns the current time.  If nil, [time.Now] is used.
	Now func() time.Time

	// Location is the router's time zone, used for the dates of the 7-day
	// view like `date` did in the script.  If nil, UTC is used.
	Location *time.Location

	// OutDir receives the history files.
	OutDir string

	// RegistryDir holds snap-ip2key.tsv and snap-mac2name.tsv, maintained by
	// router-dns-refresh-registry.
	RegistryDir string

	// QueryLogDir holds querylog.json and querylog.json.1 for [History.Load].
	QueryLogDir string

	// RouterIP is the router's LAN address; its queries count as lb:router.
	RouterIP string
}

// keep is how long entries are kept: two log generations of 24 hours plus
// the bucket in progress.
const keep = 49 * time.Hour

// History aggregates query log entries.  Its methods are safe for concurrent
// use.
type History struct {
	conf *Config

	mu      sync.Mutex
	entries []Entry
	strs    map[string]string
}

// New returns a new history.
func New(c *Config) (h *History) {
	if c.Now == nil {
		c.Now = time.Now
	}

	if c.Location == nil {
		c.Location = time.UTC
	}

	return &History{conf: c, strs: map[string]string{}}
}

// intern returns a shared copy of s.  h.mu must be held.
func (h *History) intern(s string) (out string) {
	if s == "" {
		return ""
	}

	if v, ok := h.strs[s]; ok {
		return v
	}

	h.strs[s] = s

	return s
}

// Add adds an entry.
func (h *History) Add(e Entry) {
	h.mu.Lock()
	defer h.mu.Unlock()

	e.Host, e.IP, e.CID, e.Day = h.intern(e.Host), h.intern(e.IP), h.intern(e.CID), h.intern(e.Day)
	h.entries = append(h.entries, e)
}

// EntryFromLog converts a query log entry's fields.  wall is the log
// timestamp in the location it is written in.
func EntryFromLog(wall time.Time, host, ip, cid string, isFiltered bool, reason int) (e Entry) {
	w := wall.Format("2006-01-02T15:04:05")
	t, _ := time.Parse("2006-01-02T15:04:05", w)

	return Entry{
		Host:    strings.ToLower(host),
		IP:      ip,
		CID:     cid,
		Day:     w[:10],
		Epoch:   t.Unix(),
		Blocked: isFiltered || (reason >= 3 && reason <= 8),
	}
}

// logLine is the part of a query log line the history reads.
type logLine struct {
	T      string `json:"T"`
	QH     string `json:"QH"`
	IP     string `json:"IP"`
	CID    string `json:"CID"`
	Result struct {
		IsFiltered bool `json:"IsFiltered"`
		Reason     int  `json:"Reason"`
	} `json:"Result"`
}

// Load replaces the entries with the ones in the query log files, oldest
// generation first, as the scripts read them.
func (h *History) Load() (n int, err error) {
	var loaded []Entry
	for _, name := range []string{"querylog.json.1", "querylog.json"} {
		var es []Entry
		es, err = readLog(filepath.Join(h.conf.QueryLogDir, name))
		if err != nil {
			return 0, err
		}

		loaded = append(loaded, es...)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.entries = h.entries[:0]
	h.strs = map[string]string{}
	for _, e := range loaded {
		e.Host, e.IP, e.CID, e.Day = h.intern(e.Host), h.intern(e.IP), h.intern(e.CID), h.intern(e.Day)
		h.entries = append(h.entries, e)
	}

	return len(h.entries), nil
}

// readLog reads the entries of one log file; a missing file has none.
func readLog(path string) (es []Entry, err error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()

	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		var l logLine
		if json.Unmarshal(s.Bytes(), &l) != nil || len(l.T) < 19 {
			continue
		}

		t, perr := time.Parse("2006-01-02T15:04:05", l.T[:19])
		if perr != nil {
			continue
		}

		es = append(es, Entry{
			Host:    strings.ToLower(l.QH),
			IP:      l.IP,
			CID:     l.CID,
			Day:     l.T[:10],
			Epoch:   t.Unix(),
			Blocked: l.Result.IsFiltered || (l.Result.Reason >= 3 && l.Result.Reason <= 8),
		})
	}

	return es, s.Err()
}

// prune drops entries older than keep.  Entries normally arrive in time
// order, but a clock step (NTP after boot) can break that, so all entries are
// checked.  h.mu must be held.
func (h *History) prune(now int64) {
	cut := now - int64(keep/time.Second)
	kept := h.entries[:0]
	for _, e := range h.entries {
		if e.Epoch >= cut {
			kept = append(kept, e)
		}
	}

	if len(kept) == len(h.entries) {
		return
	}

	h.entries = kept
	h.strs = map[string]string{}
	for j := range h.entries {
		e := &h.entries[j]
		e.Host, e.IP, e.CID, e.Day = h.intern(e.Host), h.intern(e.IP), h.intern(e.CID), h.intern(e.Day)
	}
}

// snapshot prunes and returns a copy of the entries.
func (h *History) snapshot() (es []Entry) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.prune(h.conf.Now().Unix())

	return append([]Entry(nil), h.entries...)
}

// SetQueryLogDir sets the directory [History.Load] reads.
func (h *History) SetQueryLogDir(dir string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.conf.QueryLogDir = dir
}

// Len returns the number of entries kept.
func (h *History) Len() (n int) {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(h.entries)
}

// registry is the client key map and the client labels.
type registry struct {
	keys   map[string]string
	labels [][2]string
}

// readRegistry reads the registry snapshot.  Like the scripts, the labels
// are only used when the key map exists.
func (h *History) readRegistry() (r *registry) {
	r = &registry{keys: map[string]string{}}
	keys, _ := readTSV(filepath.Join(h.conf.RegistryDir, "snap-ip2key.tsv"))
	if len(keys) > 0 {
		for _, f := range keys {
			if len(f) >= 2 && f[0] != "" && f[1] != "" {
				r.keys[f[0]] = f[1]
			}
		}

		labels, _ := readTSV(filepath.Join(h.conf.RegistryDir, "snap-mac2name.tsv"))
		for _, f := range labels {
			if len(f) >= 2 {
				r.labels = append(r.labels, [2]string{f[0], f[1]})
			}
		}
	}

	r.keys["127.0.0.1"] = "lb:router"
	r.keys["::1"] = "lb:router"
	if h.conf.RouterIP != "" {
		r.keys[h.conf.RouterIP] = "lb:router"
	}

	return r
}

// readTSV returns the tab-separated fields of each line of path.
func readTSV(path string) (rows [][]string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for line := range strings.SplitSeq(string(b), "\n") {
		if line == "" {
			continue
		}

		rows = append(rows, strings.Split(line, "\t"))
	}

	return rows, nil
}

// clientKey returns the client key the scripts used for an entry.
func (h *History) clientKey(r *registry, e *Entry) (ck string) {
	switch {
	case e.CID != "":
		return "@" + e.CID
	case e.IP == "":
		return ""
	case h.isRouterIP(e.IP):
		return "lb:router"
	}

	if k, ok := r.keys[e.IP]; ok {
		return k
	}

	return e.IP
}

// isRouterIP mirrors the scripts' is_router_ip.
func (h *History) isRouterIP(ip string) (ok bool) {
	return ip == "127.0.0.1" || ip == "::1" || (h.conf.RouterIP != "" && ip == h.conf.RouterIP) ||
		strings.HasPrefix(ip, "::ffff:127.0.0.1")
}

// writeAtomic writes data to path through a temporary file.
func writeAtomic(path string, data []byte) (err error) {
	tmp := path + ".new"
	err = os.WriteFile(tmp, data, 0o644)
	if err != nil {
		return err
	}

	return os.Rename(tmp, path)
}

// labelsJSON returns the _top_client_names members like the scripts: every
// label line in file order, lb:router added unless present.
func labelsJSON(r *registry) (s string) {
	var sb strings.Builder
	for i, l := range r.labels {
		if i > 0 {
			sb.WriteByte(',')
		}

		fmt.Fprintf(&sb, `"%s":"%s"`, scriptEscape(l[0]), scriptEscape(l[1]))
	}

	s = sb.String()
	if !strings.Contains(s, `"lb:router"`) {
		if s != "" {
			s = `"lb:router":"Router",` + s
		} else {
			s = `"lb:router":"Router"`
		}
	}

	return s
}
