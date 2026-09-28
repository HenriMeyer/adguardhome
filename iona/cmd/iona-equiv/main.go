// Command iona-equiv checks that filtering with the Iona list table decides
// exactly like filtering with every list loaded into urlfilter, the way the
// router works today (lists with $ctag=~<tag> per device-excludable list).
//
//	iona-equiv -lists <dir> [-allow <dir>] [-n 300000] [-seed 1]
//
// <dir> holds the lists as the router pulls them (with $ctag) and
// lists-meta.json.  Both sides run through filtering.DNSFilter.CheckHost.
//
//	iona-equiv -lists <dir> -mem legacy|iona [-queries 1000000]
//
// measures the process memory of one side after loading and after a query
// storm of random names, in a fresh process each.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/iona"
	"github.com/AdguardTeam/AdGuardHome/internal/iona/listtable"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
)

// list is one input list.
type list struct {
	name string
	tag  string
	text []byte
}

// profile is a filtering setup to compare under.
type profile struct {
	name     string
	selected []string
	excluded []string
}

var (
	listsDir = flag.String("lists", "", "directory with the lists and lists-meta.json")
	allowDir = flag.String("allow", "", "directory with global allowlist files")
	n        = flag.Int("n", 300000, "domains per profile")
	seed     = flag.Uint64("seed", 1, "random seed")
	memMode  = flag.String("mem", "", "measure memory of one side: legacy or iona")
	queries  = flag.Int("queries", 1000000, "random queries for -mem")
)

var logger = slogutil.New(&slogutil.Config{Level: slog.LevelWarn})

func main() {
	flag.Parse()
	if *listsDir == "" {
		flag.Usage()
		os.Exit(2)
	}

	allow := readAllow(*allowDir)
	if *memMode != "" {
		measureMemory(nil, allow)

		return
	}

	lists := readLists(*listsDir)

	compare(lists, allow)
}

// readLists reads the lists and their device tags from lists-meta.json.
func readLists(dir string) (ls []list) {
	var meta []struct {
		Name   string  `json:"name"`
		AghTag *string `json:"agh_tag"`
	}

	b, err := os.ReadFile(filepath.Join(dir, "lists-meta.json"))
	check(err)
	check(json.Unmarshal(b, &meta))

	tags := map[string]string{}
	for _, m := range meta {
		if m.AghTag != nil {
			tags[m.Name] = *m.AghTag
		}
	}

	paths, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	check(err)
	sort.Strings(paths)
	for _, p := range paths {
		text, rerr := os.ReadFile(p)
		check(rerr)
		name := filepath.Base(p)
		ls = append(ls, list{name: name, tag: tags[name], text: text})
	}

	return ls
}

// readAllow returns the global allowlist files' content.
func readAllow(dir string) (text []byte) {
	if dir == "" {
		return nil
	}

	paths, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	check(err)
	for _, p := range paths {
		b, rerr := os.ReadFile(p)
		check(rerr)
		text = append(append(text, b...), '\n')
	}

	return text
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "iona-equiv:", err)
		os.Exit(1)
	}
}

// allowID is the filter ID of the global allowlist on both sides.
const allowID = 9001

// newLegacy returns a filter with the selected lists loaded into urlfilter.
func newLegacy(lists []list, allow []byte, selected []string) (d *filtering.DNSFilter) {
	var fs []filtering.Filter
	for i, l := range lists {
		if slices.Contains(selected, l.name) {
			fs = append(fs, filtering.Filter{ID: rules.ListID(i + 1), Data: l.text})
		}
	}

	if allow != nil {
		fs = append(fs, filtering.Filter{ID: allowID, Data: allow})
	}

	d, err := filtering.New(&filtering.Config{Logger: logger}, fs)
	check(err)

	return d
}

// testMAC is the MAC address of the simulated client.
const testMAC = "02:00:00:00:00:01"

// clientIP is the address of the simulated client.
var clientIP = netip.MustParseAddr("192.168.1.100")

// ionaSide is a filter with the Iona engine.
type ionaSide struct {
	dir string
	eng *iona.Engine
	d   *filtering.DNSFilter
}

// newIona builds a signed table from lists into a fresh control directory
// and returns an engine and filter over it.
func newIona(lists []list, allow []byte) (s *ionaSide) {
	dir, err := os.MkdirTemp("", "iona-equiv")
	check(err)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	check(err)
	check(os.MkdirAll(filepath.Join(dir, iona.KeysDir), 0o755))
	check(os.WriteFile(filepath.Join(dir, iona.KeysDir, "test.pub"),
		[]byte(base64.StdEncoding.EncodeToString(pub)), 0o644))

	srcs := make([]listtable.Source, 0, len(lists))
	for _, l := range lists {
		srcs = append(srcs, listtable.Source{Name: l.name, Text: l.text})
	}

	start := time.Now()
	data, st, err := listtable.Build(srcs, &listtable.BuildConfig{
		Created: time.Now(), Key: priv, Sequence: 1,
	})
	check(err)
	fmt.Printf("table: entries=%d combos=%d residual=%d size=%d build=%s\n",
		st.Entries, st.Combos, st.Residual, st.Size, time.Since(start).Round(time.Millisecond))

	check(os.WriteFile(filepath.Join(dir, iona.TableFile), data, 0o644))

	s = &ionaSide{dir: dir}
	s.eng = iona.New(&iona.Config{
		Logger: logger,
		Dir:    dir,
		Neighbors: func() (map[netip.Addr]string, error) {
			return map[netip.Addr]string{clientIP: testMAC}, nil
		},
	})

	var fs []filtering.Filter
	if allow != nil {
		fs = append(fs, filtering.Filter{ID: allowID, Data: allow})
	}

	s.d, err = filtering.New(&filtering.Config{Logger: logger, Iona: s.eng}, fs)
	check(err)

	return s
}

// setProfile writes the control files for p and reloads.
func (s *ionaSide) setProfile(p profile, allow []byte) {
	check(os.WriteFile(filepath.Join(s.dir, iona.SelectedFile),
		[]byte(strings.Join(p.selected, "\n")+"\n"), 0o644))

	dev := ""
	if len(p.excluded) > 0 {
		dev = testMAC + " " + strings.Join(p.excluded, ",") + "\n"
	}

	check(os.WriteFile(filepath.Join(s.dir, iona.DevicesFile), []byte(dev), 0o644))

	_, err := s.eng.Reload(context.Background())
	check(err)

	st := s.eng.Status()
	if len(st.Errors) > 0 {
		check(fmt.Errorf("reload errors: %v", st.Errors))
	}

	// Rebuild the small urlfilter engine: allowlist plus residual rules.
	var fs []filtering.Filter
	if allow != nil {
		fs = append(fs, filtering.Filter{ID: allowID, Data: allow})
	}

	for _, r := range s.eng.ResidualRules() {
		fs = append(fs, filtering.Filter{ID: rules.ListID(r.ID), Data: r.Text})
	}

	d, err := filtering.New(&filtering.Config{Logger: logger, Iona: s.eng}, fs)
	check(err)
	s.d = d
}

// decide returns whether d blocks host for the client with settings setts.
func decide(d *filtering.DNSFilter, host string, setts *filtering.Settings) (blocked bool, reason string) {
	res, err := d.CheckHost(host, dns.TypeA, setts)
	check(err)

	return res.IsFiltered, res.Reason.String()
}

func compare(lists []list, allow []byte) {
	rng := mrand.New(mrand.NewPCG(*seed, *seed^0x9e3779b97f4a7c15))
	profiles := makeProfiles(lists, rng)
	domains := makeDomains(lists, allow, rng, *n)
	fmt.Printf("domains per profile: %d\n", len(domains))

	s := newIona(lists, allow)
	total, mismatches := 0, 0
	for _, p := range profiles {
		legacy := newLegacy(lists, allow, p.selected)
		s.setProfile(p, allow)

		var tags []string
		for _, l := range lists {
			if slices.Contains(p.excluded, l.name) {
				tags = append(tags, l.tag)
			}
		}

		pol := s.eng.ClientPolicy(clientIP)
		legacySetts := &filtering.Settings{
			ProtectionEnabled: true, FilteringEnabled: true, ClientTags: tags, ClientIP: clientIP,
		}
		ionaSetts := &filtering.Settings{
			ProtectionEnabled: true, FilteringEnabled: true, ClientTags: pol.Tags,
			ClientIP: clientIP, IonaPolicy: pol,
		}

		blockedLegacy, blockedIona, pm := 0, 0, 0
		var tLegacy, tIona time.Duration
		for _, host := range domains {
			t0 := time.Now()
			bl, rl := decide(legacy, host, legacySetts)
			t1 := time.Now()
			bi, ri := decide(s.d, host, ionaSetts)
			t2 := time.Now()
			tLegacy += t1.Sub(t0)
			tIona += t2.Sub(t1)

			if bl {
				blockedLegacy++
			}

			if bi {
				blockedIona++
			}

			if bl != bi {
				pm++
				if pm <= 10 {
					fmt.Printf("  MISMATCH %s: %q legacy=%v(%s) iona=%v(%s)\n", p.name, host, bl, rl, bi, ri)
				}
			}
		}

		total += len(domains)
		mismatches += pm
		fmt.Printf("%-34s lists=%-2d excluded=%-2d blocked legacy=%-7d iona=%-7d mismatches=%d  µs/query legacy=%.2f iona=%.2f\n",
			p.name, len(p.selected), len(p.excluded), blockedLegacy, blockedIona, pm,
			float64(tLegacy.Microseconds())/float64(len(domains)),
			float64(tIona.Microseconds())/float64(len(domains)))

		legacy.Close()
		runtime.GC()
	}

	fmt.Printf("TOTAL decisions=%d mismatches=%d\n", total, mismatches)
	if mismatches > 0 {
		os.Exit(1)
	}
}

// routerSelection is the selection active on the test device (2026-09-26).
var routerSelection = strings.Split("anti.piracy.txt,dns-rebind-protection.txt,doh-vpn-proxy-bypass.txt,"+
	"dyndns.txt,fake.txt,gambling.txt,native.amazon.txt,native.apple.txt,native.huawei.txt,"+
	"native.lgwebos.txt,native.oppo-realme.txt,native.roku.txt,native.samsung.txt,native.tiktok.txt,"+
	"native.vivo.txt,native.winoffice.txt,native.xiaomi.txt,nosafesearch.txt,nsfw.txt,popupads.txt,"+
	"pro.plus.txt,spam-tlds.txt,tif.medium.txt", ",")

// makeProfiles returns the profiles to compare under.
func makeProfiles(lists []list, rng *mrand.Rand) (ps []profile) {
	var all, tagged []string
	for _, l := range lists {
		all = append(all, l.name)
		if l.tag != "" {
			tagged = append(tagged, l.name)
		}
	}

	ps = append(ps,
		profile{name: "all lists", selected: all},
		profile{name: "router selection", selected: routerSelection},
		profile{name: "router selection + 5 exclusions", selected: routerSelection, excluded: []string{
			"gambling.txt", "nsfw.txt", "pro.plus.txt", "native.apple.txt", "nosafesearch.txt",
		}},
		profile{name: "all lists, every tagged excluded", selected: all, excluded: tagged},
	)

	for i := range 4 {
		p := profile{name: fmt.Sprintf("random selection #%d", i+1)}
		for _, l := range lists {
			if rng.IntN(2) == 0 {
				p.selected = append(p.selected, l.name)
				if l.tag != "" && rng.IntN(3) == 0 {
					p.excluded = append(p.excluded, l.name)
				}
			}
		}

		ps = append(ps, p)
	}

	return ps
}

// ruleDomains returns the domains of every ||domain^ rule and the TLDs of
// wildcard TLD rules.
func ruleDomains(lists []list) (domains, tlds, denyallow []string) {
	for _, l := range lists {
		for line := range strings.SplitSeq(string(l.text), "\n") {
			line = strings.TrimSpace(line)
			rest, ok := strings.CutPrefix(line, "||")
			if !ok {
				if r, ok2 := strings.CutPrefix(line, "@@||"); ok2 {
					if i := strings.IndexByte(r, '^'); i > 0 {
						domains = append(domains, r[:i])
					}
				}

				continue
			}

			i := strings.IndexByte(rest, '^')
			if i <= 0 {
				continue
			}

			dom := rest[:i]
			if t, ok2 := strings.CutPrefix(dom, "*."); ok2 {
				tlds = append(tlds, t)
				if _, da, ok3 := strings.Cut(rest[i:], "denyallow="); ok3 {
					da, _, _ = strings.Cut(da, ",")
					denyallow = append(denyallow, strings.Split(da, "|")...)
				}

				continue
			}

			domains = append(domains, dom)
		}
	}

	return domains, tlds, denyallow
}

// makeDomains returns a mix of listed, related, and unlisted names.
func makeDomains(lists []list, allow []byte, rng *mrand.Rand, n int) (out []string) {
	domains, tlds, denyallow := ruleDomains(lists)
	pick := func(s []string) string { return s[rng.IntN(len(s))] }
	label := func() string {
		const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
		b := make([]byte, 3+rng.IntN(10))
		for i := range b {
			b[i] = chars[rng.IntN(len(chars))]
		}

		return string(b)
	}

	commonTLDs := []string{"com", "de", "net", "org", "io", "info", "xyz", "app", "co.uk"}
	add := func(s string) { out = append(out, s) }
	for len(out) < n {
		switch k := rng.IntN(100); {
		case k < 30:
			add(pick(domains))
		case k < 45:
			add(label() + "." + pick(domains))
		case k < 55:
			d := pick(domains)
			if i := strings.IndexByte(d, '.'); i > 0 {
				d = d[i+1:]
			}

			add(d)
		case k < 80:
			add(label() + "." + pick(commonTLDs))
		case k < 88:
			add(label() + "." + pick(tlds))
		case k < 92 && len(denyallow) > 0:
			d := pick(denyallow)
			if rng.IntN(2) == 0 {
				d = label() + "." + d
			}

			add(d)
		case k < 96:
			add(strings.ToUpper(pick(domains)))
		default:
			add(pick(domains) + ".")
		}
	}

	for _, s := range []string{
		"fritz.box", "www.fritz.box", "fritz.nas", "fritz.local", "dns.msftncsi.com",
		"x.dns.msftncsi.com", "com", "de", "localhost", "a", "xn--mnchen-3ya.de",
	} {
		add(s)
	}

	for line := range strings.SplitSeq(string(allow), "\n") {
		if r, ok := strings.CutPrefix(strings.TrimSpace(line), "@@||"); ok {
			if i := strings.IndexByte(r, '^'); i > 0 {
				add(r[:i])
				add("sub." + r[:i])
			}
		}
	}

	return out
}

// rss returns the current and peak resident set size in MB.
func rss() (cur, peak int) {
	b, err := os.ReadFile("/proc/self/status")
	check(err)
	for line := range strings.SplitSeq(string(b), "\n") {
		var v int
		if _, err = fmt.Sscanf(line, "VmRSS: %d kB", &v); err == nil {
			cur = v / 1024
		} else if _, err = fmt.Sscanf(line, "VmHWM: %d kB", &v); err == nil {
			peak = v / 1024
		}
	}

	return cur, peak
}

// resetPeak resets VmHWM so that the next peak reading covers only what
// follows.
func resetPeak() {
	// Writing 5 to clear_refs resets the peak RSS (Linux >= 4.0).
	check(os.WriteFile("/proc/self/clear_refs", []byte("5"), 0o200))
}

var (
	table1 = flag.String("table1", "", "-mem iona: prebuilt table")
	table2 = flag.String("table2", "", "-mem iona: newer table to swap in")
	pubKey = flag.String("pub", "", "-mem iona: public key of the tables")
)

// readSelected reads only the lists of the router selection.
func readSelected(dir string) (ls []list) {
	for _, name := range routerSelection {
		text, err := os.ReadFile(filepath.Join(dir, name))
		check(err)
		ls = append(ls, list{name: name, text: text})
	}

	return ls
}

// ionaFromFile sets up an engine over a prebuilt table file, like the router.
func ionaFromFile(allow []byte) (s *ionaSide) {
	dir, err := os.MkdirTemp("", "iona-mem")
	check(err)
	check(os.MkdirAll(filepath.Join(dir, iona.KeysDir), 0o755))
	pub, err := os.ReadFile(*pubKey)
	check(err)
	check(os.WriteFile(filepath.Join(dir, iona.KeysDir, "k.pub"), pub, 0o644))
	check(os.Symlink(*table1, filepath.Join(dir, iona.TableFile)))

	s = &ionaSide{dir: dir, eng: iona.New(&iona.Config{Logger: logger, Dir: dir})}
	s.setProfile(profile{selected: routerSelection}, allow)

	return s
}

func measureMemory(_ []list, allow []byte) {
	debug.SetGCPercent(20)
	runtime.GC()
	debug.FreeOSMemory()
	resetPeak()
	c0, _ := rss()
	setts := &filtering.Settings{ProtectionEnabled: true, FilteringEnabled: true, ClientIP: clientIP}

	var d *filtering.DNSFilter
	var s *ionaSide
	start := time.Now()
	switch *memMode {
	case "legacy":
		d = newLegacy(readSelected(*listsDir), allow, routerSelection)
	case "iona":
		s = ionaFromFile(allow)
		d = s.d
		setts.IonaPolicy = s.eng.ClientPolicy(clientIP)
	default:
		check(fmt.Errorf("unknown -mem %q", *memMode))
	}

	load := time.Since(start)
	runtime.GC()
	debug.FreeOSMemory()
	c1, p1 := rss()
	fmt.Printf("%s: load=%s rss_base=%dMB rss_loaded=%dMB (+%d) peak_during_load=%dMB\n",
		*memMode, load.Round(time.Millisecond), c0, c1, c1-c0, p1)

	rng := mrand.New(mrand.NewPCG(*seed, 7))
	start = time.Now()
	for i := range *queries {
		b := make([]byte, 12)
		for j := range b {
			b[j] = byte('a' + rng.IntN(26))
		}

		_, err := d.CheckHost(string(b)+".example"+fmt.Sprint(i%1000)+".com", dns.TypeA, setts)
		check(err)
	}

	took := time.Since(start)
	runtime.GC()
	debug.FreeOSMemory()
	c2, p2 := rss()
	fmt.Printf("%s: after %d random queries (%.2f µs/query): rss=%dMB (+%d vs loaded) peak=%dMB\n",
		*memMode, *queries, float64(took.Microseconds())/float64(*queries), c2, c2-c1, p2)

	// A list change: legacy rebuilds its engine while the old one still
	// serves; iona swaps in a staged table.
	resetPeak()
	start = time.Now()
	switch *memMode {
	case "legacy":
		d2 := newLegacy(readSelected(*listsDir), allow, routerSelection)
		d.Close()
		d = d2
	case "iona":
		if *table2 != "" {
			tb, err := os.ReadFile(*table2)
			check(err)
			check(os.WriteFile(filepath.Join(s.dir, iona.NewTableFile), tb, 0o644))
			tb = nil
			s.setProfile(profile{selected: routerSelection}, allow)
			d = s.d
			if st := s.eng.Status(); st.Table.Sequence != 2 {
				check(fmt.Errorf("swap failed: %v", st.Errors))
			}
		}
	}

	swap := time.Since(start)
	runtime.GC()
	debug.FreeOSMemory()
	c3, p3 := rss()
	fmt.Printf("%s: list change took %s: peak=%dMB (+%d over loaded) rss_after=%dMB\n",
		*memMode, swap.Round(time.Millisecond), p3, p3-c2, c3)

	runtime.KeepAlive(d)
	runtime.KeepAlive(s)
}
