package history

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Constants of the scripts.
const (
	bucketSec   = 900
	bucketCount = 96

	topDomains24h   = 50
	topClients24h   = 20
	topPerClient24h = 40

	keepDays          = 7
	topDomainsPerDay  = 80
	topClientsPerDay  = 30
	topDomainsFinal7d = 50
	topClientsFinal7d = 20
	gcKeepDays        = 30

	file24h        = "router-dns-24h-history.json"
	fileBlockedBy  = "router-dns-blocked-by-client.json"
	file7d         = "router-dns-history.json"
	blockedByLimit = topPerClient24h
)

// scriptEscape escapes like the scripts' awk: backslash and double quote.
func scriptEscape(s string) (out string) {
	if !strings.ContainsAny(s, `\"`) {
		return s
	}

	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

// counted is a name with a count.
type counted struct {
	name  string
	count int
}

// topN returns the n largest counts in the order of busybox
// `sort -t<TAB> -k1,1 -nr | head -n n` over "count<TAB>name" lines: count
// descending, ties by the whole line compared bytewise in reverse, i.e. by
// name descending.
func topN(m map[string]int, n int) (out []counted) {
	out = make([]counted, 0, len(m))
	for k, v := range m {
		out = append(out, counted{name: k, count: v})
	}

	slices.SortFunc(out, func(a, b counted) int {
		if c := cmp.Compare(b.count, a.count); c != 0 {
			return c
		}

		return strings.Compare(b.name, a.name)
	})

	if len(out) > n {
		out = out[:n]
	}

	return out
}

// topJSON renders counts as the scripts' {"name":count},… array body.
func topJSON(cs []counted) (s string) {
	var sb strings.Builder
	for i, c := range cs {
		if i > 0 {
			sb.WriteByte(',')
		}

		fmt.Fprintf(&sb, `{"%s":%d}`, scriptEscape(c.name), c.count)
	}

	return sb.String()
}

// allowedOnly returns total minus blocked per name, keeping positive ones.
func allowedOnly(tot, blk map[string]int) (m map[string]int) {
	m = make(map[string]int, len(tot))
	for k, t := range tot {
		if a := t - blk[k]; a > 0 {
			m[k] = a
		}
	}

	return m
}

// ints renders integers as a comma-separated list.
func ints(vs []int) (s string) {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(v)
	}

	return strings.Join(parts, ",")
}

// clientDomain is a blocked domain of one client.
type clientDomain struct {
	domain string
	count  int
	last   int64
}

// Write24h writes the 24-hour history and the blocked-by-client file.
func (h *History) Write24h() (err error) {
	es := h.snapshot()
	r := h.readRegistry()
	now := h.conf.Now().Unix()
	winEnd := (now/bucketSec)*bucketSec + bucketSec
	winStart := winEnd - bucketCount*bucketSec

	var total, blocked [bucketCount]int
	dcount, bdcount := map[string]int{}, map[string]int{}
	ccount, bccount := map[string]int{}, map[string]int{}
	cbd := map[string]map[string]*clientDomain{}
	for i := range es {
		e := &es[i]
		if e.Epoch < winStart || e.Epoch >= winEnd {
			continue
		}

		b := (e.Epoch - winStart) / bucketSec
		total[b]++
		if e.Blocked {
			blocked[b]++
		}

		if e.Host != "" {
			dcount[e.Host]++
			if e.Blocked {
				bdcount[e.Host]++
			}
		}

		ck := h.clientKey(r, e)
		if ck == "" {
			continue
		}

		ccount[ck]++
		if !e.Blocked {
			continue
		}

		bccount[ck]++
		if e.Host != "" {
			m := cbd[ck]
			if m == nil {
				m = map[string]*clientDomain{}
				cbd[ck] = m
			}

			d := m[e.Host]
			if d == nil {
				d = &clientDomain{domain: e.Host}
				m[e.Host] = d
			}

			d.count++
			d.last = max(d.last, e.Epoch)
		}
	}

	sumT, sumB := 0, 0
	for i := range total {
		sumT += total[i]
		sumB += blocked[i]
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, `{"time_units":"hours","num_dns_queries":%d,"num_blocked_filtering":%d`, sumT, sumB)
	sb.WriteString(`,"num_replaced_safebrowsing":0,"num_replaced_safesearch":0,"num_replaced_parental":0`)
	sb.WriteString(`,"avg_processing_time":0`)
	fmt.Fprintf(&sb, `,"dns_queries":[%s],"blocked_filtering":[%s]`, ints(total[:]), ints(blocked[:]))
	fmt.Fprintf(&sb, `,"top_queried_domains":[%s]`, topJSON(topN(allowedOnly(dcount, bdcount), topDomains24h)))
	fmt.Fprintf(&sb, `,"top_blocked_domains":[%s]`, topJSON(topN(bdcount, topDomains24h)))
	fmt.Fprintf(&sb, `,"top_clients":[%s]`, topJSON(topN(ccount, topClients24h)))
	fmt.Fprintf(&sb, `,"_top_clients_blocked":[%s]`, topJSON(topN(bccount, topClients24h)))
	fmt.Fprintf(&sb, `,"_top_client_names":{%s}`, labelsJSON(r))
	fmt.Fprintf(&sb, `,"_bucket_ms":%d,"_bucket_count":%d,"_window_end":%d`, bucketSec*1000, bucketCount, winEnd)
	fmt.Fprintf(&sb, `,"_unique_domains":%d,"_generated_at":%d}`, len(dcount), now)

	err = os.MkdirAll(h.conf.OutDir, 0o755)
	if err != nil {
		return err
	}

	err = writeAtomic(filepath.Join(h.conf.OutDir, file24h), []byte(sb.String()))
	if err != nil {
		return err
	}

	return writeAtomic(filepath.Join(h.conf.OutDir, fileBlockedBy), blockedByJSON(cbd, now, winStart))
}

// blockedByJSON renders the per-client blocked domains, top 40 by count.
// The scripts listed clients and equal counts in awk's hash order; this uses
// key and domain order, which is one of the orders the scripts could produce.
func blockedByJSON(cbd map[string]map[string]*clientDomain, now, winStart int64) (b []byte) {
	clean := strings.NewReplacer(`\`, "/", `"`, "")
	cks := make([]string, 0, len(cbd))
	for ck := range cbd {
		cks = append(cks, ck)
	}

	slices.Sort(cks)

	var sb strings.Builder
	fmt.Fprintf(&sb, `{"generated_at":%d,"window_start":%d,"clients":{`, now, winStart)
	for i, ck := range cks {
		ds := make([]*clientDomain, 0, len(cbd[ck]))
		for _, d := range cbd[ck] {
			ds = append(ds, d)
		}

		slices.SortFunc(ds, func(a, b *clientDomain) int {
			if c := cmp.Compare(b.count, a.count); c != 0 {
				return c
			}

			return strings.Compare(a.domain, b.domain)
		})

		if len(ds) > blockedByLimit {
			ds = ds[:blockedByLimit]
		}

		if i > 0 {
			sb.WriteByte(',')
		}

		fmt.Fprintf(&sb, `"%s":[`, clean.Replace(ck))
		for j, d := range ds {
			if j > 0 {
				sb.WriteByte(',')
			}

			fmt.Fprintf(&sb, `{"d":"%s","n":%d,"t":%d}`, clean.Replace(d.domain), d.count, d.last)
		}

		sb.WriteByte(']')
	}

	sb.WriteString("}}\n")

	return []byte(sb.String())
}

// dayAgg is the aggregate of one day.
type dayAgg struct {
	dcount, bdcount map[string]int
	ccount, bccount map[string]int
	total, blocked  int
}

// Write7d updates the per-day files and writes the 7-day history.
func (h *History) Write7d() (err error) {
	es := h.snapshot()
	r := h.readRegistry()
	dir := h.conf.OutDir
	err = os.MkdirAll(dir, 0o755)
	if err != nil {
		return err
	}

	days := map[string]*dayAgg{}
	for i := range es {
		e := &es[i]
		d := days[e.Day]
		if d == nil {
			d = &dayAgg{
				dcount: map[string]int{}, bdcount: map[string]int{},
				ccount: map[string]int{}, bccount: map[string]int{},
			}
			days[e.Day] = d
		}

		d.total++
		if e.Blocked {
			d.blocked++
		}

		if e.Host != "" {
			d.dcount[e.Host]++
			if e.Blocked {
				d.bdcount[e.Host]++
			}
		}

		if ck := h.clientKey(r, e); ck != "" {
			d.ccount[ck]++
			if e.Blocked {
				d.bccount[ck]++
			}
		}
	}

	for day, d := range days {
		err = writeDay(dir, day, d)
		if err != nil {
			return err
		}
	}

	return h.writeMerged7d(r)
}

// writeDay writes a day's files unless the saved total is higher, which
// means the log rotated part of that day away (the scripts' high-water mark).
func writeDay(dir, day string, d *dayAgg) (err error) {
	prev := 0
	if b, rerr := os.ReadFile(filepath.Join(dir, day+".total")); rerr == nil {
		prev, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}

	if d.total < prev {
		return nil
	}

	mini := fmt.Sprintf(`{"day":"%s","total":%d,"blocked":%d,"top_domains":[%s],"top_blocked":[%s],"top_clients":[%s],"top_clients_blocked":[%s]}`,
		day, d.total, d.blocked,
		topJSON(topN(allowedOnly(d.dcount, d.bdcount), topDomainsPerDay)),
		topJSON(topN(d.bdcount, topDomainsPerDay)),
		topJSON(topN(d.ccount, topClientsPerDay)),
		topJSON(topN(d.bccount, topClientsPerDay)),
	)

	err = writeAtomic(filepath.Join(dir, day+".json"), []byte(mini))
	if err != nil {
		return err
	}

	err = os.WriteFile(filepath.Join(dir, day+".total"), []byte(strconv.Itoa(d.total)+"\n"), 0o644)
	if err != nil {
		return err
	}

	names := make([]string, 0, len(d.dcount))
	for n := range d.dcount {
		names = append(names, n)
	}

	slices.Sort(names)
	content := strings.Join(names, "\n")
	if content != "" {
		content += "\n"
	}

	return os.WriteFile(filepath.Join(dir, day+".domains"), []byte(content), 0o644)
}

// miniDay is what the merge reads back from a day file.
type miniDay struct {
	tops  map[string][]counted
	total int
	block int
}

// readMini parses a day file written by writeDay or the script.
func readMini(path string) (m *miniDay, ok bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	s := string(b)
	m = &miniDay{tops: map[string][]counted{}}
	m.total = firstInt(s, `"total":`)
	m.block = firstInt(s, `"blocked":`)
	for _, f := range []string{"top_domains", "top_blocked", "top_clients", "top_clients_blocked"} {
		m.tops[f] = parseTopArray(s, f)
	}

	return m, true
}

// firstInt returns the number after the first occurrence of key, or 0.
func firstInt(s, key string) (n int) {
	i := strings.Index(s, key)
	if i < 0 {
		return 0
	}

	rest := s[i+len(key):]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}

	n, _ = strconv.Atoi(rest[:j])

	return n
}

// parseTopArray extracts the {"name":count} objects of a field like the
// script's sed and awk: from the last `"<field>":[` up to the first `]`.
func parseTopArray(s, field string) (cs []counted) {
	key := `"` + field + `":[`
	i := strings.LastIndex(s, key)
	if i < 0 {
		return nil
	}

	body := s[i+len(key):]
	j := strings.IndexByte(body, ']')
	if j < 0 {
		return nil
	}

	body = body[:j]
	body = strings.ReplaceAll(body, "},{", "}\n{")
	for obj := range strings.SplitSeq(body, "\n") {
		if !strings.HasPrefix(obj, `{"`) {
			continue
		}

		obj = obj[2:]
		q := strings.Index(obj, `":`)
		if q < 0 {
			continue
		}

		name := obj[:q]
		num := strings.TrimSuffix(obj[q+2:], "}")
		if k := strings.IndexByte(num, '}'); k >= 0 {
			num = num[:k]
		}

		c, _ := strconv.Atoi(num)
		if c > 0 {
			cs = append(cs, counted{name: name, count: c})
		}
	}

	return cs
}

// writeMerged7d builds router-dns-history.json from the day files of the last
// seven local dates and removes day files older than 30 days.
func (h *History) writeMerged7d(r *registry) (err error) {
	dir := h.conf.OutDir
	now := h.conf.Now()
	var dayList []string
	for i := keepDays - 1; i >= 0; i-- {
		dayList = append(dayList, now.Add(-24*time.Duration(i)*time.Hour).In(h.conf.Location).Format("2006-01-02"))
	}

	var totals, blocks []int
	sumT, sumB := 0, 0
	combined := map[string]map[string]int{
		"top_domains": {}, "top_blocked": {}, "top_clients": {}, "top_clients_blocked": {},
	}
	unique := map[string]struct{}{}
	for _, d := range dayList {
		t, b := 0, 0
		if m, ok := readMini(filepath.Join(dir, d+".json")); ok {
			t, b = m.total, m.block
			for f, cs := range m.tops {
				for _, c := range cs {
					combined[f][c.name] += c.count
				}
			}
		}

		totals, blocks = append(totals, t), append(blocks, b)
		sumT, sumB = sumT+t, sumB+b

		if content, rerr := os.ReadFile(filepath.Join(dir, d+".domains")); rerr == nil {
			for n := range strings.SplitSeq(string(content), "\n") {
				if n != "" {
					unique[n] = struct{}{}
				}
			}
		}
	}

	quoted := make([]string, len(dayList))
	for i, d := range dayList {
		quoted[i] = `"` + d + `"`
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, `{"time_units":"days","num_dns_queries":%d,"num_blocked_filtering":%d`, sumT, sumB)
	sb.WriteString(`,"num_replaced_safebrowsing":0,"num_replaced_safesearch":0,"num_replaced_parental":0`)
	sb.WriteString(`,"avg_processing_time":0`)
	fmt.Fprintf(&sb, `,"dns_queries":[%s],"blocked_filtering":[%s]`, ints(totals), ints(blocks))
	fmt.Fprintf(&sb, `,"top_queried_domains":[%s]`, topJSON(topN(combined["top_domains"], topDomainsFinal7d)))
	fmt.Fprintf(&sb, `,"top_blocked_domains":[%s]`, topJSON(topN(combined["top_blocked"], topDomainsFinal7d)))
	fmt.Fprintf(&sb, `,"top_clients":[%s]`, topJSON(topN(combined["top_clients"], topClientsFinal7d)))
	fmt.Fprintf(&sb, `,"_top_clients_blocked":[%s]`, topJSON(topN(combined["top_clients_blocked"], topClientsFinal7d)))
	fmt.Fprintf(&sb, `,"_top_client_names":{%s}`, labelsJSON(r))
	fmt.Fprintf(&sb, `,"_days":[%s],"_unique_domains":%d,"_generated_at":%d}`,
		strings.Join(quoted, ","), len(unique), now.Unix())

	err = writeAtomic(filepath.Join(dir, file7d), []byte(sb.String()))
	if err != nil {
		return err
	}

	gcDays(dir, now.Add(-gcKeepDays*24*time.Hour).In(h.conf.Location).Format("2006-01-02"))

	return nil
}

// gcDays removes day files dated before cutoff.
func gcDays(dir, cutoff string) {
	for _, ext := range []string{".json", ".total", ".domains"} {
		paths, _ := filepath.Glob(filepath.Join(dir, "*"+ext))
		for _, p := range paths {
			d := strings.TrimSuffix(filepath.Base(p), ext)
			if isDate(d) && d < cutoff {
				_ = os.Remove(p)
			}
		}
	}
}

// isDate returns true for YYYY-MM-DD.
func isDate(s string) (ok bool) {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}

	for i, c := range s {
		if i != 4 && i != 7 && (c < '0' || c > '9') {
			return false
		}
	}

	return true
}
