package history

// DEBUG, remove before release: the complete per-day query counts.  The day
// files keep only the top 80 domains with counts and the bare names in
// <day>.domains; this file keeps every domain every client asked for, so a
// question like "how often did this phone ask for www.google-analytics.com"
// has an exact answer.  It is a full browsing history per device, which is
// why it must not ship.  Removing it: delete this file, the counts field of
// dayAgg with its two lines in Write7d, the writeDebugCounts call in
// writeDay, and debugCountsExt in gcDays.

import (
	"cmp"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// debugCountsExt is the extension of the per-day count file.
const debugCountsExt = ".counts.tsv"

// clientHost is a client key and a question host.
type clientHost struct {
	client string
	host   string
}

// hostCount is how often a client asked for a host and how often that was
// blocked.
type hostCount struct {
	total   int
	blocked int
}

// addDebugCount counts e under its client key ck, "-" if it has none.
func addDebugCount(m map[clientHost]*hostCount, ck string, e *Entry) {
	k := clientHost{client: cmp.Or(ck, "-"), host: e.Host}
	c := m[k]
	if c == nil {
		c = &hostCount{}
		m[k] = c
	}

	c.total++
	if e.Blocked {
		c.blocked++
	}
}

// writeDebugCounts writes <day>.counts.tsv: one line per client and host,
// "client<TAB>label<TAB>host<TAB>total<TAB>blocked", clients by key, hosts by
// total descending, then by name.
func writeDebugCounts(dir, day string, m map[clientHost]*hostCount, r *registry) (err error) {
	labels := make(map[string]string, len(r.labels))
	for _, l := range r.labels {
		labels[l[0]] = l[1]
	}

	keys := make([]clientHost, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	slices.SortFunc(keys, func(a, b clientHost) int {
		if c := strings.Compare(a.client, b.client); c != 0 {
			return c
		}

		if c := cmp.Compare(m[b].total, m[a].total); c != 0 {
			return c
		}

		return strings.Compare(a.host, b.host)
	})

	clean := strings.NewReplacer("\t", " ", "\n", " ")
	var sb strings.Builder
	sb.WriteString("# client\tlabel\thost\ttotal\tblocked\n")
	for _, k := range keys {
		c := m[k]
		fmt.Fprintf(&sb, "%s\t%s\t%s\t%d\t%d\n",
			clean.Replace(k.client), clean.Replace(labels[k.client]), clean.Replace(k.host), c.total, c.blocked)
	}

	return writeAtomic(filepath.Join(dir, day+debugCountsExt), []byte(sb.String()))
}
