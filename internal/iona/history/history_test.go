package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTopN_busyboxOrder(t *testing.T) {
	// busybox sort -t<TAB> -k1,1 -nr orders "3\tb 3\tab 3\ta 3\tB" as
	// b > ab > a > B (measured in the router VM).
	got := topN(map[string]int{"b": 3, "a": 3, "c": 5, "ab": 3, "z": 10, "B": 3}, 5)
	var names []string
	for _, c := range got {
		names = append(names, c.name)
	}

	assert.Equal(t, []string{"z", "c", "b", "ab", "a"}, names)
	assert.Equal(t, `{"z":10},{"c":5}`, topJSON(got[:2]))
}

func TestParseTopArray(t *testing.T) {
	s := `{"day":"2026-09-26","total":7,"blocked":3,"top_domains":[{"a.com":4},{"b.com":1}],` +
		`"top_blocked":[{"x.com":3}],"top_clients":[{"mac:aa:bb":5},{"lb:router":2}],"top_clients_blocked":[]}`
	assert.Equal(t, []counted{{"a.com", 4}, {"b.com", 1}}, parseTopArray(s, "top_domains"))
	assert.Equal(t, []counted{{"mac:aa:bb", 5}, {"lb:router", 2}}, parseTopArray(s, "top_clients"))
	assert.Empty(t, parseTopArray(s, "top_clients_blocked"))
	assert.Equal(t, 7, firstInt(s, `"total":`))
	assert.Equal(t, 3, firstInt(s, `"blocked":`))
}

func TestEntryFromLog(t *testing.T) {
	cest := time.FixedZone("CEST", 2*3600)
	e := EntryFromLog(time.Date(2026, 9, 26, 23, 30, 5, 999, cest), "Ads.Example", "192.168.1.5", "", false, 3, 0)
	assert.Equal(t, "ads.example", e.Host)
	assert.Equal(t, "2026-09-26", e.Day, "date of the wall clock as written")
	assert.Equal(t, time.Date(2026, 9, 26, 23, 30, 5, 0, time.UTC).Unix(), e.Epoch, "wall clock read as UTC")
	assert.True(t, e.Blocked, "reason 3")
	assert.False(t, EntryFromLog(time.Now(), "a", "", "", false, 9, 0).Blocked, "rewrites are not blocks")
	assert.True(t, EntryFromLog(time.Now(), "a", "", "", true, 0, 0).Blocked)
}

// newTest returns a history over temporary directories at a fixed time.
func newTest(t *testing.T, now time.Time) (h *History, out string) {
	t.Helper()

	out = t.TempDir()
	h = New(&Config{
		Logger:      slogutil.NewDiscardLogger(),
		Now:         func() time.Time { return now },
		OutDir:      out,
		RegistryDir: out,
		RouterIP:    "192.168.1.1",
		Location:    time.FixedZone("CEST", 2*3600),
	})

	return h, out
}

func readJSON(t *testing.T, path string) (m map[string]any) {
	t.Helper()

	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &m))

	return m
}

func TestWrite24h(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 7, 0, 0, time.UTC)
	h, out := newTest(t, now)
	require.NoError(t, os.WriteFile(filepath.Join(out, "snap-ip2key.tsv"),
		[]byte("192.168.1.10\tmac:aa:bb:cc:00:00:10\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(out, "snap-mac2name.tsv"),
		[]byte("mac:aa:bb:cc:00:00:10\tPhone \"A\"\n"), 0o644))

	at := func(d time.Duration) time.Time { return now.Add(-d) }
	add := func(ts time.Time, host, ip, cid string, blocked bool) {
		h.Add(EntryFromLog(ts, host, ip, cid, blocked, 0, 0))
	}

	add(at(time.Minute), "ads.example", "192.168.1.10", "", true)
	add(at(time.Minute), "ads.example", "192.168.1.10", "", true)
	add(at(2*time.Minute), "good.example", "192.168.1.10", "", false)
	add(at(3*time.Minute), "good.example", "192.168.1.1", "", false)
	add(at(3*time.Minute), "x.example", "::1", "", false)
	add(at(4*time.Minute), "y.example", "192.168.1.99", "", true)
	add(at(5*time.Minute), "z.example", "", "phone", false)
	add(at(23*time.Hour), "old.example", "192.168.1.10", "", false)
	add(at(25*time.Hour), "gone.example", "192.168.1.10", "", false)
	add(at(50*time.Hour), "pruned.example", "192.168.1.10", "", false)

	require.NoError(t, h.Write24h())
	m := readJSON(t, filepath.Join(out, file24h))

	winEnd := (now.Unix()/900)*900 + 900
	assert.EqualValues(t, winEnd, m["_window_end"])
	assert.EqualValues(t, 8, m["num_dns_queries"], "entries older than 24h excluded")
	assert.EqualValues(t, 3, m["num_blocked_filtering"])
	dq := m["dns_queries"].([]any)
	require.Len(t, dq, 96)
	assert.EqualValues(t, 7, dq[95], "current bucket included")
	assert.EqualValues(t, 1, dq[3], "23h ago → bucket 3")
	assert.Equal(t, []any{map[string]any{"good.example": 2.0}, map[string]any{"z.example": 1.0},
		map[string]any{"x.example": 1.0}, map[string]any{"old.example": 1.0}}, m["top_queried_domains"])
	assert.Equal(t, []any{map[string]any{"ads.example": 2.0}, map[string]any{"y.example": 1.0}},
		m["top_blocked_domains"])
	assert.Equal(t, []any{
		map[string]any{"mac:aa:bb:cc:00:00:10": 4.0}, map[string]any{"lb:router": 2.0},
		map[string]any{"@phone": 1.0}, map[string]any{"192.168.1.99": 1.0},
	}, m["top_clients"])
	assert.Equal(t, map[string]any{"lb:router": "Router", "mac:aa:bb:cc:00:00:10": `Phone "A"`},
		m["_top_client_names"])
	assert.EqualValues(t, 6, m["_unique_domains"])
	assert.NotContains(t, m, "_blocked_lists", "no breakdown without Config.ListName")
	assert.Equal(t, 9, h.Len(), "50h-old entry pruned, although added last")

	bb := readJSON(t, filepath.Join(out, fileBlockedBy))
	cl := bb["clients"].(map[string]any)
	assert.Equal(t, []any{map[string]any{"d": "ads.example", "n": 2.0, "t": float64(at(time.Minute).Unix())}},
		cl["mac:aa:bb:cc:00:00:10"])
	assert.Contains(t, cl, "192.168.1.99")
}

func TestWrite7d_highWaterMark(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	h, out := newTest(t, now)

	for range 5 {
		h.Add(EntryFromLog(now.Add(-time.Hour), "a.example", "10.0.0.1", "", false, 0, 0))
	}

	h.Add(EntryFromLog(now.Add(-26*time.Hour), "b.example", "10.0.0.1", "", true, 0, 0))
	require.NoError(t, h.Write7d())

	m := readJSON(t, filepath.Join(out, file7d))
	assert.Equal(t, []any{"2026-09-20", "2026-09-21", "2026-09-22", "2026-09-23", "2026-09-24", "2026-09-25", "2026-09-26"},
		m["_days"])
	assert.Equal(t, []any{0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 5.0}, m["dns_queries"])
	assert.EqualValues(t, 2, m["_unique_domains"])

	// A saved day with more queries than the log still holds is kept.
	require.NoError(t, os.WriteFile(filepath.Join(out, "2026-09-26.total"), []byte("100\n"), 0o644))
	day := `{"day":"2026-09-26","total":100,"blocked":9,"top_domains":[{"kept.example":100}],"top_blocked":[],"top_clients":[],"top_clients_blocked":[]}`
	require.NoError(t, os.WriteFile(filepath.Join(out, "2026-09-26.json"), []byte(day), 0o644))
	require.NoError(t, h.Write7d())
	m = readJSON(t, filepath.Join(out, file7d))
	assert.Equal(t, []any{0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 100.0}, m["dns_queries"])
	assert.Equal(t, []any{map[string]any{"kept.example": 100.0}, map[string]any{"b.example": 0.0}}[:1],
		m["top_queried_domains"].([]any)[:1])

	// Day files older than 30 days are removed, others kept.
	for _, d := range []string{"2026-08-01", "2026-09-01"} {
		require.NoError(t, os.WriteFile(filepath.Join(out, d+".json"), []byte("{}"), 0o644))
	}

	require.NoError(t, h.Write7d())
	assert.NoFileExists(t, filepath.Join(out, "2026-08-01.json"))
	assert.FileExists(t, filepath.Join(out, "2026-09-01.json"))
	assert.FileExists(t, filepath.Join(out, file7d))
}

func TestLoad(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	h, out := newTest(t, now)
	qdir := t.TempDir()
	h.SetQueryLogDir(qdir)
	lines := []string{
		`{"T":"2026-09-26T11:00:00.123Z","QH":"A.example","IP":"192.168.1.5","Result":{"IsFiltered":true,"Reason":3}}`,
		`{"T":"2026-09-26T11:01:00Z","QH":"b.example","IP":"192.168.1.5","CID":"x","Result":{}}`,
		`not json`,
		`{"T":"short"}`,
	}
	require.NoError(t, os.WriteFile(filepath.Join(qdir, "querylog.json"), []byte(strings.Join(lines, "\n")), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(qdir, "querylog.json.1"),
		[]byte(`{"T":"2026-09-25T20:00:00Z","QH":"c.example","IP":"192.168.1.6","Result":{"Reason":0}}`+"\n"), 0o644))

	n, err := h.Load()
	require.NoError(t, err)
	assert.Equal(t, 3, n)

	require.NoError(t, h.Write24h())
	m := readJSON(t, filepath.Join(out, file24h))
	assert.EqualValues(t, 3, m["num_dns_queries"])
	assert.EqualValues(t, 1, m["num_blocked_filtering"])
	assert.Equal(t, []any{map[string]any{"c.example": 1.0}, map[string]any{"b.example": 1.0}},
		m["top_queried_domains"])
}

func TestBlockedByList(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	h, out := newTest(t, now)
	names := map[int64]string{1_000_000: "gambling.txt", 1_000_003: "pro.plus.txt"}
	h.conf.ListName = func(id int64) string { return names[id] }

	add := func(d time.Duration, host string, blocked bool, id int64) {
		h.Add(EntryFromLog(now.Add(-d), host, "192.168.1.5", "", blocked, 0, id))
	}

	add(time.Minute, "casino.example", true, 1_000_000)
	add(2*time.Minute, "casino.example", true, 1_000_000)
	add(time.Minute, "ads.example", true, 1_000_003)
	add(time.Minute, "ads.example", true, 1_000_003)
	add(time.Minute, "track.example", true, 1_000_003)
	add(time.Minute, "hosts.example", true, 0)
	add(time.Minute, "unknown.example", true, 42)
	add(time.Minute, "casino.example", false, 1_000_000)
	add(26*time.Hour, "old-casino.example", true, 1_000_000)

	require.NoError(t, h.Write24h())
	m := readJSON(t, filepath.Join(out, file24h))
	assert.Equal(t, []any{
		map[string]any{"pro.plus.txt": 3.0}, map[string]any{"gambling.txt": 2.0}, map[string]any{"_other": 2.0},
	}, m["_blocked_lists"], "allowed entries don't count, unknown IDs are _other")
	assert.Equal(t, map[string]any{
		"_other":       []any{map[string]any{"unknown.example": 1.0}, map[string]any{"hosts.example": 1.0}},
		"gambling.txt": []any{map[string]any{"casino.example": 2.0}},
		"pro.plus.txt": []any{map[string]any{"ads.example": 2.0}, map[string]any{"track.example": 1.0}},
	}, m["_blocked_list_domains"])

	require.NoError(t, h.Write7d())
	day, err := os.ReadFile(filepath.Join(out, "2026-09-26.json"))
	require.NoError(t, err)
	assert.Contains(t, string(day), `"top_clients_blocked":[{"192.168.1.5":7}],"blocked_lists":[`,
		"list fields come after the scripts' fields")

	// A day the scripts wrote has no list fields; the merge adds nothing for it.
	script := `{"day":"2026-09-24","total":4,"blocked":4,"top_domains":[],"top_blocked":[{"x.example":4}],"top_clients":[],"top_clients_blocked":[]}`
	require.NoError(t, os.WriteFile(filepath.Join(out, "2026-09-24.json"), []byte(script), 0o644))
	require.NoError(t, h.Write7d())
	m = readJSON(t, filepath.Join(out, file7d))
	assert.Equal(t, []any{
		map[string]any{"pro.plus.txt": 3.0}, map[string]any{"gambling.txt": 3.0}, map[string]any{"_other": 2.0},
	}, m["_blocked_lists"], "the 26h-old block counts on its own day")
	assert.Equal(t, []any{map[string]any{"casino.example": 2.0}, map[string]any{"old-casino.example": 1.0}},
		m["_blocked_list_domains"].(map[string]any)["gambling.txt"])
	assert.EqualValues(t, 12, m["num_blocked_filtering"])
}

func TestLoad_listID(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	h, out := newTest(t, now)
	h.conf.ListName = func(id int64) string { return map[int64]string{1_000_022: "native.apple.txt"}[id] }
	qdir := t.TempDir()
	h.SetQueryLogDir(qdir)
	line := `{"T":"2026-09-26T11:00:00Z","QH":"a.apple","IP":"192.168.1.5",` +
		`"Result":{"Rules":[{"Text":"||a.apple^","FilterListID":1000022}],"Reason":3,"IsFiltered":true}}`
	require.NoError(t, os.WriteFile(filepath.Join(qdir, "querylog.json"), []byte(line+"\n"), 0o644))

	_, err := h.Load()
	require.NoError(t, err)
	require.NoError(t, h.Write24h())
	m := readJSON(t, filepath.Join(out, file24h))
	assert.Equal(t, []any{map[string]any{"native.apple.txt": 1.0}}, m["_blocked_lists"])
}
