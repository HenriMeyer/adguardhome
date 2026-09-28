package iona

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/iona/listtable"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPriv is the signing key of the test tables.
var testPriv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))

const (
	gambling = "||casino.example^\n||bet.example^\n"
	ads      = "||ads.example^\n||bet.example^\n"
	tlds     = "||*.spamtld^$denyallow=good.spamtld\n@@||fritz.box^\n"
)

// buildTable returns a signed table of the three test lists.
func buildTable(t testing.TB, seq uint64, extra string) (data []byte) {
	t.Helper()

	data, _, err := listtable.Build([]listtable.Source{
		{Name: "gambling.txt", Text: []byte(gambling + extra)},
		{Name: "ads.txt", Text: []byte(ads)},
		{Name: "tlds.txt", Text: []byte(tlds)},
	}, &listtable.BuildConfig{Created: time.Now(), Key: testPriv, Sequence: seq})
	require.NoError(t, err)

	return data
}

// neighbors is a settable neighbor table.
type neighbors struct {
	mu sync.Mutex
	m  map[netip.Addr]string
	n  atomic.Int32
}

func (nb *neighbors) set(ip, mac string) {
	nb.mu.Lock()
	defer nb.mu.Unlock()

	if nb.m == nil {
		nb.m = map[netip.Addr]string{}
	}

	nb.m[netip.MustParseAddr(ip)] = mac
}

func (nb *neighbors) fetch() (m map[netip.Addr]string, err error) {
	nb.mu.Lock()
	defer nb.mu.Unlock()

	nb.n.Add(1)
	m = make(map[netip.Addr]string, len(nb.m))
	for k, v := range nb.m {
		m[k] = v
	}

	return m, nil
}

// newTestEngine returns an engine over a fresh control directory holding the
// public key and, if table is not nil, lists.tbl.
func newTestEngine(t testing.TB, table []byte) (e *Engine, dir string, nb *neighbors) {
	t.Helper()

	dir = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, KeysDir), 0o755))
	pub := testPriv.Public().(ed25519.PublicKey)
	writeFile(t, dir, filepath.Join(KeysDir, "test.pub"), base64.StdEncoding.EncodeToString(pub))
	if table != nil {
		require.NoError(t, os.WriteFile(filepath.Join(dir, TableFile), table, 0o644))
	}

	nb = &neighbors{}
	e = New(&Config{
		Logger:     slogutil.NewDiscardLogger(),
		Neighbors:  nb.fetch,
		Dir:        dir,
		StatusPath: filepath.Join(dir, "status.json"),
	})
	t.Cleanup(func() { _ = e.Close() })

	return e, dir, nb
}

func writeFile(t testing.TB, dir, name, content string) {
	t.Helper()

	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
}

func reload(t testing.TB, e *Engine) (changed bool) {
	t.Helper()

	changed, err := e.Reload(context.Background())
	require.NoError(t, err)

	return changed
}

// blocked returns the list blocking host for a client at addr, or "".
func blocked(e *Engine, addr, host string) (list string) {
	m, ok := e.Match(host, e.ClientPolicy(netip.MustParseAddr(addr)))
	if !ok {
		return ""
	}

	return m.List
}

func readStatus(t testing.TB, dir string) (s *Status) {
	t.Helper()

	b, err := os.ReadFile(filepath.Join(dir, "status.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &s))

	return s
}

func TestEngine_selectionAndDevices(t *testing.T) {
	e, dir, nb := newTestEngine(t, buildTable(t, 1, ""))
	const phone, laptop = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"
	nb.set("192.168.1.10", phone)
	nb.set("fd00::10", phone)
	nb.set("2001:db8::10", phone)
	nb.set("192.168.1.20", laptop)

	assert.True(t, reload(t, e))
	st := readStatus(t, dir)
	assert.Equal(t, []string{"gambling.txt", "ads.txt", "tlds.txt"}, st.Enabled, "empty selection = all")
	assert.Equal(t, "current", st.Table.Source)
	assert.EqualValues(t, 1, st.Generation)

	assert.Equal(t, "gambling.txt", blocked(e, "192.168.1.10", "www.casino.example"))
	assert.Equal(t, "gambling.txt", blocked(e, "192.168.1.10", "bet.example"))

	// Exclude the phone from gambling; the MAC is written in upper case to
	// check normalization.
	writeFile(t, dir, DevicesFile, "AA:BB:CC:00:00:01 gambling.txt,unknown.txt\n")
	reload(t, e)

	for _, addr := range []string{"192.168.1.10", "fd00::10", "2001:db8::10", "::ffff:192.168.1.10"} {
		assert.Equal(t, "", blocked(e, addr, "casino.example"), addr)
		assert.Equal(t, "ads.txt", blocked(e, addr, "bet.example"), "bet is in ads too: %s", addr)
	}

	assert.Equal(t, "gambling.txt", blocked(e, "192.168.1.20", "casino.example"), "other device")
	assert.Equal(t, "gambling.txt", blocked(e, "192.168.1.99", "casino.example"), "unknown device")

	// The phone gets a new address: the exclusion follows the MAC.
	nb.set("192.168.1.77", phone)
	time.Sleep(neighborMissBackoff + 100*time.Millisecond)
	assert.Equal(t, "", blocked(e, "192.168.1.77", "casino.example"))

	// Residual rules of an excluded list carry the device's exclusion tag.
	p := e.ClientPolicy(netip.MustParseAddr("192.168.1.10"))
	assert.Equal(t, []string{"iona_x_gambling"}, p.Tags)

	// Selection without gambling.
	writeFile(t, dir, SelectedFile, "ads.txt\nnope.txt, tlds.txt\n")
	assert.True(t, reload(t, e))
	st = readStatus(t, dir)
	assert.Equal(t, []string{"ads.txt", "tlds.txt"}, st.Enabled)
	assert.Equal(t, []string{"nope.txt"}, st.UnknownSelected)
	assert.Equal(t, map[string][]string{phone: {"gambling.txt", "unknown.txt"}}, st.Devices)
	assert.Equal(t, "", blocked(e, "192.168.1.20", "casino.example"))
	assert.Equal(t, "ads.txt", blocked(e, "192.168.1.20", "ads.example"))

	// Reloading unchanged files changes nothing but the generation.
	assert.False(t, reload(t, e))
	assert.EqualValues(t, 4, readStatus(t, dir).Generation)
}

func TestEngine_residual(t *testing.T) {
	e, dir, _ := newTestEngine(t, buildTable(t, 1, ""))
	reload(t, e)

	rs := e.ResidualRules()
	require.Len(t, rs, 1)
	assert.Equal(t, ListIDBase+2, rs[0].ID)
	assert.Equal(t,
		"||*.spamtld^$denyallow=good.spamtld,ctag=~iona_x_tlds\n@@||fritz.box^$ctag=~iona_x_tlds\n",
		string(rs[0].Text))

	writeFile(t, dir, SelectedFile, "ads.txt\n")
	assert.True(t, reload(t, e))
	assert.Empty(t, e.ResidualRules())
}

func TestWithExclusionTag(t *testing.T) {
	testCases := map[string]string{
		"||a^":                         "||a^$ctag=~t",
		"||a^$important":               "||a^$important,ctag=~t",
		"||a^$ctag=~device_tv":         "||a^$ctag=~t",
		"||a^$important,ctag=~os_ios":  "||a^$important,ctag=~t",
		"||a^$denyallow=x.a|y.a":       "||a^$denyallow=x.a|y.a,ctag=~t",
		"@@||a^":                       "@@||a^$ctag=~t",
		"||a^$ctag=~x,important":       "||a^$ctag=~x,important,ctag=~t",
		"/regex$/":                     "/regex$/$ctag=~t",
		"@@/re$/":                      "@@/re$/$ctag=~t",
		"/re/$important":               "/re/$important,ctag=~t",
		"||a^$client=192.168.1.1|~y":   "||a^$client=192.168.1.1|~y,ctag=~t",
		"||a^$denyallow=ctag.a":        "||a^$denyallow=ctag.a,ctag=~t",
		"||a^$dnsrewrite=NOERROR;A;1.": "||a^$dnsrewrite=NOERROR;A;1.,ctag=~t",
	}

	for in, want := range testCases {
		assert.Equal(t, want, withExclusionTag(in, "t"), in)
	}

	assert.Equal(t, "iona_x_native_oppo_realme", ExclusionTag("native.oppo-realme.txt"))
	assert.Equal(t, "iona_x_pro_plus", ExclusionTag("PRO.plus.txt"))
}

func TestEngine_staging(t *testing.T) {
	e, dir, _ := newTestEngine(t, buildTable(t, 5, ""))
	reload(t, e)
	assert.Equal(t, "", blocked(e, "10.0.0.1", "new.example"))

	stage := func(data []byte) {
		t.Helper()

		require.NoError(t, os.WriteFile(filepath.Join(dir, NewTableFile), data, 0o644))
	}

	t.Run("promote_raw", func(t *testing.T) {
		stage(buildTable(t, 6, "||new.example^\n"))
		assert.True(t, reload(t, e))
		assert.Equal(t, "gambling.txt", blocked(e, "10.0.0.1", "new.example"))
		assert.NoFileExists(t, filepath.Join(dir, NewTableFile))
		assert.FileExists(t, filepath.Join(dir, PrevTableFile))
		assert.EqualValues(t, 6, readStatus(t, dir).Table.Sequence)
		assert.Empty(t, readStatus(t, dir).Errors)
	})

	t.Run("promote_transport", func(t *testing.T) {
		pub := testPriv.Public().(ed25519.PublicKey)
		tr, err := listtable.EncodeTransport(buildTable(t, 7, "||newer.example^\n"),
			&listtable.OpenConfig{Keys: []ed25519.PublicKey{pub}})
		require.NoError(t, err)

		stage(tr)
		assert.True(t, reload(t, e))
		assert.Equal(t, "gambling.txt", blocked(e, "10.0.0.1", "newer.example"))
		assert.EqualValues(t, 7, readStatus(t, dir).Table.Sequence)
	})

	t.Run("reject_bad_signature", func(t *testing.T) {
		bad := buildTable(t, 8, "||evil.example^\n")
		bad[len(bad)-200] ^= 0xff
		stage(bad)

		assert.False(t, reload(t, e))
		assert.Equal(t, "", blocked(e, "10.0.0.1", "evil.example"))
		assert.Equal(t, "gambling.txt", blocked(e, "10.0.0.1", "newer.example"), "old table stays")
		assert.FileExists(t, filepath.Join(dir, RejectedTableFile))
		st := readStatus(t, dir)
		assert.EqualValues(t, 7, st.Table.Sequence)
		require.Len(t, st.Errors, 1)
		assert.Contains(t, st.Errors[0], "signature")
	})

	t.Run("reject_other_key", func(t *testing.T) {
		other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
		data, _, err := listtable.Build([]listtable.Source{{Name: "x.txt", Text: []byte("||x.example^")}},
			&listtable.BuildConfig{Key: other, Sequence: 99})
		require.NoError(t, err)

		stage(data)
		reload(t, e)
		assert.EqualValues(t, 7, readStatus(t, dir).Table.Sequence)
	})

	t.Run("reject_downgrade", func(t *testing.T) {
		stage(buildTable(t, 3, "||old.example^\n"))
		reload(t, e)
		assert.Equal(t, "", blocked(e, "10.0.0.1", "old.example"))
		st := readStatus(t, dir)
		require.Len(t, st.Errors, 1)
		assert.Contains(t, st.Errors[0], "older than the active")
	})

	t.Run("reject_wrong_version", func(t *testing.T) {
		data := buildTable(t, 10, "")
		binary.LittleEndian.PutUint32(data[8:], 2)
		stage(data)
		reload(t, e)
		assert.EqualValues(t, 7, readStatus(t, dir).Table.Sequence)
		assert.Contains(t, readStatus(t, dir).Errors[0], "format version 2")
	})

	t.Run("reject_garbage_and_gzip_garbage", func(t *testing.T) {
		stage([]byte("<html>502 Bad Gateway</html>"))
		reload(t, e)
		stage([]byte{0x1f, 0x8b, 0x08, 0, 0, 0})
		reload(t, e)
		assert.EqualValues(t, 7, readStatus(t, dir).Table.Sequence)
		assert.Equal(t, "gambling.txt", blocked(e, "10.0.0.1", "casino.example"))
	})
}

func TestEngine_startupFallback(t *testing.T) {
	good := buildTable(t, 2, "")

	t.Run("broken_current_uses_prev", func(t *testing.T) {
		broken := bytes.Clone(good)
		broken[100] ^= 1
		e, dir, _ := newTestEngine(t, broken)
		require.NoError(t, os.WriteFile(filepath.Join(dir, PrevTableFile), good, 0o644))

		reload(t, e)
		st := readStatus(t, dir)
		assert.Equal(t, "prev", st.Table.Source)
		assert.True(t, st.Table.Loaded)
		assert.Equal(t, "gambling.txt", blocked(e, "10.0.0.1", "casino.example"))
	})

	t.Run("first_start_with_staged_only", func(t *testing.T) {
		e, dir, _ := newTestEngine(t, nil)
		require.NoError(t, os.WriteFile(filepath.Join(dir, NewTableFile), good, 0o644))
		reload(t, e)
		st := readStatus(t, dir)
		assert.True(t, st.Table.Loaded)
		assert.Empty(t, st.Errors, "no stale errors from the empty disk")
	})

	t.Run("nothing_usable", func(t *testing.T) {
		e, dir, _ := newTestEngine(t, nil)
		reload(t, e)
		st := readStatus(t, dir)
		assert.False(t, st.Table.Loaded)
		assert.Equal(t, "none", st.Table.Source)
		assert.Contains(t, st.Errors, "no usable list table")
		assert.Equal(t, "", blocked(e, "10.0.0.1", "casino.example"))
	})

	t.Run("no_keys", func(t *testing.T) {
		e, dir, _ := newTestEngine(t, good)
		require.NoError(t, os.RemoveAll(filepath.Join(dir, KeysDir)))
		reload(t, e)
		st := readStatus(t, dir)
		assert.False(t, st.Table.Loaded)
		assert.Contains(t, strings.Join(st.Errors, "|"), "no trusted keys")
	})

	t.Run("min_entries", func(t *testing.T) {
		e, dir, _ := newTestEngine(t, good)
		e.conf.MinEntries = 1000
		reload(t, e)
		assert.False(t, readStatus(t, dir).Table.Loaded)
	})
}

func TestEngine_badControlFiles(t *testing.T) {
	e, dir, _ := newTestEngine(t, buildTable(t, 1, ""))
	writeFile(t, dir, DevicesFile, "not-a-mac gambling.txt\naa:bb:cc:dd:ee:ff\n11:22:33:44:55:66 ads.txt\n")
	reload(t, e)

	st := readStatus(t, dir)
	assert.Len(t, st.Devices, 1, "valid lines still apply")
	assert.Len(t, st.Errors, 1)
	assert.Contains(t, st.Errors[0], "line 1: bad mac")
	assert.Contains(t, st.Errors[0], "line 2")
}

// TestEngine_hotSwap reloads new tables while queries run, under -race.
func TestEngine_hotSwap(t *testing.T) {
	e, dir, nb := newTestEngine(t, buildTable(t, 1, ""))
	nb.set("192.168.1.10", "aa:bb:cc:00:00:01")
	writeFile(t, dir, DevicesFile, "aa:bb:cc:00:00:01 ads.txt\n")
	reload(t, e)

	var wg sync.WaitGroup
	var stop atomic.Bool
	var queries, wrong atomic.Int64
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for !stop.Load() {
				// casino.example is in gambling in every table version and
				// the device isn't excluded from it.
				if blocked(e, "192.168.1.10", "casino.example") != "gambling.txt" {
					wrong.Add(1)
				}

				if blocked(e, "192.168.1.10", "ads.example") != "" {
					wrong.Add(1)
				}

				queries.Add(1)
			}
		}()
	}

	for seq := uint64(2); seq < 40; seq++ {
		extra := fmt.Sprintf("||v%d.example^\n", seq)
		require.NoError(t, os.WriteFile(filepath.Join(dir, NewTableFile), buildTable(t, seq, extra), 0o644))
		reload(t, e)
	}

	stop.Store(true)
	wg.Wait()

	assert.Zero(t, wrong.Load())
	assert.Positive(t, queries.Load())
	assert.EqualValues(t, 39, readStatus(t, dir).Table.Sequence)
}

func TestNeighborCache_missRefresh(t *testing.T) {
	nb := &neighbors{}
	c := newNeighborCache(nb.fetch)
	defer c.stop()

	_, ok := c.MAC(netip.MustParseAddr("10.0.0.1"))
	assert.False(t, ok)

	nb.set("10.0.0.1", "02:00:00:00:00:01")

	// Within the backoff a miss doesn't hit the kernel again.
	_, ok = c.MAC(netip.MustParseAddr("10.0.0.1"))
	assert.False(t, ok)
	assert.EqualValues(t, 1, nb.n.Load())

	time.Sleep(neighborMissBackoff + 50*time.Millisecond)
	mac, ok := c.MAC(netip.MustParseAddr("10.0.0.1"))
	assert.True(t, ok)
	assert.Equal(t, "02:00:00:00:00:01", mac)
}

func TestReadDNSControl(t *testing.T) {
	dir := t.TempDir()
	c, err := ReadDNSControl(dir)
	require.NoError(t, err)
	assert.Equal(t, &DNSControl{}, c, "missing files change nothing")

	writeFile(t, dir, UpstreamsFile, "127.0.0.1:5335\n# comment\n")
	writeFile(t, dir, FallbacksFile, "")
	writeFile(t, dir, BlockingFile, "custom_ip 192.168.1.1 fd00::1\n")
	writeFile(t, dir, RewritesFile, "Iona.Router 192.168.1.1\nnas.lan 192.168.1.50\n")

	c, err = ReadDNSControl(dir)
	require.NoError(t, err)
	assert.Equal(t, []string{"127.0.0.1:5335"}, c.Upstreams)
	assert.Equal(t, []string{}, c.Fallbacks)
	assert.Equal(t, &Blocking{
		Mode: "custom_ip",
		IPv4: netip.MustParseAddr("192.168.1.1"),
		IPv6: netip.MustParseAddr("fd00::1"),
	}, c.Blocking)
	assert.Equal(t, [][2]string{{"iona.router", "192.168.1.1"}, {"nas.lan", "192.168.1.50"}}, c.Rewrites)

	for _, bad := range []string{"custom_ip", "custom_ip ::1", "nxdomain 1.2.3.4", "weird", "custom_ip 1.2.3.4 1.2.3.4"} {
		writeFile(t, dir, BlockingFile, bad)
		_, err = ReadDNSControl(dir)
		assert.Error(t, err, bad)
	}

	writeFile(t, dir, BlockingFile, "custom_ip 192.168.1.1\n")
	writeFile(t, dir, RewritesFile, "just-a-domain\n")
	c, err = ReadDNSControl(dir)
	assert.ErrorContains(t, err, "line 1")
	assert.Equal(t, netip.IPv6Unspecified(), c.Blocking.IPv6)
}
