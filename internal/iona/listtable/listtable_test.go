package listtable

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// updateVectors rewrites testdata/vectors.json from this implementation.
var updateVectors = flag.Bool("update-vectors", false, "rewrite testdata/vectors.json")

// vector is one normalization and hash test vector.
type vector struct {
	Input string `json:"input"`
	Norm  string `json:"norm"`
	Hash  string `json:"hash"`
	OK    bool   `json:"ok"`
}

var vectorInputs = []string{
	"example.com", "EXAMPLE.COM", "example.com.", "sub.example.com", "a", "com",
	"xn--mnchen-3ya.de", "münchen.de", "MÜNCHEN.de", "_dmarc.example.com",
	"ads-1.tracker.example.co.uk", "", ".", "a..b", ".example.com", "exa mple.com",
	"exa*mple.com", strings.Repeat("a", 63) + ".com", strings.Repeat("a", 64) + ".com",
	"1.2.3.4", "例え.jp", "straße.de",
}

func TestVectors(t *testing.T) {
	var got []vector
	for _, in := range vectorInputs {
		norm, ok := NormalizeDomain(in)
		v := vector{Input: in, Norm: norm, OK: ok}
		if ok {
			v.Hash = fmt.Sprintf("%016x", Hash(norm))
		}

		got = append(got, v)
	}

	path := filepath.Join("testdata", "vectors.json")
	if *updateVectors {
		b, err := json.MarshalIndent(got, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, append(b, '\n'), 0o644))
	}

	b, err := os.ReadFile(path)
	require.NoError(t, err)

	var want []vector
	require.NoError(t, json.Unmarshal(b, &want))
	assert.Equal(t, want, got)
}

func TestHash_known(t *testing.T) {
	// Pinned independently of the vectors file so that a regenerated file
	// can't silently change the algorithm.
	// Computed independently in Python.
	assert.Equal(t, uint64(0x9591d6421994d599), Hash("example.com"))
}

// testKey returns a deterministic key pair.
func testKey(t testing.TB) (pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()

	priv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

	return priv.Public().(ed25519.PublicKey), priv
}

// build builds a table from name/text pairs.
func build(t testing.TB, seq uint64, lists ...string) (data []byte, st *BuildStats) {
	t.Helper()

	_, priv := testKey(t)
	var srcs []Source
	for i := 0; i < len(lists); i += 2 {
		srcs = append(srcs, Source{Name: lists[i], Text: []byte(lists[i+1])})
	}

	data, st, err := Build(srcs, &BuildConfig{Created: time.Unix(1700000000, 0), Key: priv, Sequence: seq})
	require.NoError(t, err)

	return data, st
}

// mustParse parses data with the test key.
func mustParse(t testing.TB, data []byte) (tbl *Table) {
	t.Helper()

	pub, _ := testKey(t)
	tbl, err := Parse(data, &OpenConfig{Keys: []ed25519.PublicKey{pub}})
	require.NoError(t, err)

	return tbl
}

const (
	listA = "! Title: A\n||ads.example^\n||tracker.test^$ctag=~device_tv\n" +
		"||both.example^\n||*.wild^\n@@||allowed.ads.example^\n||UPPER.Example^\n" +
		"||trailing.example.^\n||.leading.example^\n||münchen.de^\n||opt.example^$important\n" +
		"||tld^$denyallow=ok.tld\n\n# comment\n[Adblock Plus]\n"
	listB = "||both.example^\n||b-only.example^\n||deep.sub.b.example^\n"
)

func TestBuild_parseAndMatch(t *testing.T) {
	data, st := build(t, 1, "a.txt", listA, "b.txt", listB)
	tbl := mustParse(t, data)

	assert.Equal(t, 1, st.Converted)
	assert.Equal(t, 5+3, st.TableRules)
	assert.Equal(t, 6, st.Residual)
	assert.Equal(t, 7, tbl.Entries())

	lists := tbl.Lists()
	require.Len(t, lists, 2)
	assert.Equal(t, []string{
		"||*.wild^", "@@||allowed.ads.example^", "||trailing.example.^",
		"||.leading.example^", "||opt.example^$important", "||tld^$denyallow=ok.tld",
	}, lists[0].Residual)

	a, b := uint64(1), uint64(2)
	testCases := []struct {
		host    string
		mask    uint64
		wantBit int
		wantVia string
		wantOK  bool
	}{
		{"ads.example", a | b, 0, "ads.example", true},
		{"x.y.ads.example", a | b, 0, "ads.example", true},
		{"example", a | b, 0, "", false},
		{"notads.example", a | b, 0, "", false},
		{"tracker.test", a, 0, "tracker.test", true},
		{"both.example", b, 1, "both.example", true},
		{"both.example", a | b, 0, "both.example", true},
		{"b-only.example", a, 0, "", false},
		{"deep.sub.b.example", b, 1, "deep.sub.b.example", true},
		{"sub.b.example", b, 0, "", false},
		{"upper.example", a, 0, "upper.example", true},
		{"xn--mnchen-3ya.de", a, 0, "xn--mnchen-3ya.de", true},
		{"ads.example", 0, 0, "", false},
		{"", a, 0, "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.host, func(t *testing.T) {
			bit, via, ok := tbl.Match(tc.host, tc.mask)
			assert.Equal(t, tc.wantOK, ok)
			if ok {
				assert.Equal(t, tc.wantBit, bit)
				assert.Equal(t, tc.wantVia, via)
			}
		})
	}

	assert.Equal(t, a|b, tbl.Lookup("BOTH.example."))

	mask, unknown := tbl.Mask([]string{"b.txt", "nope.txt"})
	assert.Equal(t, b, mask)
	assert.Equal(t, []string{"nope.txt"}, unknown)
	assert.Equal(t, a|b, tbl.AllMask())
}

func TestParse_rejects(t *testing.T) {
	data, _ := build(t, 5, "a.txt", listA, "b.txt", listB)
	pub, _ := testKey(t)
	otherPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	mutate := func(f func(d []byte) []byte) []byte {
		return f(bytes.Clone(data))
	}

	testCases := []struct {
		name    string
		data    []byte
		keys    []ed25519.PublicKey
		min     int
		wantErr string
	}{{
		name:    "wrong_key",
		data:    data,
		keys:    []ed25519.PublicKey{otherPub},
		wantErr: ErrSignature.Error(),
	}, {
		name:    "no_keys",
		data:    data,
		wantErr: ErrSignature.Error(),
	}, {
		name:    "flipped_hash_bit",
		data:    mutate(func(d []byte) []byte { d[len(d)-100] ^= 1; return d }),
		keys:    []ed25519.PublicKey{pub},
		wantErr: ErrSignature.Error(),
	}, {
		name:    "flipped_meta",
		data:    mutate(func(d []byte) []byte { d[headerSize+3] ^= 1; return d }),
		keys:    []ed25519.PublicKey{pub},
		wantErr: ErrSignature.Error(),
	}, {
		name: "version",
		data: mutate(func(d []byte) []byte {
			binary.LittleEndian.PutUint32(d[8:], 2)
			return d
		}),
		keys:    []ed25519.PublicKey{pub},
		wantErr: "format version 2, want 1",
	}, {
		name: "hash_algo",
		data: mutate(func(d []byte) []byte {
			binary.LittleEndian.PutUint32(d[12:], 9)
			return d
		}),
		keys:    []ed25519.PublicKey{pub},
		wantErr: "unknown hash algorithm 9",
	}, {
		name:    "truncated",
		data:    data[:len(data)-1],
		keys:    []ed25519.PublicKey{pub},
		wantErr: "file size",
	}, {
		name:    "empty",
		data:    nil,
		keys:    []ed25519.PublicKey{pub},
		wantErr: "not a table file",
	}, {
		name:    "garbage",
		data:    bytes.Repeat([]byte{0xAB}, 4096),
		keys:    []ed25519.PublicKey{pub},
		wantErr: "not a table file",
	}, {
		name:    "too_few_entries",
		data:    data,
		keys:    []ed25519.PublicKey{pub},
		min:     100,
		wantErr: "fewer than the required 100",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, perr := Parse(tc.data, &OpenConfig{Keys: tc.keys, MinEntries: tc.min})
			require.Error(t, perr)
			assert.Contains(t, perr.Error(), tc.wantErr)
		})
	}
}

func TestBuild_limits(t *testing.T) {
	_, priv := testKey(t)
	c := &BuildConfig{Key: priv}

	var srcs []Source
	for i := range MaxLists + 1 {
		srcs = append(srcs, Source{Name: fmt.Sprintf("l%d.txt", i), Text: []byte("||x.example^")})
	}

	_, _, err := Build(srcs, c)
	assert.ErrorContains(t, err, "out of range")

	_, _, err = Build(srcs[:MaxLists], c)
	assert.NoError(t, err)

	_, _, err = Build([]Source{{Name: "a"}, {Name: "a"}}, c)
	assert.ErrorContains(t, err, "duplicate name")

	_, _, err = Build(srcs[:1], &BuildConfig{})
	assert.ErrorContains(t, err, "invalid signing key")
}

// TestBuild_wideCategories covers more than 256 list combinations, which
// switches the category index to two bytes.
func TestBuild_wideCategories(t *testing.T) {
	const nLists = 10
	texts := make([]strings.Builder, nLists)
	for combo := 1; combo < 1<<nLists; combo++ {
		for l := range nLists {
			if combo&(1<<l) != 0 {
				fmt.Fprintf(&texts[l], "||c%d.example^\n", combo)
			}
		}
	}

	var args []string
	for l := range nLists {
		args = append(args, fmt.Sprintf("l%d.txt", l), texts[l].String())
	}

	data, st := build(t, 1, args...)
	assert.Equal(t, 1<<nLists-1, st.Combos)
	assert.Equal(t, byte(2), data[48])

	tbl := mustParse(t, data)
	for combo := 1; combo < 1<<nLists; combo++ {
		assert.Equal(t, uint64(combo), tbl.Lookup(fmt.Sprintf("c%d.example", combo)))
	}

	// And through the transport form.
	pub, _ := testKey(t)
	tr, err := EncodeTransport(data, &OpenConfig{Keys: []ed25519.PublicKey{pub}})
	require.NoError(t, err)
	back, err := DecodeTransport(bytes.NewReader(tr))
	require.NoError(t, err)
	assert.Equal(t, data, back)
}

func TestTransport(t *testing.T) {
	var sb strings.Builder
	for i := range 50000 {
		fmt.Fprintf(&sb, "||d%d.example^\n", i)
	}

	data, _ := build(t, 3, "a.txt", sb.String(), "b.txt", listB)
	pub, _ := testKey(t)
	oc := &OpenConfig{Keys: []ed25519.PublicKey{pub}}

	tr, err := EncodeTransport(data, oc)
	require.NoError(t, err)
	assert.Less(t, len(tr), len(data))

	back, err := DecodeTransport(bytes.NewReader(tr))
	require.NoError(t, err)
	assert.Equal(t, data, back)

	t.Run("truncated", func(t *testing.T) {
		_, err = DecodeTransport(bytes.NewReader(tr[:len(tr)/2]))
		assert.Error(t, err)
	})

	t.Run("not_gzip", func(t *testing.T) {
		_, err = DecodeTransport(bytes.NewReader(data))
		assert.ErrorContains(t, err, "gzip")
	})

	t.Run("unsigned_input", func(t *testing.T) {
		_, err = EncodeTransport(data, &OpenConfig{})
		assert.ErrorIs(t, err, ErrSignature)
	})
}

func TestOpen_mmap(t *testing.T) {
	data, _ := build(t, 1, "a.txt", listA, "b.txt", listB)
	path := filepath.Join(t.TempDir(), "lists.tbl")
	require.NoError(t, os.WriteFile(path, data, 0o644))

	pub, _ := testKey(t)
	tbl, err := Open(path, &OpenConfig{Keys: []ed25519.PublicKey{pub}})
	require.NoError(t, err)

	// The mapping outlives the directory entry, as when a table is
	// replaced while in use.
	require.NoError(t, os.Remove(path))
	_, _, ok := tbl.Match("ads.example", 1)
	assert.True(t, ok)
	assert.EqualValues(t, 1, tbl.Sequence())
	assert.Equal(t, time.Unix(1700000000, 0), tbl.Created())

	require.NoError(t, tbl.Close())
	require.NoError(t, tbl.Close())

	_, err = Open(filepath.Join(t.TempDir(), "missing"), &OpenConfig{})
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func BenchmarkTable_Match(b *testing.B) {
	var sb strings.Builder
	for i := range 200000 {
		fmt.Fprintf(&sb, "||d%d.example.com^\n", i)
	}

	data, _ := build(b, 1, "a.txt", sb.String())
	tbl := mustParse(b, data)
	hosts := []string{"www.d1234.example.com", "nothing.here.example.org", "d99999.example.com"}

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		tbl.Match(hosts[i%len(hosts)], 1)
	}
}
