package listtable

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Source is one list to build a table from.
type Source struct {
	// Name is the list's file name, e.g. "pro.plus.txt".
	Name string

	// Text is the list in AdGuard syntax.
	Text []byte
}

// BuildConfig is the configuration for [Build].
type BuildConfig struct {
	// Created is stored in the header.
	Created time.Time

	// Key signs the table.  It must not be nil.
	Key ed25519.PrivateKey

	// Sequence is stored in the header; it should grow with every published
	// build.
	Sequence uint64
}

// BuildStats describes a built table.
type BuildStats struct {
	// Rules is the number of rule lines over all lists.
	Rules int

	// TableRules is the number of rules that went into the table.
	TableRules int

	// Residual is the number of rules kept for urlfilter.
	Residual int

	// Entries is the number of distinct domains in the table.
	Entries int

	// Combos is the number of distinct list combinations.
	Combos int

	// Converted is the number of internationalized domains converted to
	// punycode.
	Converted int

	// Size is the size of the table file in bytes.
	Size int
}

// Build builds a signed table from srcs.  Lists keep the order of srcs; the
// first list gets bit 0.
func Build(srcs []Source, c *BuildConfig) (data []byte, st *BuildStats, err error) {
	if len(srcs) == 0 || len(srcs) > MaxLists {
		return nil, nil, fmt.Errorf("list count %d out of range 1..%d", len(srcs), MaxLists)
	} else if len(c.Key) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("invalid signing key")
	}

	st = &BuildStats{}
	masks := map[string]uint64{}
	meta := &Meta{Lists: make([]ListMeta, len(srcs))}
	seen := map[string]struct{}{}
	for i, src := range srcs {
		if _, dup := seen[src.Name]; dup || src.Name == "" {
			return nil, nil, fmt.Errorf("list %d: empty or duplicate name %q", i, src.Name)
		}

		seen[src.Name] = struct{}{}
		meta.Lists[i], err = addList(masks, src, i, st)
		if err != nil {
			return nil, nil, fmt.Errorf("list %q: %w", src.Name, err)
		}
	}

	data, err = encode(meta, masks, c, st)
	if err != nil {
		return nil, nil, err
	}

	st.Size = len(data)

	return data, st, nil
}

// addList parses src and adds its domains to masks under bit.
func addList(masks map[string]uint64, src Source, bit int, st *BuildStats) (lm ListMeta, err error) {
	lm = ListMeta{Name: src.Name, Bit: bit}
	own := map[string]struct{}{}

	s := bufio.NewScanner(bytes.NewReader(src.Text))
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if isComment(line) {
			continue
		}

		lm.Rules++
		st.Rules++

		domain, converted, ok := parsePlainRule(line)
		if !ok {
			lm.Residual = append(lm.Residual, line)
			st.Residual++

			continue
		}

		st.TableRules++
		if converted {
			st.Converted++
		}

		masks[domain] |= 1 << uint(bit)
		own[domain] = struct{}{}
	}

	if err = s.Err(); err != nil {
		return lm, err
	}

	lm.Entries = len(own)

	return lm, nil
}

// isComment returns true for lines that aren't rules.
func isComment(line string) (ok bool) {
	return line == "" || line[0] == '!' || line[0] == '#' || line[0] == '['
}

// parsePlainRule returns the normalized domain of a ||domain^ rule.  The only
// modifier accepted is a single negated $ctag, which older hagezi-sync builds
// appended to every rule of a device-excludable list; a list's category is its
// bit now.  Everything else, including rules urlfilter would read differently
// from a plain suffix match, is not a plain rule.
func parsePlainRule(line string) (domain string, converted, ok bool) {
	rest, found := strings.CutPrefix(line, "||")
	if !found {
		return "", false, false
	}

	i := strings.IndexByte(rest, '^')
	if i <= 0 {
		return "", false, false
	}

	dom, tail := rest[:i], rest[i+1:]
	if tail != "" && !isLegacyCTag(tail) {
		return "", false, false
	}

	// A leading or trailing dot or any wildcard would make urlfilter match
	// something else than the domain and its subdomains.
	if dom[0] == '.' || dom[len(dom)-1] == '.' || strings.ContainsAny(dom, "*/|:[]") {
		return "", false, false
	}

	domain, ok = NormalizeDomain(dom)
	if !ok {
		return "", false, false
	}

	return domain, domain != strings.ToLower(dom), true
}

// isLegacyCTag returns true if tail is exactly "$ctag=~<tag>".
func isLegacyCTag(tail string) (ok bool) {
	tag, found := strings.CutPrefix(tail, "$ctag=~")
	if !found || tag == "" {
		return false
	}

	for i := 0; i < len(tag); i++ {
		c := tag[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}

	return true
}

// entry is a table entry before encoding.
type entry struct {
	hash  uint64
	combo int
}

// encode lays out and signs the table.
func encode(
	meta *Meta,
	masks map[string]uint64,
	c *BuildConfig,
	st *BuildStats,
) (data []byte, err error) {
	comboIdx := map[uint64]int{}
	var combos []uint64
	entries := make([]entry, 0, len(masks))
	byHash := make(map[uint64]string, len(masks))
	for domain, mask := range masks {
		h := Hash(domain)
		if other, dup := byHash[h]; dup {
			return nil, fmt.Errorf("hash collision between %q and %q", domain, other)
		}

		byHash[h] = domain

		idx, ok := comboIdx[mask]
		if !ok {
			idx = len(combos)
			comboIdx[mask] = idx
			combos = append(combos, mask)
		}

		entries = append(entries, entry{hash: h, combo: idx})
	}

	if len(combos) > MaxCombos {
		return nil, fmt.Errorf("%d list combinations, at most %d supported", len(combos), MaxCombos)
	}

	slices.SortFunc(entries, func(a, b entry) int {
		switch {
		case a.hash < b.hash:
			return -1
		case a.hash > b.hash:
			return 1
		default:
			return 0
		}
	})

	st.Entries, st.Combos = len(entries), len(combos)

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("encoding meta: %w", err)
	}

	catWidth := 1
	if len(combos) > 256 {
		catWidth = 2
	}

	l := computeLayout(len(metaJSON), len(combos), len(entries), catWidth)
	data = make([]byte, l.size)

	copy(data, Magic)
	le := binary.LittleEndian
	le.PutUint32(data[8:], FormatVersion)
	le.PutUint32(data[12:], HashAlgoFNV1aFmix64)
	le.PutUint32(data[16:], uint32(len(meta.Lists)))
	le.PutUint32(data[20:], uint32(len(combos)))
	le.PutUint32(data[24:], uint32(len(entries)))
	le.PutUint32(data[28:], uint32(len(metaJSON)))
	le.PutUint64(data[32:], uint64(c.Created.Unix()))
	le.PutUint64(data[40:], c.Sequence)
	data[48] = byte(catWidth)

	copy(data[l.metaOff:], metaJSON)

	for i, m := range combos {
		le.PutUint64(data[l.combosOff+8*i:], m)
	}

	bucket := 0
	for i, e := range entries {
		b := int(e.hash >> (64 - IndexBits))
		for bucket <= b {
			le.PutUint32(data[l.indexOff+4*bucket:], uint32(i))
			bucket++
		}

		le.PutUint64(data[l.hashesOff+8*i:], e.hash)
		if catWidth == 1 {
			data[l.catsOff+i] = byte(e.combo)
		} else {
			le.PutUint16(data[l.catsOff+2*i:], uint16(e.combo))
		}
	}

	for ; bucket <= IndexBuckets; bucket++ {
		le.PutUint32(data[l.indexOff+4*bucket:], uint32(len(entries)))
	}

	sig := ed25519.Sign(c.Key, data[:l.sigOff])
	copy(data[l.sigOff:], sig)

	return data, nil
}
