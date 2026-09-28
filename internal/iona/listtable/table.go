package listtable

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"sort"
	"syscall"
	"time"
	"unsafe"
)

// Table is a validated, read-only table.  Its methods are safe for concurrent
// use until [Table.Close].
type Table struct {
	data   []byte
	unmap  func() error
	meta   Meta
	byName map[string]int

	combos []uint64
	index  []uint32
	hashes []uint64
	cats8  []uint8
	cats16 []uint16

	created  time.Time
	sequence uint64
}

// ErrSignature is returned when no trusted key verifies a table.
var ErrSignature = errors.New("signature does not verify with any trusted key")

// OpenConfig is the configuration for [Open] and [Parse].
type OpenConfig struct {
	// Keys are the trusted public keys; a table must verify with one of them.
	Keys []ed25519.PublicKey

	// MinEntries rejects tables with fewer entries, a plausibility check
	// against truncated or empty builds.
	MinEntries int
}

// Open memory-maps and validates the table at path.
func Open(path string, c *OpenConfig) (t *Table, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := fi.Size()
	if size < headerSize+signatureSize || size > 1<<31 {
		return nil, fmt.Errorf("file size %d out of range", size)
	}

	data, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap: %w", err)
	}

	t, err = parse(data, c)
	if err != nil {
		return nil, errors.Join(err, syscall.Munmap(data))
	}

	t.unmap = func() error { return syscall.Munmap(data) }

	return t, nil
}

// Parse validates a table held in memory.  data must not change afterwards.
func Parse(data []byte, c *OpenConfig) (t *Table, err error) {
	return parse(data, c)
}

// parse validates data and sets up the section views.
func parse(data []byte, c *OpenConfig) (t *Table, err error) {
	if len(data) < headerSize+signatureSize || string(data[:8]) != Magic {
		return nil, errors.New("not a table file")
	}

	le := binary.LittleEndian
	if v := le.Uint32(data[8:]); v != FormatVersion {
		return nil, fmt.Errorf("format version %d, want %d", v, FormatVersion)
	} else if a := le.Uint32(data[12:]); a != HashAlgoFNV1aFmix64 {
		return nil, fmt.Errorf("unknown hash algorithm %d", a)
	}

	listCount := int(le.Uint32(data[16:]))
	comboCount := int(le.Uint32(data[20:]))
	entryCount := int(le.Uint32(data[24:]))
	metaLen := int(le.Uint32(data[28:]))
	catWidth := int(data[48])
	switch {
	case listCount < 1 || listCount > MaxLists:
		return nil, fmt.Errorf("list count %d out of range", listCount)
	case comboCount < 1 || comboCount > MaxCombos:
		return nil, fmt.Errorf("combination count %d out of range", comboCount)
	case catWidth != 1 && catWidth != 2:
		return nil, fmt.Errorf("category width %d", catWidth)
	case entryCount < c.MinEntries:
		return nil, fmt.Errorf("%d entries, fewer than the required %d", entryCount, c.MinEntries)
	case metaLen > len(data) || entryCount > len(data)/9:
		return nil, errors.New("counts exceed file size")
	}

	l := computeLayout(metaLen, comboCount, entryCount, catWidth)
	if l.size != len(data) {
		return nil, fmt.Errorf("file size %d, header describes %d", len(data), l.size)
	}

	if !verify(c.Keys, data[:l.sigOff], data[l.sigOff:]) {
		return nil, ErrSignature
	}

	t = &Table{
		data:     data,
		created:  time.Unix(int64(le.Uint64(data[32:])), 0),
		sequence: le.Uint64(data[40:]),
	}

	err = json.Unmarshal(data[l.metaOff:l.metaOff+metaLen], &t.meta)
	if err != nil {
		return nil, fmt.Errorf("meta: %w", err)
	}

	err = t.initMeta(listCount)
	if err != nil {
		return nil, err
	}

	t.combos = u64s(data[l.combosOff:l.indexOff], comboCount)
	t.index = u32s(data[l.indexOff:l.hashesOff], IndexBuckets+1)
	t.hashes = u64s(data[l.hashesOff:l.catsOff], entryCount)
	if catWidth == 1 {
		t.cats8 = data[l.catsOff : l.catsOff+entryCount]
	} else {
		t.cats16 = u16s(data[l.catsOff:l.sigOff], entryCount)
	}

	return t, t.check(listCount)
}

// verify returns true if any key verifies sig over msg.
func verify(keys []ed25519.PublicKey, msg, sig []byte) (ok bool) {
	for _, k := range keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig) {
			return true
		}
	}

	return false
}

// initMeta validates the list descriptions and indexes them by name.
func (t *Table) initMeta(listCount int) (err error) {
	if len(t.meta.Lists) != listCount {
		return fmt.Errorf("meta describes %d lists, header %d", len(t.meta.Lists), listCount)
	}

	t.byName = make(map[string]int, listCount)
	for i, lm := range t.meta.Lists {
		if lm.Bit != i || lm.Name == "" {
			return fmt.Errorf("list %d: bit %d, name %q", i, lm.Bit, lm.Name)
		} else if _, dup := t.byName[lm.Name]; dup {
			return fmt.Errorf("duplicate list %q", lm.Name)
		}

		t.byName[lm.Name] = i
	}

	return nil
}

// check validates the index, the ordering of the hashes, and the combination
// indexes, so that a lookup can never read out of bounds or miss an entry.
func (t *Table) check(listCount int) (err error) {
	n := uint32(len(t.hashes))
	if t.index[0] != 0 || t.index[IndexBuckets] != n {
		return errors.New("bucket index does not span the entries")
	}

	for b := 0; b < IndexBuckets; b++ {
		lo, hi := t.index[b], t.index[b+1]
		if lo > hi || hi > n {
			return fmt.Errorf("bucket %d: range %d..%d", b, lo, hi)
		}

		for i := lo; i < hi; i++ {
			if int(t.hashes[i]>>(64-IndexBits)) != b {
				return fmt.Errorf("entry %d is in the wrong bucket", i)
			}
		}
	}

	for i := 1; i < len(t.hashes); i++ {
		if t.hashes[i] <= t.hashes[i-1] {
			return fmt.Errorf("entry %d out of order", i)
		}
	}

	validBits := uint64(1)<<uint(listCount) - 1
	if listCount == 64 {
		validBits = ^uint64(0)
	}

	for i, m := range t.combos {
		if m == 0 || m&^validBits != 0 {
			return fmt.Errorf("combination %d: mask %#x", i, m)
		}
	}

	for i := range t.hashes {
		if t.combo(i) >= len(t.combos) {
			return fmt.Errorf("entry %d: combination out of range", i)
		}
	}

	return nil
}

// Close releases the table.  It must not be used afterwards.
func (t *Table) Close() (err error) {
	if t.unmap == nil {
		return nil
	}

	unmap := t.unmap
	t.unmap = nil

	return unmap()
}

// combo returns the combination index of entry i.
func (t *Table) combo(i int) (c int) {
	if t.cats8 != nil {
		return int(t.cats8[i])
	}

	return int(t.cats16[i])
}

// find returns the list mask of the exact, normalized domain, or 0.
func (t *Table) find(domain string) (mask uint64) {
	h := Hash(domain)
	b := h >> (64 - IndexBits)
	lo, hi := int(t.index[b]), int(t.index[b+1])
	bucket := t.hashes[lo:hi]
	i := sort.Search(len(bucket), func(j int) bool { return bucket[j] >= h })
	if i == len(bucket) || bucket[i] != h {
		return 0
	}

	return t.combos[t.combo(lo+i)]
}

// Match returns the first list among mask that contains host or one of its
// parent domains, checked from the most specific name up, and the name that
// matched.  host must be lowercase without a trailing dot, as AdGuard Home
// passes it.
func (t *Table) Match(host string, mask uint64) (bit int, matched string, ok bool) {
	if mask == 0 || host == "" {
		return 0, "", false
	}

	for name := host; ; {
		if m := t.find(name) & mask; m != 0 {
			return bits.TrailingZeros64(m), name, true
		}

		i := indexDot(name)
		if i < 0 {
			return 0, "", false
		}

		name = name[i+1:]
	}
}

// Lookup returns the list mask of the exact domain, normalizing it first.
func (t *Table) Lookup(domain string) (mask uint64) {
	norm, ok := NormalizeDomain(domain)
	if !ok {
		return 0
	}

	return t.find(norm)
}

// indexDot returns the index of the first dot in s, or -1.
func indexDot(s string) (i int) {
	for i = 0; i < len(s); i++ {
		if s[i] == '.' {
			return i
		}
	}

	return -1
}

// Lists returns the list descriptions, indexed by bit.  The caller must not
// modify them.
func (t *Table) Lists() (lists []ListMeta) { return t.meta.Lists }

// Bit returns the bit of the named list.
func (t *Table) Bit(name string) (bit int, ok bool) {
	bit, ok = t.byName[name]

	return bit, ok
}

// Mask returns the mask of the named lists and the names this table doesn't
// know.
func (t *Table) Mask(names []string) (mask uint64, unknown []string) {
	for _, n := range names {
		bit, ok := t.byName[n]
		if !ok {
			unknown = append(unknown, n)

			continue
		}

		mask |= 1 << uint(bit)
	}

	return mask, unknown
}

// AllMask returns the mask of all lists.
func (t *Table) AllMask() (mask uint64) {
	n := len(t.meta.Lists)
	if n == 64 {
		return ^uint64(0)
	}

	return uint64(1)<<uint(n) - 1
}

// Entries returns the number of domains in the table.
func (t *Table) Entries() (n int) { return len(t.hashes) }

// Combos returns the number of list combinations.
func (t *Table) Combos() (n int) { return len(t.combos) }

// Size returns the size of the table file in bytes.
func (t *Table) Size() (n int) { return len(t.data) }

// Created returns the build time stored in the header.
func (t *Table) Created() (c time.Time) { return t.created }

// Sequence returns the build sequence number stored in the header.
func (t *Table) Sequence() (s uint64) { return t.sequence }

// littleEndian is true on little-endian hosts, where sections are used in
// place instead of being decoded.
var littleEndian = func() bool {
	x := uint16(1)

	return *(*byte)(unsafe.Pointer(&x)) == 1
}()

// u64s returns b as n little-endian uint64 values.
func u64s(b []byte, n int) (s []uint64) {
	if n == 0 {
		return []uint64{}
	}

	if littleEndian && uintptr(unsafe.Pointer(&b[0]))%8 == 0 {
		return unsafe.Slice((*uint64)(unsafe.Pointer(&b[0])), n)
	}

	s = make([]uint64, n)
	for i := range s {
		s[i] = binary.LittleEndian.Uint64(b[8*i:])
	}

	return s
}

// u32s returns b as n little-endian uint32 values.
func u32s(b []byte, n int) (s []uint32) {
	if littleEndian && uintptr(unsafe.Pointer(&b[0]))%4 == 0 {
		return unsafe.Slice((*uint32)(unsafe.Pointer(&b[0])), n)
	}

	s = make([]uint32, n)
	for i := range s {
		s[i] = binary.LittleEndian.Uint32(b[4*i:])
	}

	return s
}

// u16s returns b as n little-endian uint16 values.
func u16s(b []byte, n int) (s []uint16) {
	if n == 0 {
		return []uint16{}
	}

	if littleEndian && uintptr(unsafe.Pointer(&b[0]))%2 == 0 {
		return unsafe.Slice((*uint16)(unsafe.Pointer(&b[0])), n)
	}

	s = make([]uint16, n)
	for i := range s {
		s[i] = binary.LittleEndian.Uint16(b[2*i:])
	}

	return s
}
