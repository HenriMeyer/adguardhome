package listtable

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// TransportMagic starts the decompressed transport stream.
const TransportMagic = "IONATRN1"

// The transport form is what routers download: a gzip stream of
//
//	magic "IONATRN1"
//	uvarint length P, then the table's first P bytes (header, meta,
//	combinations) verbatim
//	IndexBuckets × uvarint: number of entries per bucket
//	N × 6 bytes: low 48 bits of every hash, little endian (the top 16 bits
//	are the bucket)
//	the category index section, unpadded
//	the 64-byte signature
//
// Hashes are uniformly distributed, so no general compressor can shrink them;
// dropping the bits the bucket already implies saves a quarter.  Decoding
// rebuilds the table byte for byte, so the original signature still applies
// and is checked by [Parse] as usual.
const lowBits = 64 - IndexBits

// EncodeTransport returns the transport form of a table.  table is validated
// with c first.
func EncodeTransport(table []byte, c *OpenConfig) (out []byte, err error) {
	t, err := Parse(table, c)
	if err != nil {
		return nil, fmt.Errorf("parsing table: %w", err)
	}

	metaLen := int(binary.LittleEndian.Uint32(table[28:]))
	l := computeLayout(metaLen, len(t.combos), len(t.hashes), catWidth(t))

	buf := &bytes.Buffer{}
	zw, err := gzip.NewWriterLevel(buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}

	w := bufio.NewWriter(zw)
	_, _ = w.WriteString(TransportMagic)
	writeUvarint(w, uint64(l.indexOff))
	_, _ = w.Write(table[:l.indexOff])

	for b := 0; b < IndexBuckets; b++ {
		writeUvarint(w, uint64(t.index[b+1]-t.index[b]))
	}

	var low [8]byte
	for _, h := range t.hashes {
		binary.LittleEndian.PutUint64(low[:], h)
		_, _ = w.Write(low[:6])
	}

	_, _ = w.Write(table[l.catsOff : l.catsOff+catWidth(t)*len(t.hashes)])
	_, _ = w.Write(table[l.sigOff:])

	err = errors.Join(w.Flush(), zw.Close())
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// catWidth returns the width of t's category indexes.
func catWidth(t *Table) (w int) {
	if t.cats8 != nil {
		return 1
	}

	return 2
}

// writeUvarint writes v as an unsigned varint.
func writeUvarint(w *bufio.Writer, v uint64) {
	var b [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(b[:], v)
	_, _ = w.Write(b[:n])
}

// maxTableSize bounds the size of a decoded table.
const maxTableSize = 256 << 20

// DecodeTransport rebuilds the table from its transport form.  The result is
// not validated; pass it to [Parse] or write it to a file for [Open].
func DecodeTransport(r io.Reader) (table []byte, err error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}

	br := bufio.NewReader(io.LimitReader(zr, maxTableSize))

	magic := make([]byte, len(TransportMagic))
	if _, err = io.ReadFull(br, magic); err != nil || string(magic) != TransportMagic {
		return nil, errors.New("not a table transport stream")
	}

	prefixLen, err := binary.ReadUvarint(br)
	if err != nil || prefixLen < headerSize || prefixLen > maxTableSize {
		return nil, fmt.Errorf("prefix length %d: %v", prefixLen, err)
	}

	prefix := make([]byte, prefixLen)
	if _, err = io.ReadFull(br, prefix); err != nil {
		return nil, fmt.Errorf("prefix: %w", err)
	}

	le := binary.LittleEndian
	comboCount := int(le.Uint32(prefix[20:]))
	entryCount := int(le.Uint32(prefix[24:]))
	metaLen := int(le.Uint32(prefix[28:]))
	width := int(prefix[48])
	if (width != 1 && width != 2) || entryCount > maxTableSize/9 || comboCount > MaxCombos ||
		metaLen > maxTableSize {
		return nil, errors.New("implausible header")
	}

	l := computeLayout(metaLen, comboCount, entryCount, width)
	if l.indexOff != int(prefixLen) || l.size > maxTableSize {
		return nil, errors.New("header does not match prefix length")
	}

	table = make([]byte, l.size)
	copy(table, prefix)

	return table, decodeEntries(br, table, l, entryCount, width)
}

// decodeEntries fills the index, hash, category, and signature sections.
func decodeEntries(br *bufio.Reader, table []byte, l layout, entryCount, width int) (err error) {
	le := binary.LittleEndian
	counts := make([]int, IndexBuckets)
	total := 0
	for b := range counts {
		n, rerr := binary.ReadUvarint(br)
		if rerr != nil || n > uint64(entryCount-total) {
			return fmt.Errorf("bucket %d: count %d: %v", b, n, rerr)
		}

		counts[b] = int(n)
		total += int(n)
	}

	var low [8]byte
	pos := 0
	for b, n := range counts {
		le.PutUint32(table[l.indexOff+4*b:], uint32(pos))
		for i := 0; i < n; i++ {
			if _, err = io.ReadFull(br, low[:6]); err != nil {
				return fmt.Errorf("entry %d: %w", pos, err)
			}

			h := uint64(b)<<lowBits | le.Uint64(low[:])&(1<<lowBits-1)
			le.PutUint64(table[l.hashesOff+8*pos:], h)
			pos++
		}
	}

	if pos != entryCount {
		return fmt.Errorf("decoded %d entries, header says %d", pos, entryCount)
	}

	le.PutUint32(table[l.indexOff+4*IndexBuckets:], uint32(pos))

	if _, err = io.ReadFull(br, table[l.catsOff:l.catsOff+width*entryCount]); err != nil {
		return fmt.Errorf("categories: %w", err)
	}

	if _, err = io.ReadFull(br, table[l.sigOff:]); err != nil {
		return fmt.Errorf("signature: %w", err)
	}

	if _, err = br.ReadByte(); err != io.EOF {
		return errors.New("trailing data after signature")
	}

	return nil
}
