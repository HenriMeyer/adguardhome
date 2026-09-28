package listtable

import "crypto/ed25519"

// File layout, all integers little endian:
//
//	offset  size  field
//	0       8     magic "IONATBL1"
//	8       4     format version (FormatVersion)
//	12      4     hash algorithm (HashAlgoFNV1aFmix64)
//	16      4     list count (1..MaxLists)
//	20      4     combination count (1..MaxCombos)
//	24      4     entry count
//	28      4     meta length (JSON, see Meta)
//	32      8     created, Unix seconds
//	40      8     sequence, increases with every published build
//	48      1     category index width in bytes (1 or 2)
//	49      15    reserved, zero
//	64      …     meta JSON, zero-padded to 8 bytes
//	        8×C   combinations: list bitmask per combination index
//	        4×B   bucket index: B = IndexBuckets+1 entry offsets by top hash bits,
//	              zero-padded to 8 bytes
//	        8×N   entry hashes, strictly ascending
//	        W×N   entry combination indexes (W = width byte above), zero-padded
//	              to 8 bytes
//	        64    Ed25519 signature over every byte before it
const (
	// Magic identifies a table file.
	Magic = "IONATBL1"

	// FormatVersion is the only layout version this package reads and
	// writes.  A reader must reject any other value.
	FormatVersion uint32 = 1

	// HashAlgoFNV1aFmix64 identifies [Hash].
	HashAlgoFNV1aFmix64 uint32 = 1

	// MaxLists is the number of lists a table can describe, one bit each.
	MaxLists = 64

	// MaxCombos is the maximum number of distinct list combinations.
	MaxCombos = 1 << 16

	// IndexBits is the number of top hash bits used for the bucket index.
	IndexBits = 16

	// IndexBuckets is the number of buckets of the bucket index.
	IndexBuckets = 1 << IndexBits

	headerSize    = 64
	signatureSize = ed25519.SignatureSize
)

// Meta is the JSON document stored in the table header.
type Meta struct {
	// Lists describes every list of the table, indexed by its bit.
	Lists []ListMeta `json:"lists"`
}

// ListMeta describes one list of a table.
type ListMeta struct {
	// Name is the list's file name, e.g. "pro.plus.txt", which is how routers
	// select lists.
	Name string `json:"name"`

	// Residual are the list's rules that aren't plain ||domain^ rules.  They
	// are evaluated by urlfilter on the router.
	Residual []string `json:"residual,omitempty"`

	// Bit is the list's bit in the combination masks.
	Bit int `json:"bit"`

	// Rules is the number of rules in the source list.
	Rules int `json:"rules"`

	// Entries is the number of distinct domains of this list in the table.
	Entries int `json:"entries"`
}

// align8 returns n rounded up to a multiple of 8.
func align8(n int) (aligned int) {
	return (n + 7) &^ 7
}

// layout holds the section offsets derived from the header.
type layout struct {
	metaOff   int
	combosOff int
	indexOff  int
	hashesOff int
	catsOff   int
	sigOff    int
	size      int
}

// computeLayout returns the section offsets for the given counts.
func computeLayout(metaLen, comboCount, entryCount, catWidth int) (l layout) {
	l.metaOff = headerSize
	l.combosOff = l.metaOff + align8(metaLen)
	l.indexOff = l.combosOff + 8*comboCount
	l.hashesOff = l.indexOff + align8(4*(IndexBuckets+1))
	l.catsOff = l.hashesOff + 8*entryCount
	l.sigOff = l.catsOff + align8(catWidth*entryCount)
	l.size = l.sigOff + signatureSize

	return l
}
