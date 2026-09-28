// Package listtable implements Iona's compact block-list table.
//
// Every pure ||domain^ rule of every published list is stored once, as a
// 64-bit hash of the normalized domain plus a one-byte index into a small
// table of list bitmasks (which lists contain the domain).  The table is built
// on the server, signed with Ed25519, and memory-mapped on the router, so
// loading or swapping it costs no parsing and no heap.  All other rules of a
// list (wildcards, $denyallow, exceptions, …) travel along as "residual" rules
// and stay with urlfilter.
//
// The hash and the normalization must be identical in every builder and
// reader; testdata/vectors.json pins them for other implementations.
package listtable

import (
	"strings"

	"golang.org/x/net/idna"
)

const (
	fnvOffset64 = 0xcbf29ce484222325
	fnvPrime64  = 0x100000001b3
)

// Hash returns the table hash of an already normalized domain: FNV-1a 64 over
// its bytes, finished with the MurmurHash3 fmix64 avalanche so that the top
// bits used for the bucket index are well mixed.
func Hash(domain string) (h uint64) {
	h = fnvOffset64
	for i := 0; i < len(domain); i++ {
		h ^= uint64(domain[i])
		h *= fnvPrime64
	}

	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33

	return h
}

// idnaProfile converts internationalized names to their ASCII form the same
// way for list entries and queries.
var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(false))

// NormalizeDomain returns the canonical form of a domain name as used for
// hashing: lowercase ASCII (IDNs converted to punycode), without a trailing
// dot.  ok is false if s is not a usable domain name.
func NormalizeDomain(s string) (norm string, ok bool) {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return "", false
	}

	if !isASCII(s) {
		var err error
		s, err = idnaProfile.ToASCII(s)
		if err != nil {
			return "", false
		}
	}

	s = strings.ToLower(s)

	return s, validDomain(s)
}

// isASCII returns true if s contains only ASCII bytes.
func isASCII(s string) (ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}

	return true
}

// validDomain returns true if s consists of non-empty labels of lowercase
// letters, digits, hyphens, and underscores (the latter appear in real lists,
// e.g. _dmarc names), each at most 63 bytes long.
func validDomain(s string) (ok bool) {
	labelLen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '.':
			if labelLen == 0 {
				return false
			}

			labelLen = 0
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_':
			labelLen++
			if labelLen > 63 {
				return false
			}
		default:
			return false
		}
	}

	return labelLen > 0
}
