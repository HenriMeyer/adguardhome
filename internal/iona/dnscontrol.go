package iona

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
)

// DNS control files in [Config.Dir].  Each one is optional; a missing file
// leaves the setting as configured in adguardhome.yaml.
const (
	UpstreamsFile = "upstreams"
	FallbacksFile = "fallbacks"
	BlockingFile  = "blocking"
	RewritesFile  = "rewrites"
)

// DNSControl is the content of the DNS control files.  A nil field means the
// file doesn't exist.
type DNSControl struct {
	Blocking  *Blocking
	Upstreams []string
	Fallbacks []string
	Rewrites  [][2]string
}

// Blocking is the content of the blocking file: "<mode> [<ipv4> [<ipv6>]]".
type Blocking struct {
	Mode string
	IPv4 netip.Addr
	IPv6 netip.Addr
}

// ReadDNSControl reads the DNS control files from dir.
func ReadDNSControl(dir string) (c *DNSControl, err error) {
	c = &DNSControl{}
	var errs []error

	c.Upstreams, err = readList(filepath.Join(dir, UpstreamsFile))
	errs = append(errs, err)

	c.Fallbacks, err = readList(filepath.Join(dir, FallbacksFile))
	errs = append(errs, err)

	c.Blocking, err = readBlocking(filepath.Join(dir, BlockingFile))
	errs = append(errs, err)

	c.Rewrites, err = readRewrites(filepath.Join(dir, RewritesFile))
	errs = append(errs, err)

	return c, errors.Join(errs...)
}

// readList returns the lines of path, a non-nil empty slice for an empty
// file, and nil if it doesn't exist.
func readList(path string) (list []string, err error) {
	lines, err := readLines(path)
	if err != nil || lines != nil {
		return lines, err
	}

	if exists(path) {
		return []string{}, nil
	}

	return nil, nil
}

// readBlocking parses the blocking file.
func readBlocking(path string) (b *Blocking, err error) {
	lines, err := readLines(path)
	if err != nil || len(lines) == 0 {
		return nil, err
	}

	f := strings.Fields(lines[0])
	b = &Blocking{Mode: f[0]}
	switch b.Mode {
	case "default", "nxdomain", "null_ip", "refused":
		if len(f) != 1 {
			return nil, fmt.Errorf("%s: mode %s takes no addresses", BlockingFile, b.Mode)
		}
	case "custom_ip":
		if len(f) < 2 || len(f) > 3 {
			return nil, fmt.Errorf("%s: custom_ip needs an IPv4 and an optional IPv6 address", BlockingFile)
		}

		b.IPv4, err = netip.ParseAddr(f[1])
		if err != nil || !b.IPv4.Is4() {
			return nil, fmt.Errorf("%s: bad IPv4 address %q", BlockingFile, f[1])
		}

		b.IPv6 = netip.IPv6Unspecified()
		if len(f) == 3 {
			b.IPv6, err = netip.ParseAddr(f[2])
			if err != nil || !b.IPv6.Is6() {
				return nil, fmt.Errorf("%s: bad IPv6 address %q", BlockingFile, f[2])
			}
		}
	default:
		return nil, fmt.Errorf("%s: unknown mode %q", BlockingFile, b.Mode)
	}

	return b, nil
}

// readRewrites parses the rewrites file: "<domain> <answer>" per line.
func readRewrites(path string) (rws [][2]string, err error) {
	lines, err := readList(path)
	if err != nil || lines == nil {
		return nil, err
	}

	rws = [][2]string{}
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) != 2 {
			return nil, fmt.Errorf("%s: line %d: want \"<domain> <answer>\"", RewritesFile, i+1)
		}

		rws = append(rws, [2]string{strings.ToLower(f[0]), f[1]})
	}

	return rws, nil
}
