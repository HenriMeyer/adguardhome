package filtering

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// serveMutableLocally is like [serveFiltersLocally], but serves whatever
// content currently holds, so a test can change a list between refreshes.
func serveMutableLocally(tb testing.TB, content *atomic.Pointer[[]byte]) (urlStr string) {
	tb.Helper()

	pt := testutil.NewPanicT(tb)

	return serveHTTPLocally(tb, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, werr := w.Write(*content.Load())
		require.NoError(pt, werr)
	}))
}

func TestDNSFilter_RefreshAllowOnly(t *testing.T) {
	const host = "blocked.example"

	blockContent := []byte("||" + host + "^\n")
	allowContent := &atomic.Pointer[[]byte]{}
	allowContent.Store(&[]byte{})

	d := newDNSFilter(t)
	d.conf.Filters = []FilterYAML{{
		Enabled: true,
		URL:     serveFiltersLocally(t, blockContent),
		Filter:  Filter{ID: 1},
	}}
	d.conf.WhitelistFilters = []FilterYAML{{
		Enabled: true,
		URL:     serveMutableLocally(t, allowContent),
		Filter:  Filter{ID: 2},
	}}

	setts := &Settings{ProtectionEnabled: true, FilteringEnabled: true}

	updated, isNetErr := d.refreshFiltersIntl(true, true, true)
	require.False(t, isNetErr)
	require.Equal(t, 1, updated)

	res, err := d.CheckHost(host, dns.TypeA, setts)
	require.NoError(t, err)
	require.Equal(t, FilteredBlockList, res.Reason)

	blockStorage, blockEngine := d.rulesStorage, d.filteringEngine
	allowStorage := d.rulesStorageAllow

	newAllow := []byte("@@||" + host + "^\n")
	allowContent.Store(&newAllow)

	updated, isNetErr = d.refreshFiltersIntl(false, true, true)
	require.False(t, isNetErr)
	require.Equal(t, 1, updated)

	assert.Same(t, blockStorage, d.rulesStorage, "blocklist storage must not be rebuilt")
	assert.Same(t, blockEngine, d.filteringEngine, "blocklist engine must not be rebuilt")
	assert.NotSame(t, allowStorage, d.rulesStorageAllow, "allowlist storage must be rebuilt")

	res, err = d.CheckHost(host, dns.TypeA, setts)
	require.NoError(t, err)
	assert.Equal(t, NotFilteredAllowList, res.Reason)
}
