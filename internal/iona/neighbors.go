package iona

import (
	"net/netip"
	"sync"
	"time"
)

// NeighborFunc returns the current IP-to-MAC mapping of the LAN, MAC addresses
// in lowercase colon form.
type NeighborFunc func() (m map[netip.Addr]string, err error)

// Refresh timing of the neighbor cache.  A miss triggers an early refresh so
// that a device's first queries after it joins already get its profile.
const (
	neighborRefreshIvl  = 10 * time.Second
	neighborMissBackoff = time.Second
)

// neighborCache caches a [NeighborFunc] and refreshes it periodically and on
// misses.
type neighborCache struct {
	fetch NeighborFunc

	mu      sync.RWMutex
	byIP    map[netip.Addr]string
	fetched time.Time

	// refreshMu makes concurrent misses share one refresh.
	refreshMu sync.Mutex

	stopOnce sync.Once
	done     chan struct{}
	started  sync.Once
}

// newNeighborCache returns a cache over fetch.
func newNeighborCache(fetch NeighborFunc) (c *neighborCache) {
	return &neighborCache{
		fetch: fetch,
		byIP:  map[netip.Addr]string{},
		done:  make(chan struct{}),
	}
}

// MAC returns the MAC address of ip.
func (c *neighborCache) MAC(ip netip.Addr) (mac string, ok bool) {
	c.started.Do(func() { go c.loop() })

	c.mu.RLock()
	mac, ok = c.byIP[ip]
	stale := time.Since(c.fetched) > neighborMissBackoff
	c.mu.RUnlock()

	if ok || !stale {
		return mac, ok
	}

	c.refresh()

	c.mu.RLock()
	defer c.mu.RUnlock()

	mac, ok = c.byIP[ip]

	return mac, ok
}

// refresh re-reads the neighbor table unless another goroutine just did.
func (c *neighborCache) refresh() {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	c.mu.RLock()
	fresh := time.Since(c.fetched) < neighborMissBackoff
	c.mu.RUnlock()
	if fresh {
		return
	}

	m, err := c.fetch()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.fetched = time.Now()
	if err == nil {
		c.byIP = m
	}
}

// loop refreshes the cache periodically so that an address reassigned to
// another device is picked up without a miss.
func (c *neighborCache) loop() {
	t := time.NewTicker(neighborRefreshIvl)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			c.mu.Lock()
			c.fetched = time.Time{}
			c.mu.Unlock()
			c.refresh()
		case <-c.done:
			return
		}
	}
}

// stop ends the refresh loop.
func (c *neighborCache) stop() {
	c.stopOnce.Do(func() { close(c.done) })
}
