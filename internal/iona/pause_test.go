package iona

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock is a settable clock for [Engine.now].
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() (t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.t = c.t.Add(d)
}

// writePause writes a pause file ending at until that protects macs.
func writePause(t testing.TB, dir string, until time.Time, macs ...string) {
	t.Helper()

	s := fmt.Sprintf("until %d\n", until.Unix())
	for _, m := range macs {
		s += "protect " + m + "\n"
	}

	writeFile(t, dir, PauseFile, s)
}

func TestEngine_pause(t *testing.T) {
	e, dir, nb := newTestEngine(t, buildTable(t, 1, ""))
	clock := &fakeClock{t: time.Now()}
	e.now = clock.now

	const phone, kidMAC1, kidMAC2 = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03"
	nb.set("192.168.1.10", phone)
	nb.set("fd00::10", phone)
	nb.set("192.168.1.20", kidMAC1)
	nb.set("192.168.1.21", kidMAC2)
	nb.set("fd00::20", kidMAC1)
	reload(t, e)

	// The device exclusion stays as it is under a pause and after it.
	writeFile(t, dir, DevicesFile, phone+" ads.txt\n")

	// A pause file in upper case checks normalization.
	writePause(t, dir, clock.now().Add(MaxPause), "AA:BB:CC:00:00:02", kidMAC2)
	assert.False(t, reload(t, e), "a pause needs no filter rebuild")

	for _, addr := range []string{"192.168.1.10", "fd00::10"} {
		assert.Equal(t, "", blocked(e, addr, "casino.example"), addr)
		assert.Equal(t, "", blocked(e, addr, "ads.example"), addr)
	}

	// Protected devices, every MAC of them, and unknown devices stay filtered.
	for _, addr := range []string{"192.168.1.20", "192.168.1.21", "fd00::20", "192.168.1.99"} {
		assert.Equal(t, "gambling.txt", blocked(e, addr, "casino.example"), addr)
	}

	// A paused device carries every enabled list's tag, so residual rules
	// don't apply to it either; a protected one only its own exclusions.
	p := e.ClientPolicy(netip.MustParseAddr("192.168.1.10"))
	assert.Equal(t, []string{"iona_x_gambling", "iona_x_ads", "iona_x_tlds"}, p.Tags)
	assert.Empty(t, e.ClientPolicy(netip.MustParseAddr("192.168.1.20")).Tags)

	st := readStatus(t, dir)
	require.NotNil(t, st.Pause)
	assert.Equal(t, []string{kidMAC1, kidMAC2}, st.Pause.Protected)
	assert.Equal(t, clock.now().Add(MaxPause).Unix(), st.Pause.Until)

	// The pause ends by itself, without a reload.
	clock.add(MaxPause)
	assert.Equal(t, "gambling.txt", blocked(e, "192.168.1.10", "casino.example"))
	assert.Equal(t, "", blocked(e, "192.168.1.10", "ads.example"), "own exclusion again")
	assert.Equal(t, []string{"iona_x_ads"}, e.ClientPolicy(netip.MustParseAddr("192.168.1.10")).Tags)

	// Reloading the expired pause doesn't restart it.
	reload(t, e)
	assert.Nil(t, readStatus(t, dir).Pause)
	assert.Equal(t, "gambling.txt", blocked(e, "192.168.1.10", "casino.example"))
}

func TestEngine_pauseEnd(t *testing.T) {
	e, dir, nb := newTestEngine(t, buildTable(t, 1, ""))
	clock := &fakeClock{t: time.Now()}
	e.now = clock.now

	const phone = "aa:bb:cc:00:00:01"
	nb.set("192.168.1.10", phone)

	// An until far ahead is capped.
	writePause(t, dir, clock.now().Add(24*time.Hour))
	reload(t, e)
	require.NotNil(t, readStatus(t, dir).Pause)
	assert.Equal(t, clock.now().Add(MaxPause).Unix(), readStatus(t, dir).Pause.Until)

	// Reloading the same pause keeps its end.
	clock.add(4 * time.Minute)
	reload(t, e)
	assert.Equal(t, clock.now().Add(time.Minute).Unix(), readStatus(t, dir).Pause.Until)
	assert.Equal(t, "", blocked(e, "192.168.1.10", "casino.example"))

	clock.add(time.Minute)
	assert.Equal(t, "gambling.txt", blocked(e, "192.168.1.10", "casino.example"))

	// A new until starts a new pause.
	writePause(t, dir, clock.now().Add(2*time.Minute))
	reload(t, e)
	assert.Equal(t, clock.now().Add(2*time.Minute).Unix(), readStatus(t, dir).Pause.Until)
	assert.Equal(t, "", blocked(e, "192.168.1.10", "casino.example"))

	// Removing the file ends the pause.
	require.NoError(t, os.Remove(filepath.Join(dir, PauseFile)))
	reload(t, e)
	assert.Nil(t, readStatus(t, dir).Pause)
	assert.Equal(t, "gambling.txt", blocked(e, "192.168.1.10", "casino.example"))

	// An until in the past is no pause.
	writePause(t, dir, clock.now().Add(-time.Second))
	reload(t, e)
	assert.Nil(t, readStatus(t, dir).Pause)
	assert.Equal(t, "gambling.txt", blocked(e, "192.168.1.10", "casino.example"))
}

func TestEngine_pauseBadFile(t *testing.T) {
	e, dir, nb := newTestEngine(t, buildTable(t, 1, ""))
	nb.set("192.168.1.10", "aa:bb:cc:00:00:01")

	until := fmt.Sprintf("until %d\n", time.Now().Add(time.Minute).Unix())
	for name, content := range map[string]string{
		"bad mac":      until + "protect aa:bb:cc:00:00:02\nprotect nope\n",
		"no until":     "protect aa:bb:cc:00:00:02\n",
		"two untils":   until + until,
		"bad until":    "until soon\n",
		"unknown key":  until + "pause aa:bb:cc:00:00:02\n",
		"extra fields": until + "protect aa:bb:cc:00:00:02 x\n",
	} {
		t.Run(name, func(t *testing.T) {
			writeFile(t, dir, PauseFile, content)
			reload(t, e)

			st := readStatus(t, dir)
			assert.Nil(t, st.Pause)
			require.Len(t, st.Errors, 1)
			assert.Contains(t, st.Errors[0], PauseFile)
			assert.Equal(t, "gambling.txt", blocked(e, "192.168.1.10", "casino.example"))
		})
	}
}
