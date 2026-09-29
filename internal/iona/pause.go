package iona

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/iona/listtable"
)

// PauseFile is the list pause in [Config.Dir]: for a short time the lists
// don't apply to any device except the protected ones.
//
//	until <unix seconds>
//	protect <mac>
//	protect <mac>
//
// The router writes the MACs of every device under parental control as
// protect lines.  A device whose address can't be resolved to a MAC stays
// filtered, so an unknown device never slips into the pause.
const PauseFile = "pause"

// MaxPause caps a pause, whatever until says.
const MaxPause = 5 * time.Minute

// pauseSpec is the content of the pause file.
type pauseSpec struct {
	protect map[string]struct{}
	until   int64
}

// readPause returns the pause file's content, or nil if it doesn't exist.  A
// file with any bad line is rejected as a whole: a skipped protect line would
// pause a protected device.
func readPause(dir string) (p *pauseSpec, err error) {
	lines, err := readList(filepath.Join(dir, PauseFile))
	if err != nil || lines == nil {
		return nil, err
	}

	p = &pauseSpec{protect: map[string]struct{}{}}
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) != 2 {
			return nil, fmt.Errorf("line %d: want \"until <unix>\" or \"protect <mac>\"", i+1)
		}

		switch f[0] {
		case "until":
			if p.until != 0 {
				return nil, fmt.Errorf("line %d: until given twice", i+1)
			}

			p.until, err = strconv.ParseInt(f[1], 10, 64)
			if err != nil || p.until <= 0 {
				return nil, fmt.Errorf("line %d: bad until %q", i+1, f[1])
			}
		case "protect":
			hw, perr := net.ParseMAC(f[1])
			if perr != nil || len(hw) != 6 {
				return nil, fmt.Errorf("line %d: bad mac %q", i+1, f[1])
			}

			p.protect[hw.String()] = struct{}{}
		default:
			return nil, fmt.Errorf("line %d: unknown key %q", i+1, f[0])
		}
	}

	if p.until == 0 {
		return nil, errors.New("until missing")
	}

	return p, nil
}

// pauseState is the applied pause.  The zero value is no pause.
type pauseState struct {
	// end is when the pause ends.  It carries a monotonic clock reading, so a
	// wall clock step (NTP after boot) can't stretch it.
	end time.Time

	// protect are the MAC addresses the pause doesn't apply to.
	protect map[string]struct{}

	// tags are the exclusion tags of every enabled list, so that their
	// residual rules don't apply to a paused device either.
	tags []string

	// until is the file's until, to tell a reload of the same pause from a
	// new one.
	until int64
}

// nextPause returns the pause to apply for spec.  A reload of the same pause
// keeps its end, so that reloading can't stretch it.  e.mu must be held.
func (e *Engine) nextPause(spec *pauseSpec, t *listtable.Table, mask uint64) (ps pauseState) {
	if spec == nil {
		return pauseState{}
	}

	now := e.now()
	end := e.pause.end
	if e.pause.until != spec.until || end.IsZero() {
		// time.Unix has no monotonic reading, so this compares wall clocks,
		// as the router's script that wrote until did.
		rem := time.Unix(spec.until, 0).Sub(now)
		end = now.Add(min(rem, MaxPause))
	}

	if !now.Before(end) {
		return pauseState{}
	}

	ps = pauseState{end: end, protect: spec.protect, until: spec.until}
	if t != nil {
		for _, l := range t.Lists() {
			if mask&(1<<uint(l.Bit)) != 0 {
				ps.tags = append(ps.tags, ExclusionTag(l.Name))
			}
		}
	}

	return ps
}

// pauseActiveLocked returns true if a pause is running.  e.mu must be held.
func (e *Engine) pauseActiveLocked() (ok bool) {
	return !e.pause.end.IsZero() && e.now().Before(e.pause.end)
}

// pausedLocked returns true if the lists are paused for mac.  e.mu must be
// held.
func (e *Engine) pausedLocked(mac string) (ok bool) {
	if mac == "" || !e.pauseActiveLocked() {
		return false
	}

	_, protected := e.pause.protect[mac]

	return !protected
}

// StatusPause describes a running pause.
type StatusPause struct {
	// Protected are the MAC addresses the pause doesn't apply to.
	Protected []string `json:"protected"`

	// Until is when the pause ends, in Unix seconds.
	Until int64 `json:"until"`
}

// statusPauseLocked returns the running pause, or nil.  e.mu must be held.
func (e *Engine) statusPauseLocked() (sp *StatusPause) {
	if !e.pauseActiveLocked() {
		return nil
	}

	sp = &StatusPause{
		Protected: make([]string, 0, len(e.pause.protect)),
		Until:     e.pause.end.Unix(),
	}
	for mac := range e.pause.protect {
		sp.Protected = append(sp.Protected, mac)
	}

	slices.Sort(sp.Protected)

	return sp
}
