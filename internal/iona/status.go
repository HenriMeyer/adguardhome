package iona

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// Status is the applied state as written to [Config.StatusPath].  Scripts
// compare Generation before and after a reload to know when it is applied.
type Status struct {
	Table           *StatusTable        `json:"table"`
	Devices         map[string][]string `json:"devices"`
	Extra           map[string]any      `json:"extra,omitempty"`
	Selected        []string            `json:"selected"`
	UnknownSelected []string            `json:"unknown_selected"`
	Enabled         []string            `json:"enabled"`
	Errors          []string            `json:"errors"`
	Updated         int64               `json:"updated"`
	Generation      uint64              `json:"generation"`
	Applied         uint64              `json:"applied"`
	Started         int64               `json:"started"`
	PID             int                 `json:"pid"`
}

// StatusTable describes the active table.
type StatusTable struct {
	Source   string   `json:"source"`
	Lists    []string `json:"lists"`
	Created  int64    `json:"created"`
	Sequence uint64   `json:"sequence"`
	Entries  int      `json:"entries"`
	Size     int      `json:"size"`
	Loaded   bool     `json:"loaded"`
}

// statusExtra is set by the embedding code to add its own applied state.
type statusExtra func() map[string]any

// SetStatusExtra registers a function that contributes extra state, e.g. the
// applied upstreams, to the status file.
func (e *Engine) SetStatusExtra(f func() map[string]any) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.extra = f
}

// Status returns the applied state.
func (e *Engine) Status() (s *Status) {
	ti := e.Table()

	e.mu.RLock()
	defer e.mu.RUnlock()

	s = &Status{
		Table: &StatusTable{
			Source:   e.st.TableSource,
			Lists:    ti.Lists,
			Sequence: ti.Sequence,
			Entries:  ti.Entries,
			Size:     ti.Size,
			Loaded:   ti.Loaded,
		},
		Devices:         map[string][]string{},
		Selected:        nonNil(e.st.Selected),
		UnknownSelected: nonNil(e.st.UnknownSelected),
		Enabled:         nonNil(e.st.Enabled),
		Errors:          nonNil(e.st.Errors),
		Updated:         time.Now().Unix(),
		Generation:      e.st.Generation,
		Applied:         e.applied,
		Started:         e.started.Unix(),
		PID:             os.Getpid(),
	}

	if ti.Loaded {
		s.Table.Created = ti.Created.Unix()
	}

	macs := make([]string, 0, len(e.devices))
	for mac := range e.devices {
		macs = append(macs, mac)
	}

	sort.Strings(macs)
	for _, mac := range macs {
		s.Devices[mac] = e.devices[mac].names
	}

	if e.extra != nil {
		s.Extra = e.extra()
	}

	return s
}

// nonNil returns s, or an empty slice instead of nil so that JSON shows [].
func nonNil(s []string) (out []string) {
	if s == nil {
		return []string{}
	}

	return s
}

// Applied marks a reload as fully applied by the embedding code (filters
// rebuilt, DNS settings set, cache cleared) and writes the status file.
// Scripts wait for the applied counter to grow, not for the generation, which
// changes before the embedding code has applied its part.
func (e *Engine) Applied(ctx context.Context) {
	e.mu.Lock()
	e.applied++
	e.mu.Unlock()

	e.writeStatus(ctx)
}

// WriteStatus writes the status file now, e.g. after the embedding code
// applied its own part of a reload.
func (e *Engine) WriteStatus(ctx context.Context) {
	e.writeStatus(ctx)
}

// writeStatus atomically replaces the status file.
func (e *Engine) writeStatus(ctx context.Context) {
	p := e.conf.StatusPath
	if p == "" {
		return
	}

	b, err := json.Marshal(e.Status())
	if err == nil {
		err = os.MkdirAll(filepath.Dir(p), 0o755)
	}

	if err == nil {
		tmp := p + ".tmp"
		err = os.WriteFile(tmp, append(b, '\n'), 0o644)
		if err == nil {
			err = os.Rename(tmp, p)
		}
	}

	if err != nil {
		e.logger.ErrorContext(ctx, "writing status", slogutil.KeyError, err)
	}
}
