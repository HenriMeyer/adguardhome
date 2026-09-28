package iona

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/AdguardTeam/AdGuardHome/internal/iona/listtable"
)

// readLines returns the non-empty, non-comment lines of the file, or nil if it
// doesn't exist.
func readLines(path string) (lines []string, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		lines = append(lines, line)
	}

	return lines, s.Err()
}

// readKeys returns the trusted public keys from dir/keys/*.pub.
func readKeys(dir string) (keys []ed25519.PublicKey, err error) {
	paths, err := filepath.Glob(filepath.Join(dir, KeysDir, "*.pub"))
	if err != nil {
		return nil, err
	}

	var errs []error
	for _, p := range paths {
		var b []byte
		b, err = os.ReadFile(p)
		if err != nil {
			errs = append(errs, err)

			continue
		}

		var k []byte
		k, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(k) != ed25519.PublicKeySize {
			errs = append(errs, fmt.Errorf("%s: not a base64 Ed25519 public key", filepath.Base(p)))

			continue
		}

		keys = append(keys, ed25519.PublicKey(k))
	}

	if len(keys) == 0 {
		errs = append(errs, errors.New("no trusted keys"))
	}

	return keys, errors.Join(errs...)
}

// readSelected returns the enabled list names.
func readSelected(dir string) (names []string, err error) {
	lines, err := readLines(filepath.Join(dir, SelectedFile))
	if err != nil {
		return nil, err
	}

	for _, l := range lines {
		// Accept the comma-separated UCI form too.
		for _, n := range strings.Split(l, ",") {
			n = strings.TrimSpace(n)
			if n != "" && !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}

	return names, nil
}

// readDevices returns the per-device exclusions by normalized MAC address.
func readDevices(dir string) (profiles map[string][]string, err error) {
	lines, err := readLines(filepath.Join(dir, DevicesFile))
	if err != nil {
		return nil, err
	}

	profiles = map[string][]string{}
	var errs []error
	for i, l := range lines {
		fields := strings.Fields(l)
		if len(fields) != 2 {
			errs = append(errs, fmt.Errorf("line %d: want \"<mac> <lists>\"", i+1))

			continue
		}

		hw, perr := net.ParseMAC(fields[0])
		if perr != nil || len(hw) != 6 {
			errs = append(errs, fmt.Errorf("line %d: bad mac %q", i+1, fields[0]))

			continue
		}

		mac := hw.String()
		for _, n := range strings.Split(fields[1], ",") {
			if n = strings.TrimSpace(n); n != "" && !slices.Contains(profiles[mac], n) {
				profiles[mac] = append(profiles[mac], n)
			}
		}
	}

	return profiles, errors.Join(errs...)
}

// Table sources reported in the status file.
const (
	sourceCurrent = "current"
	sourcePrev    = "prev"
	sourceNone    = "none"
)

// loadTable returns the table to use after this reload: a staged table if it
// validates, otherwise the current one, otherwise lists.tbl or lists.tbl.prev
// from disk.
func (e *Engine) loadTable(
	ctx context.Context,
	keys []ed25519.PublicKey,
	cur *listtable.Table,
	curSource string,
) (t *listtable.Table, source string, errs []string) {
	oc := &listtable.OpenConfig{Keys: keys, MinEntries: e.conf.MinEntries}
	dir := e.conf.Dir

	// A table opened here isn't installed yet, so it must be closed here if
	// the staged one replaces it.
	openedHere := false
	var diskErrs []string
	if cur == nil {
		cur, curSource, diskErrs = e.openFromDisk(oc)
		openedHere = cur != nil
	}

	staged := filepath.Join(dir, NewTableFile)
	if _, err := os.Stat(staged); errors.Is(err, fs.ErrNotExist) {
		return cur, curSource, diskErrs
	}

	next, err := e.promote(oc, staged, cur)
	if err != nil {
		// The disk errors matter now: they say what is (not) active instead.
		errs = append(diskErrs, fmt.Sprintf("staged table rejected: %s", err))
		rerr := os.Rename(staged, filepath.Join(dir, RejectedTableFile))
		if rerr != nil {
			errs = append(errs, fmt.Sprintf("moving rejected table aside: %s", rerr))
		}

		return cur, curSource, errs
	}

	e.logger.InfoContext(ctx, "promoted list table", "sequence", next.Sequence(), "entries", next.Entries())

	if openedHere {
		if cerr := cur.Close(); cerr != nil {
			errs = append(errs, fmt.Sprintf("closing replaced table: %s", cerr))
		}
	}

	return next, sourceCurrent, errs
}

// openFromDisk opens lists.tbl, falling back to lists.tbl.prev.
func (e *Engine) openFromDisk(oc *listtable.OpenConfig) (t *listtable.Table, source string, errs []string) {
	t, err := listtable.Open(filepath.Join(e.conf.Dir, TableFile), oc)
	if err == nil {
		return t, sourceCurrent, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Sprintf("%s: %s", TableFile, err))
	}

	t, perr := listtable.Open(filepath.Join(e.conf.Dir, PrevTableFile), oc)
	if perr == nil {
		errs = append(errs, "using the previous table")

		return t, sourcePrev, errs
	} else if !errors.Is(perr, fs.ErrNotExist) {
		errs = append(errs, fmt.Sprintf("%s: %s", PrevTableFile, perr))
	}

	errs = append(errs, "no usable list table")

	return nil, sourceNone, errs
}

// promote decodes and validates the staged table and makes it the active
// file, keeping the old one as lists.tbl.prev.
func (e *Engine) promote(
	oc *listtable.OpenConfig,
	staged string,
	cur *listtable.Table,
) (t *listtable.Table, err error) {
	dir := e.conf.Dir
	tmp := filepath.Join(dir, tmpTableFile)
	err = decodeStaged(staged, tmp)
	if err != nil {
		return nil, err
	}

	t, err = listtable.Open(tmp, oc)
	if err != nil {
		return nil, errors.Join(err, os.Remove(tmp))
	}

	if cur != nil && t.Sequence() < cur.Sequence() {
		err = fmt.Errorf("sequence %d is older than the active %d", t.Sequence(), cur.Sequence())

		return nil, errors.Join(err, t.Close(), os.Remove(tmp))
	}

	active := filepath.Join(dir, TableFile)
	if _, serr := os.Stat(active); serr == nil {
		err = os.Rename(active, filepath.Join(dir, PrevTableFile))
		if err != nil {
			return nil, errors.Join(err, t.Close(), os.Remove(tmp))
		}
	}

	err = os.Rename(tmp, active)
	if err != nil {
		return nil, errors.Join(err, t.Close())
	}

	return t, errors.Join(os.Remove(staged), syncDir(dir))
}

// decodeStaged writes the raw table for the staged file to tmp, decoding the
// transport form if needed, and syncs it to disk.
func decodeStaged(staged, tmp string) (err error) {
	f, err := os.Open(staged)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()

	br := bufio.NewReader(f)
	head, _ := br.Peek(2)

	var src io.Reader = br
	if len(head) == 2 && head[0] == 0x1f && head[1] == 0x8b {
		var table []byte
		table, err = listtable.DecodeTransport(br)
		if err != nil {
			return fmt.Errorf("decoding transport form: %w", err)
		}

		src = bytes.NewReader(table)
	}

	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, src)
	if err == nil {
		err = out.Sync()
	}

	return errors.Join(err, out.Close())
}

// syncDir fsyncs a directory so that renames inside it are durable.
func syncDir(dir string) (err error) {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}

	return errors.Join(d.Sync(), d.Close())
}

// exists returns true if path exists.
func exists(path string) (ok bool) {
	_, err := os.Stat(path)

	return err == nil
}
