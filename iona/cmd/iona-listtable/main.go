// Command iona-listtable builds, signs, and inspects Iona list tables (see
// package listtable).
//
//	iona-listtable keygen <private-key-out> <public-key-out>
//	iona-listtable build -key <private-key> [-seq N] -o <table> <list.txt>...
//	iona-listtable verify -pub <public-key> <table>
//	iona-listtable info -pub <public-key> <table>
//	iona-listtable lookup -pub <public-key> <table> <domain>...
//	iona-listtable pack -pub <public-key> <table> <transport-out>
//	iona-listtable unpack <transport> <table-out>
//
// Keys are stored as one line of standard base64: the 64-byte Ed25519 private
// key, or the 32-byte public key.  Lists are named after their file name.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/iona/listtable"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "keygen":
		err = keygen(args)
	case "build":
		err = build(args)
	case "verify", "info":
		err = info(args, cmd == "info")
	case "lookup":
		err = lookup(args)
	case "pack":
		err = pack(args)
	case "unpack":
		err = unpack(args)
	default:
		usage()
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "iona-listtable:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: iona-listtable keygen|build|verify|info|lookup ...")
	os.Exit(2)
}

func keygen(args []string) (err error) {
	if len(args) != 2 {
		return fmt.Errorf("keygen needs <private-key-out> <public-key-out>")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	err = os.WriteFile(args[0], []byte(base64.StdEncoding.EncodeToString(priv)+"\n"), 0o600)
	if err != nil {
		return err
	}

	return os.WriteFile(args[1], []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644)
}

// readKey reads a base64 key file of the given size.
func readKey(path string, size int) (key []byte, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	key, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	} else if len(key) != size {
		return nil, fmt.Errorf("%s: key has %d bytes, want %d", path, len(key), size)
	}

	return key, nil
}

func build(args []string) (err error) {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	keyPath := fs.String("key", "", "private key file")
	out := fs.String("o", "", "output table file")
	seq := fs.Uint64("seq", uint64(time.Now().Unix()), "sequence number")
	_ = fs.Parse(args)
	if *keyPath == "" || *out == "" || fs.NArg() == 0 {
		return fmt.Errorf("build needs -key, -o, and at least one list")
	}

	key, err := readKey(*keyPath, ed25519.PrivateKeySize)
	if err != nil {
		return err
	}

	srcs := make([]listtable.Source, 0, fs.NArg())
	for _, p := range fs.Args() {
		var text []byte
		text, err = os.ReadFile(p)
		if err != nil {
			return err
		}

		srcs = append(srcs, listtable.Source{Name: filepath.Base(p), Text: text})
	}

	start := time.Now()
	data, st, err := listtable.Build(srcs, &listtable.BuildConfig{
		Created:  time.Now(),
		Key:      ed25519.PrivateKey(key),
		Sequence: *seq,
	})
	if err != nil {
		return err
	}

	tmp := *out + ".tmp"
	err = os.WriteFile(tmp, data, 0o644)
	if err != nil {
		return err
	}

	fmt.Printf(
		"lists=%d rules=%d table_rules=%d residual=%d entries=%d combos=%d idn=%d size=%d took=%s\n",
		len(srcs), st.Rules, st.TableRules, st.Residual, st.Entries, st.Combos, st.Converted,
		st.Size, time.Since(start).Round(time.Millisecond),
	)

	return os.Rename(tmp, *out)
}

// openTable opens a table with the public key given by -pub.
func openTable(name string, args []string) (t *listtable.Table, rest []string, err error) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	pubPath := fs.String("pub", "", "public key file")
	_ = fs.Parse(args)
	if *pubPath == "" || fs.NArg() == 0 {
		return nil, nil, fmt.Errorf("%s needs -pub and a table", name)
	}

	pub, err := readKey(*pubPath, ed25519.PublicKeySize)
	if err != nil {
		return nil, nil, err
	}

	t, err = listtable.Open(fs.Arg(0), &listtable.OpenConfig{Keys: []ed25519.PublicKey{pub}})
	if err != nil {
		return nil, nil, err
	}

	return t, fs.Args()[1:], nil
}

func info(args []string, verbose bool) (err error) {
	t, _, err := openTable("info", args)
	if err != nil {
		return err
	}
	defer func() { _ = t.Close() }()

	fmt.Printf("ok entries=%d combos=%d size=%d sequence=%d created=%s\n",
		t.Entries(), t.Combos(), t.Size(), t.Sequence(), t.Created().UTC().Format(time.RFC3339))
	if !verbose {
		return nil
	}

	for _, l := range t.Lists() {
		fmt.Printf("  bit=%-2d %-28s rules=%-8d entries=%-8d residual=%d\n",
			l.Bit, l.Name, l.Rules, l.Entries, len(l.Residual))
	}

	return nil
}

func pack(args []string) (err error) {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	pubPath := fs.String("pub", "", "public key file")
	_ = fs.Parse(args)
	if *pubPath == "" || fs.NArg() != 2 {
		return fmt.Errorf("pack needs -pub, a table, and an output file")
	}

	pub, err := readKey(*pubPath, ed25519.PublicKeySize)
	if err != nil {
		return err
	}

	table, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}

	out, err := listtable.EncodeTransport(table, &listtable.OpenConfig{Keys: []ed25519.PublicKey{pub}})
	if err != nil {
		return err
	}

	fmt.Printf("table=%d transport=%d\n", len(table), len(out))

	return os.WriteFile(fs.Arg(1), out, 0o644)
}

func unpack(args []string) (err error) {
	if len(args) != 2 {
		return fmt.Errorf("unpack needs <transport> <table-out>")
	}

	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	table, err := listtable.DecodeTransport(f)
	if err != nil {
		return err
	}

	return os.WriteFile(args[1], table, 0o644)
}

func lookup(args []string) (err error) {
	t, domains, err := openTable("lookup", args)
	if err != nil {
		return err
	}
	defer func() { _ = t.Close() }()

	for _, d := range domains {
		var names []string
		mask := t.Lookup(d)
		for _, l := range t.Lists() {
			if mask&(1<<uint(l.Bit)) != 0 {
				names = append(names, l.Name)
			}
		}

		bit, matched, ok := t.Match(strings.ToLower(strings.TrimSuffix(d, ".")), t.AllMask())
		via := "-"
		if ok {
			via = fmt.Sprintf("%s via %s", t.Lists()[bit].Name, matched)
		}

		fmt.Printf("%s exact=[%s] match=%s\n", d, strings.Join(names, ","), via)
	}

	return nil
}
