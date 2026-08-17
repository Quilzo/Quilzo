package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/timestamp"
)

func stampPath(root string) string { return filepath.Join(root, "timestamps.json") }

func loadStamps(root string) (*timestamp.Store, error) {
	st := &timestamp.Store{}
	b, err := os.ReadFile(stampPath(root))
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	return st, timestamp.UnmarshalStore(b, st)
}

func cmdTimestamp(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "stamp":
		return stampNow(root, args[1:])
	case "list":
		return stampList(root)
	case "export":
		return stampExport(root, args[1:])
	default:
		return fmt.Errorf("unknown timestamp command %q; try stamp, list or export", args[0])
	}
}

// publishedRoot is what gets stamped: a fingerprint over every published page.
//
// One stamp for the whole site rather than one per page. Content is
// content-addressed, so the root commits to all of it at once — and a page's
// membership is provable from the tree afterwards. Per-page stamps would be more
// requests proving less.
func publishedRoot(root string) (string, error) {
	s, err := open(root)
	if err != nil {
		return "", err
	}
	fp := public.New(s, "").Fingerprint()
	if fp == "" {
		return "", fmt.Errorf("nothing is published, so there is nothing to prove")
	}
	return fp, nil
}

func stampNow(root string, args []string) error {
	fs := flag.NewFlagSet("stamp", flag.ContinueOnError)
	tsa := fs.String("tsa", timestamp.DefaultTSA, "the timestamp authority")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fp, err := publishedRoot(root)
	if err != nil {
		return err
	}
	store, err := loadStamps(root)
	if err != nil {
		return err
	}

	w.Human("asking %s to stamp %s...\n", *tsa, fp)
	stamp, err := timestamp.Request(nil, *tsa, fp)
	if err != nil {
		return err
	}
	store.Stamps = append(store.Stamps, stamp)

	b, err := timestamp.MarshalStore(store)
	if err != nil {
		return err
	}
	if err := os.WriteFile(stampPath(root), b, 0o600); err != nil {
		return err
	}

	if w.JSON(map[string]any{
		"root": stamp.Root, "authority": stamp.Authority,
		"token_bytes": len(stamp.Token), "requested_at": stamp.RequestedAt,
		"anchored": stamp.Anchor != nil,
	}) {
		return nil
	}
	w.Human("\n%s", timestamp.Describe(stamp))
	w.Human("  %sexport it with `scrivet timestamp export` and verify with openssl%s\n",
		dim, reset)
	return nil
}

func stampList(root string) error {
	store, err := loadStamps(root)
	if err != nil {
		return err
	}
	current, _ := publishedRoot(root)

	if w.Mode == out.JSON {
		rows := make([]map[string]any, 0, len(store.Stamps))
		for _, s := range store.Stamps {
			rows = append(rows, map[string]any{
				"root": s.Root, "authority": s.Authority,
				"requested_at": s.RequestedAt, "anchored": s.Anchor != nil,
				"covers_current": s.Root == current,
			})
		}
		w.JSON(map[string]any{"stamps": rows, "current_root": current})
		return nil
	}

	if len(store.Stamps) == 0 {
		w.Human("no timestamps\n")
		return nil
	}
	for _, s := range store.Stamps {
		mark := ""
		if s.Root == current {
			mark = green + "  ← covers what is live now" + reset
		}
		w.Human("  %s  %s  %s%s\n", s.RequestedAt, s.Root[:16], s.Authority, mark)
	}
	// Said plainly: a stamp of an older root proves what the site used to say,
	// which is a different claim from proving what it says now.
	if _, ok := store.Latest(current); !ok && current != "" {
		w.Human("\n  %swhat is live now has not been stamped; the stamps above\n"+
			"  cover earlier versions%s\n", yellow, reset)
	}
	return nil
}

func stampExport(root string, args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	dir := fs.String("dir", ".", "where to write the token and its data")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := loadStamps(root)
	if err != nil {
		return err
	}
	if len(store.Stamps) == 0 {
		return fmt.Errorf("there are no timestamps to export")
	}
	latest := store.Stamps[len(store.Stamps)-1]

	tok := filepath.Join(*dir, "stamp.tsr")
	data := filepath.Join(*dir, "stamp.data")
	if err := timestamp.WriteToken(latest, tok); err != nil {
		return err
	}
	if err := timestamp.WriteStampedData(latest, data); err != nil {
		return err
	}

	w.Human("wrote %s and %s\n\n", tok, data)
	// Verification is delegated rather than reimplemented, and the command to
	// do it is printed because a proof nobody can check is not one.
	w.Human("  %sverify it yourself — this tool does not ask you to take its word:%s\n",
		dim, reset)
	w.Human("    openssl ts -verify -in %s -token_in -data %s \\\n", tok, data)
	w.Human("      -CAfile <the authority's root> -untrusted <its signing cert>\n")
	return nil
}
