// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/quilzo/quilzo/internal/anchor"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/render"
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
		args = []string{bareRuns["timestamp"]}
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

// publishedRoot is what gets stamped: the live commit id, which is what an
// anchor commits to (liveFingerprint).
//
// One stamp for the whole site rather than one per page. Content is
// content-addressed, so the commit commits to all of it at once — and a page's
// membership is provable from the tree afterwards. Per-page stamps would be more
// requests proving less.
//
// It was the display fingerprint, which is SHA-256 over the page names and
// hashes cut to sixteen hex characters: sixty-four bits, a weaker receipt
// than it looks, and never the subject an anchor commits to. So a stamp and
// an anchor of one publication could not be joined, and every stamp said it
// had no blockchain anchor. A stamp made then is still read: see
// legacyRoot.
func publishedRoot(root string) (string, error) {
	return liveFingerprint(root)
}

// legacyRoot is what a stamp made before publishedRoot changed was over: the
// display fingerprint of what is live, or empty when that cannot be read.
//
// Kept so such a stamp still says it covers what is live when the content
// has not changed since. Its stamp.data holds the fingerprint, so it still
// verifies as it always did.
func legacyRoot(root string) string {
	s, err := open(root)
	if err != nil {
		return ""
	}
	// No layouts: a fingerprint is over what is published, and nothing here
	// renders anything.
	return public.New(s, render.Layouts{}).Fingerprint()
}

// covers says whether a stamp is over what is live now.
func covers(st timestamp.Stamp, current, legacy string) bool {
	return st.Root != "" && (st.Root == current || st.Root == legacy)
}

// joinAnchors sets each stamp's Anchor from the anchors of its subject.
//
// Joined when read rather than written into the stamp: an anchor upgrades
// from pending to a block later, and a copy taken at stamping would go on
// saying pending. The best proof wins, one in a block over one waiting.
func joinAnchors(root string, stamps []timestamp.Stamp) []timestamp.Stamp {
	file, err := loadAnchors(root)
	if err != nil || len(file.Proofs) == 0 {
		return stamps
	}
	out := make([]timestamp.Stamp, len(stamps))
	for i, st := range stamps {
		out[i] = st
		if st.Anchor != nil {
			continue
		}
		var best *anchor.Proof
		for j := range file.Proofs {
			p := &file.Proofs[j]
			if p.Digest != st.Root || p.Kind != anchor.Publication {
				continue
			}
			if best == nil || (p.Anchored() && !best.Anchored()) {
				best = p
			}
		}
		if best == nil {
			continue
		}
		ref := best.Calendar
		if best.Anchored() {
			ref = fmt.Sprintf("Bitcoin block %d, from %s", best.Height, best.Calendar)
		}
		out[i].Anchor = &timestamp.Anchor{Method: "OpenTimestamps", Reference: ref,
			SubmittedAt: best.SubmittedAt, Confirmed: best.Anchored()}
	}
	return out
}

// stampRequest asks an authority for a token: timestamp.Request, through its
// own client for public services. A variable so a test can stand in for the
// authority.
var stampRequest = timestamp.Request

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
	stamp, err := stampRequest(nil, *tsa, fp)
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
	// Sending the publication's digest to an outside authority is an act, as
	// submitting it to the calendars is, and `anchor submit` kept a record
	// while this kept none. The authority is named by its host: an address
	// can carry a credential, and the log is read further than this file.
	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "timestamp.stamp", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Model: caller.Model, Verified: caller.Verified,
		Detail: map[string]string{"root": stamp.Root, "authority": authorityHost(stamp.Authority)},
	})
	// Shown with the anchor of the same publication, when there is one.
	stamp = joinAnchors(root, []timestamp.Stamp{stamp})[0]

	if w.JSON(map[string]any{
		"root": stamp.Root, "authority": stamp.Authority,
		"token_bytes": len(stamp.Token), "requested_at": stamp.RequestedAt,
		"anchored": stamp.Anchor != nil,
	}) {
		return nil
	}
	w.Human("\n%s", timestamp.Describe(stamp))
	w.Human("  %sexport it with `quilzo timestamp export` and verify with openssl%s\n",
		dim, reset)
	return nil
}

// authorityHost is the host of an outside service's address, for an audit
// record: who the digest went to, without a user, password or query that
// the address may carry. An address that does not parse is not named.
func authorityHost(address string) string {
	u, err := url.Parse(address)
	if err != nil || u.Host == "" {
		return "unreadable address"
	}
	return u.Host
}

func stampList(root string) error {
	store, err := loadStamps(root)
	if err != nil {
		return err
	}
	current, _ := publishedRoot(root)
	legacy := legacyRoot(root)
	stamps := joinAnchors(root, store.Stamps)

	if w.Mode == out.JSON {
		rows := make([]map[string]any, 0, len(stamps))
		for _, s := range stamps {
			rows = append(rows, map[string]any{
				"root": s.Root, "authority": s.Authority,
				"requested_at": s.RequestedAt, "anchored": s.Anchor != nil,
				"covers_current": covers(s, current, legacy),
			})
		}
		w.JSON(map[string]any{"stamps": rows, "current_root": current})
		return nil
	}

	if len(stamps) == 0 {
		w.Human("no timestamps\n")
		return nil
	}
	live := false
	for _, s := range stamps {
		mark := ""
		if covers(s, current, legacy) {
			mark = green + "  ← covers what is live now" + reset
			live = true
		}
		if s.Anchor != nil {
			mark += "  " + dim + "anchored: " + describeStampAnchor(s.Anchor) + reset
		}
		w.Human("  %s  %s  %s%s\n", s.RequestedAt, short(s.Root), s.Authority, mark)
	}
	// Said plainly: a stamp of an older root proves what the site used to say,
	// which is a different claim from proving what it says now.
	if !live && current != "" {
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
