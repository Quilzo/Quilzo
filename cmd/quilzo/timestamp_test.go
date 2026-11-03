// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/quilzo/quilzo/internal/anchor"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/render"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/timestamp"
)

// publishedStore is a store with one publication live, and its commit id.
func publishedStore(t *testing.T) (string, string) {
	t.Helper()
	root := connectStore(t)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home"},
		"terms": map[string]any{"title": "Terms"},
	}, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	live := s.GetRef(site.RefLive)
	if len(live) != 64 {
		t.Fatalf("the live commit id is %q", live)
	}
	return root, live
}

// listStamps is `quilzo timestamp list --json`.
func listStamps(t *testing.T, root string) (doc struct {
	Stamps []struct {
		Root     string `json:"root"`
		Anchored bool   `json:"anchored"`
		Covers   bool   `json:"covers_current"`
	} `json:"stamps"`
	Current string `json:"current_root"`
}) {
	t.Helper()
	old := w
	t.Cleanup(func() { w = old })
	var buf bytes.Buffer
	w = out.New(true)
	w.Out = &buf
	if err := stampList(root); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("%v: %s", err, buf.String())
	}
	return doc
}

// `timestamp stamp` sent an authority the display fingerprint, SHA-256 cut
// to sixteen hex characters, while `anchor submit` commits to the full live
// commit id because a truncated hash is a weaker claim than it looks. The
// two never named the same subject, so a receipt and an anchor of one
// publication could not be joined.
func TestAStampIsOverWhatAnAnchorCommitsTo(t *testing.T) {
	root, live := publishedStore(t)
	stamped, err := publishedRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	anchored, err := liveFingerprint(root)
	if err != nil {
		t.Fatal(err)
	}
	if stamped != anchored || stamped != live {
		t.Fatalf("a stamp is over %q and an anchor over %q; the live commit is %q",
			stamped, anchored, live)
	}
}

// Stamp.Anchor was declared and never set, so every stamp said "no
// blockchain anchor" and "anchored": false, and the Integrity screen showed
// nothing, while `anchor submit` had anchored the same publication. A stamp
// is joined to the anchors of its own subject.
func TestAStampShowsTheAnchorOfItsPublication(t *testing.T) {
	root, live := publishedStore(t)
	if err := saveJSON(stampPath(root), &timestamp.Store{Stamps: []timestamp.Stamp{{
		Root: live, Authority: timestamp.DefaultTSA, Token: []byte{0x30},
		RequestedAt: "2026-11-01T10:00:00Z"}}}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(anchorPath(root), &anchorFile{Proofs: []anchor.Proof{{
		Digest: live, Calendar: anchor.Calendars[0], State: anchor.Pending,
		SubmittedAt: "2026-11-01T10:01:00Z"}}}); err != nil {
		t.Fatal(err)
	}

	doc := listStamps(t, root)
	if len(doc.Stamps) != 1 || !doc.Stamps[0].Anchored {
		t.Errorf("the stamp of an anchored publication says it is not anchored: %+v", doc.Stamps)
	}

	rows, err := evidenceRows(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Kind == "timestamp" && r.Detail == "" {
			t.Errorf("the Integrity screen shows no anchor for a stamp whose publication is anchored")
		}
	}

	st, err := loadStamps(root)
	if err != nil {
		t.Fatal(err)
	}
	joined := joinAnchors(root, st.Stamps)
	if len(joined) != 1 || joined[0].Anchor == nil {
		t.Fatal("the stamp was not joined to the anchor of its subject")
	}
	if got := timestamp.Describe(joined[0]); bytes.Contains([]byte(got), []byte("no blockchain anchor")) {
		t.Errorf("a stamp of an anchored publication describes itself as unanchored:\n%s", got)
	}
}

// A stamp made before the subject changed is over the display fingerprint.
// It is still read, and still said to cover what is live when the content
// has not changed since.
func TestAStampOfTheOldFingerprintStillReads(t *testing.T) {
	root, _ := publishedStore(t)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	old := public.New(s, render.Layouts{}).Fingerprint()
	if err := saveJSON(stampPath(root), &timestamp.Store{Stamps: []timestamp.Stamp{{
		Root: old, Authority: timestamp.DefaultTSA, Token: []byte{0x30},
		RequestedAt: "2026-10-01T10:00:00Z"}}}); err != nil {
		t.Fatal(err)
	}
	doc := listStamps(t, root)
	if len(doc.Stamps) != 1 || doc.Stamps[0].Root != old {
		t.Fatalf("the old stamp did not read back: %+v", doc.Stamps)
	}
	if !doc.Stamps[0].Covers {
		t.Error("a stamp of the fingerprint of what is live no longer says it covers it")
	}
}
