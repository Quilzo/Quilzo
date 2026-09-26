// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/quilzo/quilzo/internal/feed"
)

// The databases a scanner is only as good as.
//
// A vulnerability scanner is a comparison between an inventory and a list.
// The inventory is measured; the list is fetched from somebody else, and
// everything about the answer depends on how recently.
//
// A scanner whose database stopped updating three months ago reports no
// vulnerabilities. So does a system with no vulnerabilities. They are the
// same screen, and the longer it goes on the more reassuring it looks.
//
// `feed status` shows what is behind and whose problem each one is.

func cmdFeed(args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		return feedStatus(args[1:])
	default:
		return fmt.Errorf("unknown feed command %q; try status", args[0])
	}
}

func feedStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	behind := fs.Duration("behind", 74*time.Hour,
		"how long ago the last fetch of each feed was, for the example")
	if err := fs.Parse(args); err != nil {
		return err
	}
	now := time.Now().UTC()

	s := &feed.Set{}
	for _, f := range feed.Known() {
		m, err := s.Add(f)
		if err != nil {
			return err
		}
		switch f.Name {
		case "osv":
			// Current, and signed by nobody.
			if err := m.Take(feed.Release{Feed: f.Name,
				Version: now.Format("2006-01-02T15"), Fetched: now,
				Published: now, Digest: feed.Digest([]string{"a"}),
				Entries: 41_882, Partial: true}); err != nil {
				return err
			}
		case "epss":
			// Behind, and the source publishes daily, so how far behind
			// is a number.
			at := now.Add(-*behind)
			if err := m.Take(feed.Release{Feed: f.Name,
				Version: at.Format("2006-01-02"), Fetched: at,
				Published: at, Digest: feed.Digest([]string{"b"}),
				Entries: 284_311}); err != nil {
				return err
			}
			m.Missed(now.Add(-2*time.Hour),
				fmt.Errorf("connection refused"))
		case "kev":
			// Behind, and the source has no schedule, so how far behind
			// is not a number anybody has.
			at := now.Add(-*behind)
			if err := m.Take(feed.Release{Feed: f.Name,
				Version: at.Format("2006-01-02"), Fetched: at,
				Digest: feed.Digest([]string{"c"}), Entries: 1_665,
			}); err != nil {
				return err
			}
		case "sigma":
			// Fetched, from a source that signs, and it did not verify.
			if err := m.Take(feed.Release{Feed: f.Name, Version: "r2026-09-20",
				Fetched: now.Add(-time.Hour), Published: now.Add(-2 * time.Hour),
				Digest: feed.Digest([]string{"d"}), Entries: 3_760,
				Why: "the signing key rotated and the new one is not " +
					"pinned yet"}); err != nil {
				return err
			}
		}
	}

	if w.JSON(map[string]any{
		"attestations": s.Attest(now), "trouble": s.Look(now),
	}) {
		return nil
	}

	w.Human("%swhat the scanner is working from%s\n\n", bold, reset)
	for _, a := range s.Attest(now) {
		colour := green
		if a.Stale {
			colour = yellow
		}
		w.Human("  %s%-7s%s %s%s%s\n", colour, a.Feed, reset, dim,
			wrapAt(a.Says(), 62, "          "), reset)
	}
	w.Human("\n")

	ok, why := s.Trustworthy(now)
	if !ok {
		w.Human("  %s%s%s\n\n", yellow, wrapAt(why, 66, "  "), reset)
	}

	w.Human("%swhat is wrong, and whose it is%s\n", bold, reset)
	for _, t := range s.Look(now) {
		w.Human("  %s%-3d%s %s — %s\n", dim, t.Weight, reset, t.Feed,
			t.What)
		if t.Detail != "" {
			w.Human("      %s%s%s\n", dim, wrapAt(t.Detail, 60, "      "),
				reset)
		}
	}
	w.Human("\n  %s\"we have not fetched\" and \"they have not published\" "+
		"are\n  different facts with different owners, and conflating them "+
		"is\n  why staleness alerts get ignored. The exploited catalogue "+
		"has\n  no fixed schedule at all, so a quiet week says nothing — "+
		"which\n  is why nothing here invents a cadence for it%s\n",
		dim, reset)
	return nil
}
