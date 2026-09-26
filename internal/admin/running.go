// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"sort"
	"time"

	"github.com/quilzo/quilzo/internal/feed"
	"github.com/quilzo/quilzo/internal/flow"
	"github.com/quilzo/quilzo/internal/proving"
	"github.com/quilzo/quilzo/internal/source"
)

// Four capabilities, one question.
//
// internal/admin/assurance.go already made this argument about evidence:
// terminal-only is close to the worst place for it, because the person who
// has to answer for a system is not usually the person with a shell on the
// box. The same is true of operation, and more urgently, because these
// four all fail in the same direction.
//
// A feed that stopped updating reports no vulnerabilities. A log source
// that changed shape produces events with empty fields that match no
// detection. An automation whose filter started matching everything runs
// perfectly and does nothing. A detection estate full of rules that never
// fire looks exactly like an estate with nothing to find.
//
// Every one of those looks like a quiet week, and the longer each goes on
// the more reassuring it becomes. So they belong on one screen, and the
// screen's job is not to show that things are fine — it is to distinguish
// fine from silent, which is the distinction none of them can make alone.

// Running is what the operational screens need, each supplied by whatever
// wired this server up.
//
// Every field may be nil, and the screen says which rather than rendering
// an empty section. This is assurance.go's rule and it matters twice as
// much here: an empty list of stale feeds and a build that cannot see any
// feeds are the same picture and opposite facts.
type Running struct {
	// Feeds is the freshness of every database a scanner compares against.
	Feeds func() ([]feed.Attestation, error)
	// Sources is the health of every log mapping, across recent batches.
	Sources func() ([]source.Health, error)
	// Flows is what is wrong with the automations, already ranked.
	Flows func() ([]flow.Trouble, error)
	// Estate is what the live detections cost an analyst per day, and the
	// loudest of them — because a queue nobody can work is made of a few
	// rules rather than of all of them, and naming those few is the whole
	// of the fix.
	Estate func() (proving.Noise, []*proving.Candidate, error)
}

// quiet is one thing that is silent when it should not be, for the
// summary at the top of the screen.
//
// Collected rather than counted: "four things are quiet" is a number
// somebody acknowledges, and naming them is what makes one of them get
// looked at.
type quiet struct {
	What   string
	Detail string
	Bad    bool
}

func (s *Server) handleRunningScreen(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	data := map[string]any{
		"Nav": "security", "Title": "Is it running", "Principal": p,
	}
	if s.Running == nil {
		data["Unavailable"] = "This build was started without the " +
			"operational capabilities wired in. An empty screen here " +
			"would read as everything being fine, which is the one thing " +
			"it must not do."
		s.render(w, r, "running.html", data)
		return
	}
	now := time.Now().UTC()
	var worries []quiet
	var missing []string

	if s.Running.Feeds == nil {
		missing = append(missing, "feed freshness")
	} else if atts, err := s.Running.Feeds(); err != nil {
		missing = append(missing, "feed freshness: "+err.Error())
	} else {
		sort.SliceStable(atts, func(i, j int) bool {
			if atts[i].Stale != atts[j].Stale {
				return atts[i].Stale
			}
			return atts[i].Age > atts[j].Age
		})
		data["Feeds"] = atts
		for _, a := range atts {
			if !a.Stale {
				continue
			}
			worries = append(worries, quiet{
				What: a.Feed + " is behind", Detail: a.Says(), Bad: true,
			})
		}
	}

	if s.Running.Sources == nil {
		missing = append(missing, "log source health")
	} else if hs, err := s.Running.Sources(); err != nil {
		missing = append(missing, "log source health: "+err.Error())
	} else {
		sort.SliceStable(hs, func(i, j int) bool {
			if hs[i].Drifted != hs[j].Drifted {
				return hs[i].Drifted
			}
			return hs[i].Share > hs[j].Share
		})
		data["Sources"] = hs
		for _, h := range hs {
			if !h.Drifted && !h.Quiet {
				continue
			}
			worries = append(worries, quiet{
				What: h.Source + " is not mapping", Detail: h.Why,
				Bad: h.Drifted,
			})
		}
	}

	if s.Running.Flows == nil {
		missing = append(missing, "automation ledgers")
	} else if tr, err := s.Running.Flows(); err != nil {
		missing = append(missing, "automation ledgers: "+err.Error())
	} else {
		data["Flows"] = tr
		for _, t := range tr {
			if t.Weight < flow.Discarding {
				continue
			}
			worries = append(worries, quiet{
				What: t.Flow + ": " + t.What, Detail: t.Detail,
				Bad: t.Weight >= flow.Silent,
			})
		}
	}

	if s.Running.Estate == nil {
		missing = append(missing, "the detection estate")
	} else if noise, loudest, err := s.Running.Estate(); err != nil {
		missing = append(missing, "the detection estate: "+err.Error())
	} else {
		if len(loudest) > 8 {
			loudest = loudest[:8]
		}
		data["Noise"], data["Loudest"] = noise, loudest
		if noise.Rules == 0 {
			worries = append(worries, quiet{
				What: "nothing is live",
				Detail: "no detection has reached live, so every event " +
					"arriving is being evaluated against nothing. That is " +
					"a quiet dashboard and an empty one.",
				Bad: true,
			})
		}
	}

	data["Worries"], data["Missing"], data["As"] = worries, missing, now
	s.render(w, r, "running.html", data)
}
