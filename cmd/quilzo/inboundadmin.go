// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/inbound"
)

var feedKindWords = map[string]string{
	inbound.Okta: "Okta event hook", inbound.SSF: "Shared signals",
	inbound.Webhook: "Signed webhook", inbound.GitHub: "GitHub webhook",
}

// snapshot is the live status, copied, for the screen.
func (s *inboundServer) snapshot() map[string]inboundStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]inboundStatus{}
	for k, v := range s.status {
		c := *v
		c.Seen = nil
		c.Recent = append([]signalRow(nil), v.Recent...)
		out[k] = c
	}
	return out
}

// feedsHooks is the Feeds screen's way into the program: the same files and
// the same code the inbound command uses.
func feedsHooks(root string, inb *inboundServer) *admin.FeedsAdmin {
	return &admin.FeedsAdmin{
		List: func() ([]admin.FeedView, error) {
			feeds, err := loadFeeds(root)
			if err != nil {
				return nil, err
			}
			live := inb.snapshot()
			var out []admin.FeedView
			for _, n := range feedNames(feeds) {
				f := feeds[n]
				st := live[n]
				v := admin.FeedView{Name: n, Kind: f.Kind, KindWords: feedKindWords[f.Kind], Path: "/feeds/" + n,
					Off: f.Off, Issuer: f.Issuer, Stream: f.StreamID, Status: f.Status, Mapping: f.Mapping,
					Deliveries: st.Deliveries, Records: st.Records, Stored: st.Stored, Known: st.Known,
					Missed: st.Missed, Signals: st.Signals, Refused: st.Refused, Why: st.Why,
					Error: st.Error, Field: st.Field}
				if !f.Verified.IsZero() {
					v.Verified = f.Verified.UTC().Format("2 Jan 15:04")
				}
				if !st.LastAt.IsZero() {
					v.Last = st.LastAt.UTC().Format("2 Jan 15:04")
				}
				if !st.LastRefuse.IsZero() {
					v.LastRefused = st.LastRefuse.UTC().Format("2 Jan 15:04")
				}
				for _, r := range st.Recent {
					words := signalWords[r.Type]
					if words == "" {
						words = r.Type
					}
					tone := map[string]string{"high": "bad", "medium": "warning"}[r.Severity]
					if tone == "" {
						tone = "unknown"
					}
					v.Recent = append(v.Recent, admin.FeedSignal{At: r.At.UTC().Format("2 Jan 15:04"),
						Type: r.Type, Words: strings.ToUpper(words[:1]) + words[1:], Person: r.Person,
						Severity: r.Severity, Tone: tone, Reason: r.Reason})
				}
				out = append(out, v)
			}
			return out, nil
		},
		Mappings: func() []string {
			all, err := allSources(root)
			if err != nil {
				return nil
			}
			var out []string
			for _, s := range all {
				out = append(out, s.Issuer+"/"+s.Stream)
			}
			sort.Strings(out)
			return out
		},
		Add: func(kind, name, mapping, issuer, publicURL, alias, by string) ([]string, error) {
			_, shown, err := makeFeed(root, kind, name, map[string]string{"mapping": mapping, "issuer": issuer,
				"url": publicURL, "alias": alias}, by)
			return shown, err
		},
		SetOff: func(name string, off bool, _ string) error {
			return changeFeed(root, name, func(f *inbound.Feed) error { f.Off = off; return nil })
		},
		Remove: func(name, _ string) error {
			_, err := removeFeed(root, name)
			return err
		},
	}
}
