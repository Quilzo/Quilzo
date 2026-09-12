// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package checked records that somebody confirmed a page is still true.
//
// # The question nothing here could answer
//
// "When did anybody last look at this?" A page is written, published, and then
// sits there. Prices change, a law changes, the person named on the contact
// page leaves, and nothing in the tool says so — because nothing distinguishes
// a page that is right from a page that nobody has read in three years.
//
// It is the most ordinary content-governance requirement there is, and the one
// this program had no answer for: the history says when a page was last
// *edited*, which is a different question. A page that has not been edited in
// three years is either perfectly accurate or badly out of date, and the
// history cannot tell you which.
//
// # Why the record carries a hash
//
// The same reason collab.Approval and note.Note carry one: the thing being
// vouched for can change afterwards, and a check that silently starts applying
// to different words is worse than no check.
//
// So a check is about the page as it stood. Edit the page and the check does
// not follow it — which is right, because an edit is somebody changing the
// content and not somebody confirming it. internal/i18n already does exactly
// this for translations, recording "the hash of the source it was made from,
// so staleness is exact".
//
// # Why these are not in the store
//
// A check is a statement about content rather than content, it is superseded
// by the next one, and the store cannot forget. Same conclusion as
// internal/form and internal/note, reached the same way.
//
// # Why an interval and not a date
//
// A due date has to be moved by hand every time, so it stops being moved. An
// interval is set once — "this needs looking at twice a year" — and the due
// date follows from the last check. The default is configuration, so a site
// with one answer for everything sets it once and names nothing per page.
package checked

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// A Record is one confirmation that a page was right.
type Record struct {
	Page string `json:"page"`
	// Content is the hash of what was checked. See the package comment.
	Content string `json:"content"`
	By      string `json:"by"`
	At      int64  `json:"at"`
	// Every is how long until it should be looked at again, as a duration
	// string. Empty means the site's default applies, which is the ordinary
	// case: most sites have one answer.
	Every string `json:"every,omitempty"`
	// Note is what they want the next person to know. Optional, and the part
	// that makes a record worth reading rather than counting.
	Note string `json:"note,omitempty"`
}

// Interval is how long this page may go unchecked.
func (r Record) Interval(fallback time.Duration) time.Duration {
	if strings.TrimSpace(r.Every) == "" {
		return fallback
	}
	d, err := time.ParseDuration(r.Every)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// Due is when this page should next be looked at.
func (r Record) Due(fallback time.Duration) time.Time {
	return time.Unix(r.At, 0).Add(r.Interval(fallback))
}

// State is what to say about a page.
type State string

const (
	// Fresh means somebody checked it and it has not changed or expired.
	Fresh State = "fresh"
	// Changed means it was edited after it was checked, so the check is about
	// words that are no longer there. Reported separately from Overdue
	// because the remedy is different: this one needs reading, not chasing.
	Changed State = "changed"
	// Overdue means the interval has passed.
	Overdue State = "overdue"
	// Never means nobody has ever said it was right.
	Never State = "never"
)

// Status says where a page stands.
//
// nowHash is the page as it is now, and may be empty when the page is not in
// the set being looked at — in which case the change cannot be tested and is
// not claimed, the same way note.Stale treats an unknown anchor.
func Status(r Record, nowHash string, fallback time.Duration, now time.Time) State {
	if r.At == 0 {
		return Never
	}
	// Changed before Overdue. A page that was edited last week and is also
	// past its interval needs somebody to read the edit, and saying "overdue"
	// sends them to look for something that has already happened.
	if r.Content != "" && nowHash != "" && r.Content != nowHash {
		return Changed
	}
	if now.After(r.Due(fallback)) {
		return Overdue
	}
	return Fresh
}

// NeedsAttention reports whether a state is one somebody has to act on.
func NeedsAttention(s State) bool { return s != Fresh }

// Store is a directory of records, one per page.
//
// One per page and not a history: the question is "when was this last
// confirmed", and every earlier answer is superseded by the latest. The audit
// log holds the sequence for anybody who needs it, which is where a sequence
// belongs.
type Store struct{ dir string }

// Open makes the directory if it is not there.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// path builds a record's file, refusing anything that could leave the
// directory.
//
// A page name arrives from content and becomes a path segment, so it is
// checked where the path is built — the only place that can be sure.
func (st *Store) path(page string) (string, error) {
	if page == "" || strings.ContainsAny(page, `\:`) || strings.Contains(page, "..") {
		return "", fmt.Errorf("%q is not a usable page name", page)
	}
	for _, part := range strings.Split(page, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("%q is not a usable page name", page)
		}
	}
	p := filepath.Join(st.dir, filepath.FromSlash(page)+".json")
	if !strings.HasPrefix(filepath.Clean(p), filepath.Clean(st.dir)+string(filepath.Separator)) {
		return "", fmt.Errorf("%q is not a usable page name", page)
	}
	return p, nil
}

// Set records a check, replacing whatever was there.
func (st *Store) Set(r Record, now time.Time) (Record, error) {
	if strings.TrimSpace(r.Page) == "" {
		return Record{}, fmt.Errorf("a check has to be about a page")
	}
	if strings.TrimSpace(r.By) == "" {
		// Named, always. "This was confirmed correct" with nobody behind it is
		// a claim nobody can follow up, which is the whole point of recording
		// it rather than assuming it.
		return Record{}, fmt.Errorf(
			"a check records who made it; somebody has to be askable")
	}
	if e := strings.TrimSpace(r.Every); e != "" {
		d, err := time.ParseDuration(e)
		if err != nil {
			return Record{}, fmt.Errorf(
				"%q is not a length of time. Try 168h for a week, or 8760h "+
					"for a year", e)
		}
		if d <= 0 {
			return Record{}, fmt.Errorf(
				"an interval of %s means the page is overdue the moment it is "+
					"checked", e)
		}
	}
	p, err := st.path(r.Page)
	if err != nil {
		return Record{}, err
	}
	r.At = now.Unix()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return Record{}, err
	}
	body, err := json.Marshal(r)
	if err != nil {
		return Record{}, err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return Record{}, err
	}
	return r, os.Rename(tmp, p)
}

// Get reads a page's record. A page nobody has checked returns the zero
// Record and no error: not having been checked is an ordinary state, not a
// failure to look something up.
func (st *Store) Get(page string) (Record, error) {
	p, err := st.path(page)
	if err != nil {
		return Record{}, err
	}
	body, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return Record{}, nil
	}
	if err != nil {
		return Record{}, err
	}
	var r Record
	if err := json.Unmarshal(body, &r); err != nil {
		return Record{}, nil
	}
	return r, nil
}

// All reads every record, by page.
func (st *Store) All() (map[string]Record, error) {
	out := map[string]Record{}
	err := filepath.WalkDir(st.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		body, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		var r Record
		if json.Unmarshal(body, &r) == nil && r.Page != "" {
			out[r.Page] = r
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return out, nil
}

// Clear removes a page's record.
//
// For a page that was deleted, and for a check somebody should not have made.
func (st *Store) Clear(page string) error {
	p, err := st.path(page)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// A Row is a page and where it stands, for a listing.
type Row struct {
	Page  string `json:"page"`
	State State  `json:"state"`
	// By and At describe the last check, empty when there was none.
	By   string `json:"by,omitempty"`
	At   int64  `json:"at,omitempty"`
	Note string `json:"note,omitempty"`
	// Due is when it is next wanted, zero when nobody has checked it.
	Due int64 `json:"due,omitempty"`
}

// Survey reports where every page stands, worst first.
//
// hashes is each page's current hash, which is what makes Changed detectable.
// Pages with no hash are still reported: a page that exists and has never been
// checked is the thing this is for.
func Survey(pages []string, hashes map[string]string, records map[string]Record,
	fallback time.Duration, now time.Time) []Row {

	out := make([]Row, 0, len(pages))
	for _, page := range pages {
		r := records[page]
		row := Row{
			Page:  page,
			State: Status(r, hashes[page], fallback, now),
			By:    r.By, At: r.At, Note: r.Note,
		}
		if r.At != 0 {
			row.Due = r.Due(fallback).Unix()
		}
		out = append(out, row)
	}

	// Worst first, so a list somebody skims puts the thing to act on at the
	// top. Within a state, oldest check first — the page nobody has looked at
	// for longest is the one to look at next.
	rank := map[State]int{Never: 0, Overdue: 1, Changed: 2, Fresh: 3}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].State] != rank[out[j].State] {
			return rank[out[i].State] < rank[out[j].State]
		}
		if out[i].At != out[j].At {
			return out[i].At < out[j].At
		}
		return out[i].Page < out[j].Page
	})
	return out
}
