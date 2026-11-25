// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/seckit"
)

// Freshness: whether each source is still reporting.
//
// Silent failure is how this goes wrong: a connector whose credential
// expired returns nothing, and nothing reads as an estate where everything
// is fine. So every source declares how often it should report, a source
// that has not is stale and named with its age wherever the record's
// posture is shown, and its owner is told, once each time it goes stale,
// so that a mailbox is not filled by a quarter-hour timer.
//
// A source reports when a file is sealed under it: a connector's run, a
// pipeline's push, a person's upload. A run that read exactly what the last
// one read still seals a new document, dated, so it still reports.

// Standing is how one source stands.
type Standing struct {
	ID     register.ID     `json:"id"`
	Source register.Source `json:"source"`
	// Last is when it last reported, zero when it never has.
	Last time.Time `json:"last,omitzero"`
	// Reports is how many files were sealed under it.
	Reports int `json:"reports"`
	// Stale says it has not reported within its window, and Since is when
	// it went stale: its last report, or when it was added, and the window.
	Stale bool      `json:"stale"`
	Since time.Time `json:"since,omitzero"`
	// Age is how long ago it last reported, or was added when it never
	// has, in words.
	Age string `json:"age"`
	// Said is the line code writes about it, for the Posture of record and
	// the owner's mail.
	Said string `json:"said"`
	// Attempt is what its last run here did, for a connector.
	Attempt *Report `json:"attempt,omitempty"`
}

// Window is how long the source may go between reports.
func (st Standing) Window() time.Duration { return time.Duration(st.Source.Fresh) * time.Second }

// Standings is how every source stands at now, stale ones first.
func (s *Sources) Standings(now time.Time) ([]Standing, error) {
	last, counts, err := s.reports()
	if err != nil {
		return nil, err
	}
	var out []Standing
	for offset := 0; ; {
		entries, total, err := s.Reg.List(register.KindSource, offset, 200)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			src, ok := e.Record.(register.Source)
			if !ok {
				continue
			}
			st := Standing{ID: e.ID, Source: src, Last: last[e.ID], Reports: counts[e.ID]}
			from := st.Last
			if from.IsZero() {
				from = e.Created.At()
			}
			st.Since = from.Add(st.Window())
			st.Stale = !now.Before(st.Since)
			st.Age = seckit.Age(now.Sub(from))
			st.Said = said(st, now)
			if src.Type == "connector" {
				st.Attempt, _ = s.LastAttempt(src.Name)
			}
			out = append(out, st)
		}
		offset += len(entries)
		if offset >= total || len(entries) == 0 {
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Stale != out[j].Stale {
			return out[i].Stale
		}
		return out[i].Source.Name < out[j].Source.Name
	})
	return out, nil
}

// Stale is the sources that are stale at now.
func (s *Sources) Stale(now time.Time) ([]Standing, error) {
	all, err := s.Standings(now)
	if err != nil {
		return nil, err
	}
	var out []Standing
	for _, st := range all {
		if st.Stale {
			out = append(out, st)
		}
	}
	return out, nil
}

// reports is when each source last reported, and how many times: the
// newest of the times each file sealed under it was received.
func (s *Sources) reports() (map[register.ID]time.Time, map[register.ID]int, error) {
	last, counts := map[register.ID]time.Time{}, map[register.ID]int{}
	for offset := 0; ; {
		files, total, err := s.Ing.Files(offset, 200)
		if err != nil {
			return nil, nil, err
		}
		for _, f := range files {
			at := f.Record.Received.At()
			if f.Sealed != nil && f.Sealed.Last.After(at) {
				at = f.Sealed.Last
			}
			if at.After(last[f.Record.Source]) {
				last[f.Record.Source] = at
			}
			counts[f.Record.Source]++
		}
		offset += len(files)
		if offset >= total || len(files) == 0 {
			return last, counts, nil
		}
	}
}

// said is the line about a source: when it last reported and how often it
// is expected to, in words code writes from the record.
func said(st Standing, now time.Time) string {
	name := st.Source.Title
	if name == "" {
		name = st.Source.Name
	}
	every := "every " + seckit.Age(st.Window())
	switch {
	case st.Last.IsZero() && st.Stale:
		return fmt.Sprintf("%s: has never reported, added %s ago, expected %s", name, st.Age, every)
	case st.Last.IsZero():
		return fmt.Sprintf("%s: has not reported yet, expected %s", name, every)
	case st.Stale:
		return fmt.Sprintf("%s: last reported %s ago, on %s, expected %s", name, st.Age, seckit.When(st.Last), every)
	}
	return fmt.Sprintf("%s: reported %s ago, expected %s", name, st.Age, every)
}

// Alerts tells each stale source's owner, once each time it goes stale.
type Alerts struct {
	Sources *Sources
	// Mail sends one message to one address. Nil sends nothing, and the
	// tick says so.
	Mail func(to, subject, body string) error
	// Audit records each message sent, or not sent; nil records nothing.
	Audit func(audit.Record) error
}

// alerted is what has been told: for each source, the moment it went stale
// that its owner was told of. Beside the store, and naming nobody: the
// owner is the source's, by pseudonym, in the register.
type alerted struct {
	Told map[string]time.Time `json:"told"`
	// Problem is why a source's owner could not be told, kept so the tick
	// does not try a missing address every quarter of an hour.
	Problem map[string]string `json:"problem,omitempty"`
}

func (a *Alerts) path() string {
	return filepath.Join(a.Sources.Reg.Store.Root(), "sources", "alerts.json")
}

// StaleAction is the name a stale source's owner being told is recorded
// under in the audit log.
const StaleAction = "source.stale"

// Tick tells the owner of every source that is stale at now and whose
// owner has not been told since it went stale, and says how many were
// told. Run on the server's upkeep timer, it is given the loop's moment.
func (a *Alerts) Tick(now time.Time) (int, error) {
	stale, err := a.Sources.Stale(now)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(a.path()), 0o700); err != nil {
		return 0, err
	}
	unlock, err := atomicfile.Lock(a.path() + ".lock")
	if err != nil {
		return 0, err
	}
	defer unlock()
	state, err := a.load()
	if err != nil {
		return 0, err
	}
	told := 0
	var problems []string
	for _, st := range stale {
		name := st.Source.Name
		if was, ok := state.Told[name]; ok && was.Equal(st.Since) {
			continue
		}
		state.Told[name] = st.Since
		delete(state.Problem, name)
		to, why := a.address(st.Source.Owner)
		if why == "" && a.Mail == nil {
			why = "no mail relay is set up"
		}
		if why == "" {
			subject := "Quilzo: the source " + st.Source.Name + " is stale"
			if err := a.Mail(to, subject, message(st)); err != nil {
				why = "the mail could not be sent: " + err.Error()
			}
		}
		outcome := audit.Success
		detail := map[string]string{"source": name, "since": st.Since.Format(time.RFC3339)}
		if why != "" {
			state.Problem[name] = why
			problems = append(problems, name+": "+why)
			outcome, detail["problem"] = audit.Failure, why
		} else {
			told++
			if st.Source.Owner != "" {
				detail["owner"] = string(st.Source.Owner)
			}
		}
		if a.Audit != nil {
			_ = a.Audit(audit.Record{Action: StaleAction, Resource: register.Area, Outcome: outcome,
				Principal: "quilzo", Kind: audit.KindService, Verified: true, Detail: detail})
		}
	}
	// A source that reported again is forgotten, so the next time it goes
	// stale its owner is told again.
	for name := range state.Told {
		if !isStale(stale, name) {
			delete(state.Told, name)
			delete(state.Problem, name)
		}
	}
	if err := a.save(state); err != nil {
		return told, err
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return told, fmt.Errorf("a stale source's owner was not told: %s", strings.Join(problems, "; "))
	}
	return told, nil
}

func isStale(stale []Standing, name string) bool {
	for _, st := range stale {
		if st.Source.Name == name {
			return true
		}
	}
	return false
}

// address is the owner's mail address, from the subject map, or why there
// is none.
func (a *Alerts) address(owner register.ID) (string, string) {
	if owner == "" {
		return "", "it has no owner to tell; name one with quilzo source owner"
	}
	p, err := a.Sources.Reg.Person(owner)
	if err != nil {
		return "", "its owner's name is not in the subject map (erased, or never named)"
	}
	addr, err := mail.ParseAddress(p.Name)
	if err != nil || addr.Name != "" || !strings.Contains(addr.Address, "@") {
		return "", "its owner is known by a name that is not a mail address"
	}
	return addr.Address, ""
}

// message is the mail, in words code writes from the source's record.
func message(st Standing) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s.\n\n", st.Said)
	fmt.Fprintf(&b, "Its facts are older than the %s it says they may be, so the Posture of record and the Sources "+
		"screen name it as stale until it reports again.\n\n", seckit.Age(st.Window()))
	switch st.Source.Type {
	case "connector":
		b.WriteString("Run it to see why: quilzo source run " + st.Source.Name + "\n")
		if st.Attempt != nil && st.Attempt.Problem != "" {
			b.WriteString("Its last run said: " + oneLine(st.Attempt.Problem) + "\n")
		}
	case "ci":
		b.WriteString("Its pipeline, in " + st.Source.Repository + ", has not pushed from " + st.Source.Workflow + ".\n")
	default:
		b.WriteString("Bring in a newer file: quilzo ingest FORMAT FILE --source " + st.Source.Name + "\n")
	}
	b.WriteString("\nYou are told once each time it goes stale.\n")
	return b.String()
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:297] + "..."
	}
	return s
}

func (a *Alerts) load() (alerted, error) {
	st := alerted{Told: map[string]time.Time{}, Problem: map[string]string{}}
	b, err := os.ReadFile(a.path())
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("%s is unreadable: %w", a.path(), err)
	}
	if st.Told == nil {
		st.Told = map[string]time.Time{}
	}
	if st.Problem == nil {
		st.Problem = map[string]string{}
	}
	return st, nil
}

func (a *Alerts) save(st alerted) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.path()), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(a.path(), append(b, '\n'), 0o600)
}
