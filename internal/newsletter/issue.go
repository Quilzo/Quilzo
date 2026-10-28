// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package newsletter

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Issues: a published page sent to the list, or proposed by an agent for a
// person to send.
//
// # Sent once to each address, and able to stop
//
// Each address an issue reaches is written down as the relay accepts the
// message, before the next is sent. A send that stops, because the relay
// failed or the program was stopped, goes on from there when it is
// continued, and an address is not sent the same issue twice. The one gap
// is a crash between the relay accepting a message and the line being
// written: that address may get it twice, which is the side to err on.
//
// # An agent proposes, a person sends
//
// Mail to everybody on the list cannot be taken back, so an agent may
// propose an issue, with the page and the subject, and a person sends it
// from the Newsletter screen after sending themselves a test.

// Issue states.
const (
	Proposed  = "proposed"
	Sending   = "sending"
	Stopped   = "stopped"
	Sent      = "sent"
	Dismissed = "dismissed"
)

// Issue is one newsletter.
type Issue struct {
	ID      string `json:"id"`
	Page    string `json:"page"`
	Subject string `json:"subject"`
	State   string `json:"state"`
	// Proposed is when an agent proposed it, By which agent, and Note what
	// it said about it.
	Proposed time.Time `json:"proposed,omitempty"`
	By       string    `json:"by,omitempty"`
	Note     string    `json:"note,omitempty"`
	// SentBy is the person who sent it.
	SentBy   string    `json:"sent_by,omitempty"`
	Started  time.Time `json:"started,omitempty"`
	Finished time.Time `json:"finished,omitempty"`
	// To is how many confirmed addresses it was for; Sent how many the
	// relay accepted; Failed how many it refused this time round.
	To     int `json:"to"`
	Sent   int `json:"sent"`
	Failed int `json:"failed"`
	// Problem is the last refusal, as the relay put it.
	Problem string `json:"problem,omitempty"`
}

// MaxProposed bounds the issues waiting for a person, so an agent in a loop
// fills a short list and not a disk.
const MaxProposed = 20

var reIssue = regexp.MustCompile(`^\d{8}-[0-9a-f]{8}$`)

// ValidIssue says whether a string is an issue's id.
func ValidIssue(id string) bool { return reIssue.MatchString(id) }

func (l *List) issuePath(id string) string { return filepath.Join(l.dir, "issues", id+".json") }
func (l *List) reachedPath(id string) string {
	return filepath.Join(l.dir, "issues", id+".sent")
}

// NewIssue starts an issue: proposed by an agent, or about to be sent by a
// person.
func (l *List) NewIssue(page, subject, state, by, note string, now time.Time) (Issue, error) {
	subject = clip(oneLine(subject), 200)
	if subject == "" {
		return Issue{}, errors.New("an issue needs a subject")
	}
	if strings.TrimSpace(page) == "" {
		return Issue{}, errors.New("an issue is a published page; name it")
	}
	if state == Proposed {
		open, err := l.Issues()
		if err != nil {
			return Issue{}, err
		}
		n := 0
		for _, is := range open {
			if is.State == Proposed {
				n++
			}
		}
		if n >= MaxProposed {
			return Issue{}, fmt.Errorf("%d issues are already waiting for a person; send or dismiss some first", n)
		}
	}
	raw := make([]byte, 4)
	if _, err := rand.Read(raw); err != nil {
		return Issue{}, err
	}
	is := Issue{ID: now.UTC().Format("20060102") + "-" + hex.EncodeToString(raw), Page: page,
		Subject: subject, State: state, Note: clip(oneLine(note), 600)}
	if state == Proposed {
		is.Proposed, is.By = now.UTC(), by
	} else {
		is.SentBy = by
	}
	return is, l.SaveIssue(is)
}

// SaveIssue keeps an issue.
func (l *List) SaveIssue(is Issue) error {
	if !ValidIssue(is.ID) {
		return fmt.Errorf("%q is not an issue", is.ID)
	}
	body, err := json.MarshalIndent(is, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(l.issuePath(is.ID), append(body, '\n'), 0o600)
}

// Issue reads one issue.
func (l *List) Issue(id string) (Issue, error) {
	if !ValidIssue(id) {
		return Issue{}, fmt.Errorf("there is no issue %q", id)
	}
	body, err := os.ReadFile(l.issuePath(id))
	if errors.Is(err, os.ErrNotExist) {
		return Issue{}, fmt.Errorf("there is no issue %q", id)
	}
	if err != nil {
		return Issue{}, err
	}
	var is Issue
	if err := json.Unmarshal(body, &is); err != nil {
		return Issue{}, fmt.Errorf("issue %s: %w", id, err)
	}
	return is, nil
}

// Issues is every issue, the newest first.
func (l *List) Issues() ([]Issue, error) {
	names, err := filepath.Glob(filepath.Join(l.dir, "issues", "*.json"))
	if err != nil {
		return nil, err
	}
	var out []Issue
	for _, n := range names {
		is, err := l.Issue(strings.TrimSuffix(filepath.Base(n), ".json"))
		if err != nil {
			continue
		}
		out = append(out, is)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// Reached is the ids an issue has been sent to.
func (l *List) Reached(id string) (map[string]bool, error) {
	f, err := os.Open(l.reachedPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); ValidID(line) {
			out[line] = true
		}
	}
	return out, sc.Err()
}

func (l *List) reached(f *os.File, id string) error {
	if _, err := f.WriteString(id + "\n"); err != nil {
		return err
	}
	return f.Sync()
}

// Deliver sends an issue to one address.
type Deliver func(Subscriber) error

// GiveUpAfter is how many refusals in a row stop a send: the relay is
// down, or has stopped taking mail from this site, and carrying on would
// only add to the list of refusals.
const GiveUpAfter = 5

// Send sends an issue to every confirmed address it has not reached, one
// at a time, pace apart, until it is done, stop is closed, or the relay
// refuses GiveUpAfter in a row. progress is told after each message. Two
// sends of one issue wait for each other, and the second finds nobody
// left to send to.
func (l *List) Send(id, by string, deliver Deliver, pace time.Duration, now func() time.Time,
	stop <-chan struct{}, progress func(Issue)) (Issue, error) {
	unlock, err := atomicfile.Lock(filepath.Join(l.dir, "issues", id+".lock"))
	if err != nil {
		return Issue{}, err
	}
	defer unlock()
	is, err := l.Issue(id)
	if err != nil {
		return is, err
	}
	if is.State == Dismissed {
		return is, errors.New("that issue was dismissed")
	}
	reached, err := l.Reached(id)
	if err != nil {
		return is, err
	}
	ids, err := l.ConfirmedIDs()
	if err != nil {
		return is, err
	}
	var todo []string
	for _, sid := range ids {
		if !reached[sid] {
			todo = append(todo, sid)
		}
	}
	is.State, is.Failed, is.Problem = Sending, 0, ""
	is.To = len(reached) + len(todo)
	is.Sent = len(reached)
	if is.Started.IsZero() {
		is.Started = now().UTC()
	}
	if by != "" {
		is.SentBy = by
	}
	if err := l.SaveIssue(is); err != nil {
		return is, err
	}
	log, err := os.OpenFile(l.reachedPath(id), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return is, err
	}
	defer log.Close()

	refused := 0
	finish := func(state string) (Issue, error) {
		is.State = state
		if state == Sent {
			is.Finished = now().UTC()
		}
		return is, l.SaveIssue(is)
	}
	for i, sid := range todo {
		select {
		case <-stop:
			return finish(Stopped)
		default:
		}
		s, err := l.read(sid)
		if errors.Is(err, ErrNotFound) || (err == nil && s.Confirmed.IsZero()) {
			// Left, or was removed, while this was sending.
			is.To--
			continue
		}
		if err != nil {
			return is, err
		}
		if err := deliver(s); err != nil {
			is.Failed++
			is.Problem = clip(oneLine(err.Error()), 300)
			refused++
			if refused >= GiveUpAfter {
				_, _ = finish(Stopped)
				return is, fmt.Errorf("stopped after %d refusals in a row; the last: %s", refused, is.Problem)
			}
		} else {
			refused = 0
			if err := l.reached(log, sid); err != nil {
				_, _ = finish(Stopped)
				return is, err
			}
			is.Sent++
		}
		if progress != nil {
			progress(is)
		}
		if i%20 == 19 {
			if err := l.SaveIssue(is); err != nil {
				return is, err
			}
		}
		if pace > 0 && i < len(todo)-1 {
			select {
			case <-stop:
				return finish(Stopped)
			case <-time.After(pace):
			}
		}
	}
	return finish(Sent)
}
