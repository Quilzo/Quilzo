// Package form collects what visitors send, deliberately outside the store.
//
// # The decision this package is built around
//
// Everything else here lives in a content-addressed, append-only store, and
// that is the product's central argument: nothing is overwritten, history is
// free, and any claim about the content is checkable.
//
// A form submission must not go anywhere near it.
//
// A submission is personal data. Somebody has a right to have it erased, and an
// append-only merkle store cannot erase anything — deleting an object breaks
// every hash above it, and the whole point is that those hashes are stable. A
// store that cannot forget is the right design for published content and the
// wrong one for a message from a member of the public, and putting the second
// inside the first would trade a legal obligation for an architectural
// preference.
//
// So submissions live in a plain directory of files: mutable, individually
// deletable, with a retention period that removes them without anybody asking.
// It is the least sophisticated storage in this program and that is the
// feature.
//
// # What is refused, and why not a CAPTCHA
//
// Three layers, none of which asks a person to prove anything:
//
//	A honeypot field, hidden from people and filled in by anything that
//	fills in every field it finds.
//
//	A minimum time between the form being served and the form coming back.
//	A person cannot read a form and answer it in under a second; a script
//	does it in twenty milliseconds.
//
//	A per-source rate limit, on the same limiter the rest of the program
//	uses.
//
// No CAPTCHA. WCAG 2.2 3.3.8 treats image recognition and transcription as
// cognitive function tests, and the sign-in screen already refuses to use one —
// putting one on a public contact form would apply a stricter accessibility
// standard to staff than to the public.
//
// # Fields are declared, and that is the injection story
//
// A form declares its fields and their kinds. A submitted value that does not
// satisfy its kind is refused; a submitted field nobody declared is dropped.
// There is no place where a name from the request becomes a key in something
// that matters, which is what makes this safe rather than sanitised.
package form

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Bounds. Every one of these is a refusal with a reason attached.
const (
	// MaxFields on one form.
	MaxFields = 24
	// MaxValue is the longest a single answer may be.
	MaxValue = 4000
	// MaxSubmission is the whole body, before parsing.
	MaxSubmission = 64 << 10
	// MinFillSeconds is how quickly a submission is assumed to be a script.
	// A person cannot read a form and answer it faster than this.
	MinFillSeconds = 2
	// DefaultRetentionDays is how long a submission is kept when a form does
	// not say. Ninety days: long enough to answer an enquiry, short enough
	// that a store nobody is watching does not accumulate personal data
	// forever.
	DefaultRetentionDays = 90
	// MaxRetentionDays is the ceiling. Keeping personal data for longer than
	// this needs a reason that lives somewhere other than a config file.
	MaxRetentionDays = 1825
)

var (
	reName  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	reEmail = regexp.MustCompile(`^[^@\s]+@[^@\s.]+\.[^@\s]+$`)
)

// Kind is what a field accepts. A closed set, for the same reason everything
// else here has one: a value that does not satisfy its kind is refused before
// it becomes anything.
type Kind string

const (
	Line   Kind = "line"   // one line of text
	Para   Kind = "para"   // several lines
	Email  Kind = "email"  // an address, shape-checked and never sent to
	Number Kind = "number" //
	Choice Kind = "choice" // one of a declared list
	Agree  Kind = "agree"  // a box that must be ticked
)

// Field is one thing a form asks for.
type Field struct {
	Name     string   `json:"name"`
	Label    string   `json:"label"`
	Kind     Kind     `json:"kind"`
	Required bool     `json:"required,omitempty"`
	Help     string   `json:"help,omitempty"`
	Choices  []string `json:"choices,omitempty"`
	// Sensitive marks a field whose value is not shown in listings and is
	// redacted in exports unless somebody asks for it explicitly. It does not
	// encrypt anything on its own — see the note on Form.
	Sensitive bool `json:"sensitive,omitempty"`
}

// Form is a declared set of questions.
type Form struct {
	Name   string  `json:"name"`
	Label  string  `json:"label,omitempty"`
	Intro  string  `json:"intro,omitempty"`
	Fields []Field `json:"fields"`
	// RetentionDays is how long submissions are kept. Zero means the default.
	//
	// Retention is a property of the form rather than a global setting,
	// because "how long may we keep this" is a question about what was
	// collected: an enquiry and a job application have different answers.
	RetentionDays int `json:"retention_days,omitempty"`
	// Notice is what the person is told before they send it. Required, and
	// Validate refuses a form without one — collecting personal data without
	// saying what happens to it is the thing every privacy regime is about,
	// and a field that can be left blank is a field that is blank.
	Notice string `json:"notice"`
	// Closed stops accepting submissions without deleting the form or what it
	// already gathered.
	Closed bool `json:"closed,omitempty"`
}

// Set is every form a site has.
type Set struct {
	Forms []Form `json:"forms"`
}

func (s *Set) Get(name string) (*Form, bool) {
	for i := range s.Forms {
		if s.Forms[i].Name == name {
			return &s.Forms[i], true
		}
	}
	return nil, false
}

func (s *Set) Names() []string {
	out := make([]string, 0, len(s.Forms))
	for _, f := range s.Forms {
		out = append(out, f.Name)
	}
	sort.Strings(out)
	return out
}

func (s *Set) Add(f Form) error {
	if err := f.Validate(); err != nil {
		return err
	}
	if _, exists := s.Get(f.Name); exists {
		return fmt.Errorf("there is already a form called %q", f.Name)
	}
	s.Forms = append(s.Forms, f)
	return nil
}

// Validate checks a form is usable and lawful to publish.
func (f *Form) Validate() error {
	if !reName.MatchString(f.Name) {
		return fmt.Errorf(
			"%q is not a usable form name: lowercase letters, digits and "+
				"underscores, starting with a letter", f.Name)
	}
	if strings.TrimSpace(f.Notice) == "" {
		return fmt.Errorf(
			"%q has no privacy notice. A form collecting personal data has to "+
				"say what happens to it before somebody sends it, and a field "+
				"that may be left blank is a field that is blank", f.Name)
	}
	if len(f.Fields) == 0 {
		return fmt.Errorf("%q asks nothing", f.Name)
	}
	if len(f.Fields) > MaxFields {
		return fmt.Errorf("%q has %d fields; the limit is %d",
			f.Name, len(f.Fields), MaxFields)
	}
	if f.RetentionDays < 0 || f.RetentionDays > MaxRetentionDays {
		return fmt.Errorf(
			"%q keeps submissions for %d days; the ceiling is %d. Holding "+
				"personal data longer than that needs a reason recorded "+
				"somewhere other than a configuration file",
			f.Name, f.RetentionDays, MaxRetentionDays)
	}

	seen := map[string]bool{}
	for _, fl := range f.Fields {
		if !reName.MatchString(fl.Name) {
			return fmt.Errorf("%q asks for %q, which is not a usable field name",
				f.Name, fl.Name)
		}
		if seen[fl.Name] {
			return fmt.Errorf("%q asks for %q twice", f.Name, fl.Name)
		}
		seen[fl.Name] = true
		if strings.TrimSpace(fl.Label) == "" {
			return fmt.Errorf(
				"%q has a field with no label, so nobody using a screen "+
					"reader can tell what it wants", fl.Name)
		}
		switch fl.Kind {
		case Line, Para, Email, Number, Agree:
		case Choice:
			if len(fl.Choices) == 0 {
				return fmt.Errorf("%q is a choice with nothing to choose",
					fl.Name)
			}
		default:
			return fmt.Errorf("%q has kind %q, which is not one of the "+
				"accepted kinds", fl.Name, fl.Kind)
		}
	}
	// The honeypot's name must not collide with a real field, or a person
	// filling the form in properly is treated as a bot.
	if seen[Honeypot] {
		return fmt.Errorf(
			"%q asks for %q, which is the name of the hidden field used to "+
				"catch scripts. Rename it", f.Name, Honeypot)
	}
	return nil
}

// Retention is how long this form's submissions are kept.
func (f *Form) Retention() time.Duration {
	days := f.RetentionDays
	if days <= 0 {
		days = DefaultRetentionDays
	}
	return time.Duration(days) * 24 * time.Hour
}

// Honeypot is the hidden field. Named for something a script would want to
// fill in and a person will never see.
const Honeypot = "website_url"

// StampField carries when the form was served, so a submission that arrives
// impossibly fast can be refused.
const StampField = "form_started"

// Submission is one thing somebody sent.
type Submission struct {
	ID     string            `json:"id"`
	Form   string            `json:"form"`
	At     int64             `json:"at"`
	Values map[string]string `json:"values"`
	// Source is the address it came from, kept because a rate limit and an
	// abuse investigation both need it — and it is personal data under GDPR,
	// which is why it expires with everything else rather than living in a log
	// that is never rotated.
	Source string `json:"source,omitempty"`
}

// Accept turns a submitted set of values into a submission, or refuses it.
//
// values are whatever arrived. Unknown names are dropped rather than refused:
// a browser extension adding a field, or a form served from a cached older
// version, should not make a person's message vanish.
func Accept(f *Form, values map[string]string, source string,
	now time.Time) (Submission, error) {

	if f.Closed {
		return Submission{}, fmt.Errorf(
			"%q is not accepting submissions", f.Name)
	}

	// The honeypot. A person never sees this field; anything filling in every
	// field it finds does.
	if strings.TrimSpace(values[Honeypot]) != "" {
		return Submission{}, fmt.Errorf("this submission was not accepted")
	}

	// The timing check. A person cannot read a form and answer it in under two
	// seconds; a script does it in twenty milliseconds. A missing or
	// unparseable stamp is refused rather than waved through — otherwise
	// removing the field is how the check is bypassed.
	started, err := strconv.ParseInt(strings.TrimSpace(values[StampField]), 10, 64)
	if err != nil {
		return Submission{}, fmt.Errorf("this submission was not accepted")
	}
	elapsed := now.Unix() - started
	if elapsed < MinFillSeconds {
		return Submission{}, fmt.Errorf("this submission was not accepted")
	}
	// And a stamp from the far past is a replayed form, or a page that sat
	// open for a week and is answering questions that may have changed.
	if elapsed > int64((24 * time.Hour).Seconds()) {
		return Submission{}, fmt.Errorf(
			"this form was opened more than a day ago. Reload it and send " +
				"again — the questions may have changed since")
	}

	out := Submission{
		Form: f.Name, At: now.Unix(), Values: map[string]string{},
		Source: source,
	}
	id, err := newID()
	if err != nil {
		return Submission{}, err
	}
	out.ID = id

	// Only declared fields, checked against their kinds. There is no path here
	// by which a name from the request becomes a key in anything.
	for _, fl := range f.Fields {
		raw := strings.TrimSpace(values[fl.Name])
		if raw == "" {
			if fl.Required {
				return Submission{}, fmt.Errorf("%s is required", fl.Label)
			}
			continue
		}
		if len(raw) > MaxValue {
			return Submission{}, fmt.Errorf(
				"%s is %d characters; the limit is %d",
				fl.Label, len(raw), MaxValue)
		}
		v, err := check(fl, raw)
		if err != nil {
			return Submission{}, fmt.Errorf("%s %w", fl.Label, err)
		}
		out.Values[fl.Name] = v
	}
	return out, nil
}

func check(fl Field, raw string) (string, error) {
	// Control characters are refused everywhere. They serve no purpose in a
	// form answer and they are how a value breaks out of whatever renders it
	// later — a CSV export, a terminal, a log line.
	for _, r := range raw {
		if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
			return "", fmt.Errorf("contains a control character")
		}
	}
	switch fl.Kind {
	case Line, Email, Choice:
		if strings.ContainsAny(raw, "\r\n") {
			return "", fmt.Errorf("must be one line")
		}
	}
	switch fl.Kind {
	case Email:
		if !reEmail.MatchString(raw) {
			return "", fmt.Errorf("does not look like an address")
		}
	case Number:
		if _, err := strconv.ParseFloat(raw, 64); err != nil {
			return "", fmt.Errorf("must be a number")
		}
	case Choice:
		for _, c := range fl.Choices {
			if c == raw {
				return raw, nil
			}
		}
		return "", fmt.Errorf("is not one of the choices")
	case Agree:
		if raw != "yes" && raw != "on" && raw != "true" {
			return "", fmt.Errorf("has to be agreed to")
		}
		return "yes", nil
	}
	return raw, nil
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("no entropy for an identifier: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Store is a directory of submissions.
//
// A plain directory of JSON files. No merkle tree, no history, no content
// addressing — every one of those properties is the opposite of what this
// data needs, which is to be deletable one row at a time and to disappear on
// its own after a while.
type Store struct{ dir string }

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

var reID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (st *Store) path(form, id string) (string, error) {
	if !reName.MatchString(form) {
		return "", fmt.Errorf("%q is not a form name", form)
	}
	if !reID.MatchString(id) {
		return "", fmt.Errorf("%q is not a submission identifier", id)
	}
	return filepath.Join(st.dir, form, id+".json"), nil
}

// Put writes one submission.
func (st *Store) Put(s Submission) error {
	p, err := st.path(s.Form, s.ID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// 0600, because this is the one place in the store holding what a member
	// of the public typed.
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(body, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// List returns a form's submissions, newest first.
func (st *Store) List(form string) ([]Submission, error) {
	if !reName.MatchString(form) {
		return nil, fmt.Errorf("%q is not a form name", form)
	}
	entries, err := os.ReadDir(filepath.Join(st.dir, form))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Submission
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(st.dir, form, e.Name()))
		if err != nil {
			continue
		}
		var s Submission
		if json.Unmarshal(body, &s) != nil {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At > out[j].At })
	return out, nil
}

// Delete removes one submission.
//
// The operation the content store cannot offer, and the reason this data is
// not in it.
func (st *Store) Delete(form, id string) error {
	p, err := st.path(form, id)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("there is no such submission")
		}
		return err
	}
	return nil
}

// Expire removes everything past its retention period.
//
// Returns how many went. Called from a timer and from the interface, and safe
// to run repeatedly — retention is computed from each submission's own age
// rather than from when this last ran, so a missed run deletes more next time
// rather than leaving anything behind.
func (st *Store) Expire(forms *Set, now time.Time) (int, error) {
	n := 0
	for _, f := range forms.Forms {
		subs, err := st.List(f.Name)
		if err != nil {
			return n, err
		}
		cutoff := now.Add(-f.Retention()).Unix()
		for _, s := range subs {
			if s.At < cutoff {
				if err := st.Delete(f.Name, s.ID); err != nil {
					return n, err
				}
				n++
			}
		}
	}
	return n, nil
}

// Purge removes every submission for a form.
//
// What an erasure request or a closed campaign needs, and what makes the
// storage choice worth defending: this is four lines and cannot be written at
// all against an append-only merkle store.
func (st *Store) Purge(form string) (int, error) {
	subs, err := st.List(form)
	if err != nil {
		return 0, err
	}
	for _, s := range subs {
		if err := st.Delete(form, s.ID); err != nil {
			return 0, err
		}
	}
	return len(subs), nil
}

// Search finds submissions containing a string, for an erasure request.
//
// Somebody asking to be forgotten gives an email address, not a submission
// identifier. Without this, honouring the request means reading every
// submission by hand.
func (st *Store) Search(forms *Set, needle string) ([]Submission, error) {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return nil, fmt.Errorf("nothing to look for")
	}
	var out []Submission
	for _, f := range forms.Forms {
		subs, err := st.List(f.Name)
		if err != nil {
			return nil, err
		}
		for _, s := range subs {
			for _, v := range s.Values {
				if strings.Contains(strings.ToLower(v), needle) {
					out = append(out, s)
					break
				}
			}
		}
	}
	return out, nil
}
