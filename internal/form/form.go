// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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
// deletable, and with a retention ceiling each form declares for itself. It is
// the least sophisticated storage in this program and that is the feature.
//
// That ceiling is now enforced by the program.
//
// It was not. This comment used to end "If nobody runs either, submissions past
// their declared ceiling are kept indefinitely", and said that an external
// timer was the intended arrangement. The disclosure was honest and the gap was
// real: there is no installer here, so nobody was ever handed the cron entry,
// and an operator who had not read this paragraph had a site that promised to
// forget and did not. The gap between a declared retention period and an
// enforced one is the whole of the obligation.
//
// Both long-running servers now sweep -- see internal/upkeep, which also says
// why this daemonises while scheduled publishing deliberately does not. Either
// server alone is enough; Expire is idempotent and tolerates a submission
// another sweep has already taken. `quilzo form expire` and the button on the
// forms screen still work and are still the way to force it.
//
// An install that runs neither server still has nothing sweeping, so the
// posture rule content.retention-unenforced counts submissions that have
// outlived their period -- an observation of the disk rather than a record of
// whether a timer fired, which is the check that cannot go stale.
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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
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

// KindList names every kind, for the error somebody gets when they guess.
//
// Guessing is the normal case: these are not the same words the content types
// use — a form has "line" and "para" where a type has "text" and "longtext" —
// and the two sets sitting next to each other in the same product is exactly
// the situation where an error has to say what is allowed rather than only
// that the guess was wrong.
func KindList() string {
	return string(Line) + ", " + string(Para) + ", " + string(Email) + ", " +
		string(Number) + ", " + string(Choice) + ", " + string(Agree) + " or " + string(File)
}

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
	// When asks this field only when an earlier one was answered so: a
	// choice was one value, or a box was ticked. Asked or not is decided
	// by the server from what arrived (Accept), and shown or not by a
	// stylesheet (StyleSheet), so it works with no script at all.
	When *When `json:"when,omitempty"`
	// Accept is what a file field takes: image, document, text, audio or
	// video. Empty takes images and documents (upload.go).
	Accept []string `json:"accept,omitempty"`
}

// When is the answer that makes a field asked.
type When struct {
	// Field is an earlier field, a choice or a box.
	Field string `json:"field"`
	// Is is the choice that makes this field asked; empty for a box, which
	// asks it when ticked.
	Is string `json:"is,omitempty"`
}

// holds reports whether a condition holds for what was accepted so far.
func (w *When) holds(accepted map[string]string) bool {
	if w == nil {
		return true
	}
	v, ok := accepted[w.Field]
	if !ok {
		return false
	}
	if w.Is == "" {
		return v == "yes"
	}
	return v == w.Is
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
	// Purpose is what the answers are used for, in a sentence: the purpose
	// GDPR Article 5(1)(b) limits them to and Article 13(1)(c) says the
	// person must be told.
	Purpose string `json:"purpose,omitempty"`
	// Basis is the lawful basis for processing them, one of Article 6(1)'s
	// six (Bases). Consent needs a box the person ticks.
	Basis string `json:"basis,omitempty"`
}

// Bases are GDPR Article 6(1)'s lawful bases, as a form names one.
var Bases = map[string]string{
	"consent":              "the person agreed, by ticking a box (Art 6(1)(a))",
	"contract":             "to do what they asked for, or to enter a contract with them (Art 6(1)(b))",
	"legal-obligation":     "a law requires it (Art 6(1)(c))",
	"vital-interests":      "to protect somebody's life (Art 6(1)(d))",
	"public-task":          "a task in the public interest or official authority (Art 6(1)(e))",
	"legitimate-interests": "a legitimate interest that the person's rights do not override (Art 6(1)(f))",
}

// Lawful reports whether a form says why it collects and on what basis.
func (f *Form) Lawful() bool { return strings.TrimSpace(f.Purpose) != "" && f.Basis != "" }

// told is each basis as the person filling in the form reads it.
var told = map[string]string{
	"consent":              "your agreement, which you can withdraw at any time (GDPR Article 6(1)(a))",
	"contract":             "the need to do what you asked for (GDPR Article 6(1)(b))",
	"legal-obligation":     "a legal obligation (GDPR Article 6(1)(c))",
	"vital-interests":      "the need to protect someone's life (GDPR Article 6(1)(d))",
	"public-task":          "a task carried out in the public interest (GDPR Article 6(1)(e))",
	"legitimate-interests": "our legitimate interests (GDPR Article 6(1)(f))",
}

// inWords is a retention period as a person says it.
func inWords(days int) string {
	switch {
	case days == 1:
		return "a day"
	case days == 365:
		return "a year"
	case days%365 == 0:
		return fmt.Sprintf("%d years", days/365)
	}
	return fmt.Sprintf("%d days", days)
}

// Told is everything the person is told before they send the form: the
// notice as written, then what the answers are for, the lawful basis, and
// how long they are kept. GDPR Article 13 asks for these at the moment of
// collection, so they are put where every layout already prints the
// notice rather than in a field a layout would have to learn about. The
// period is the one the sweep enforces (Expire), so the promise is kept.
func (f *Form) Told() string {
	parts := []string{strings.TrimSpace(f.Notice)}
	if p := strings.TrimSpace(f.Purpose); p != "" {
		parts = append(parts, "What your answers are for: "+strings.TrimRight(p, ". ")+".")
	}
	if b, ok := told[f.Basis]; ok {
		parts = append(parts, "We rely on "+b+".")
	}
	parts = append(parts, "We keep your answers for "+inWords(int(f.Retention().Hours()/24))+", then delete them.")
	return strings.TrimSpace(strings.Join(parts, " "))
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
	if f.Basis != "" {
		if _, ok := Bases[f.Basis]; !ok {
			return fmt.Errorf("%q is not a lawful basis; one of consent, contract, legal-obligation, "+
				"vital-interests, public-task, legitimate-interests", f.Basis)
		}
		if f.Basis == "consent" {
			agreed := false
			for _, fl := range f.Fields {
				// Asked of everybody: consent asked only of some is consent
				// most never gave.
				if fl.Kind == Agree && fl.Required && fl.When == nil {
					agreed = true
				}
			}
			if !agreed {
				return fmt.Errorf("%q rests on consent and has no required box to tick: consent is "+
					"something the person gives, not something the form assumes", f.Name)
			}
		}
	}
	if len(f.Purpose) > 500 {
		return fmt.Errorf("%q's purpose is over 500 characters; say it in a sentence", f.Name)
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
	kinds := map[string]Field{}
	for _, fl := range f.Fields {
		if err := checkWhen(f.Name, fl, kinds); err != nil {
			return err
		}
		kinds[fl.Name] = fl
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
		case File:
			for _, k := range fl.Accept {
				if !slices.Contains(UploadKinds, k) {
					return fmt.Errorf("%q takes %q; a file field takes %s", fl.Name, k, strings.Join(UploadKinds, ", "))
				}
			}
		case Choice:
			if len(fl.Choices) == 0 {
				return fmt.Errorf("%q is a choice with nothing to choose",
					fl.Name)
			}
		default:
			return fmt.Errorf("%q has kind %q; a form field is %s",
				fl.Name, fl.Kind, KindList())
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

// checkWhen refuses a condition that cannot hold or cannot be shown: on a
// field that is not earlier, not a choice or a box, or a choice it does
// not offer.
func checkWhen(form string, fl Field, earlier map[string]Field) error {
	w := fl.When
	if w == nil {
		return nil
	}
	on, ok := earlier[w.Field]
	if !ok {
		return fmt.Errorf("%q in %q is asked when %q is answered, which is not a field before it",
			fl.Name, form, w.Field)
	}
	switch on.Kind {
	case Agree:
		if w.Is != "" {
			return fmt.Errorf("%q is asked when the box %q is ticked; a box has no choice to name", fl.Name, w.Field)
		}
	case Choice:
		if !slices.Contains(on.Choices, w.Is) {
			return fmt.Errorf("%q is asked when %q is %q, which is not one of its choices (%s)",
				fl.Name, w.Field, w.Is, strings.Join(on.Choices, ", "))
		}
	default:
		return fmt.Errorf("%q is asked depending on %q, which is a %s; it can depend on a choice or a box",
			fl.Name, w.Field, on.Kind)
	}
	return nil
}

// Words is a condition as a person reads it: "only if Topic is Returns".
func (f *Form) Words(w *When) string {
	if w == nil {
		return ""
	}
	label := w.Field
	for _, fl := range f.Fields {
		if fl.Name == w.Field {
			label = fl.Label
		}
	}
	if w.Is == "" {
		return "Only if “" + label + "” is ticked."
	}
	return "Only if “" + label + "” is " + w.Is + "."
}

// StyleSheet hides each field asked only on an answer until the answer is
// given, with :has() and no script, or "" when no field is. Inside
// @supports, so a browser without :has() shows every field with the words
// that say when it is asked, and the server still takes only what is.
//
// The rendered field's wrapper is #f-NAME-field and its control #f-NAME,
// as the starter's layouts write them.
func (f *Form) StyleSheet() string {
	var b strings.Builder
	for _, fl := range f.Fields {
		w := fl.When
		if w == nil {
			continue
		}
		wrap := "#f-" + fl.Name + "-field"
		var on string
		if w.Is == "" {
			on = "#f-" + w.Field + ":checked"
		} else {
			on = "#f-" + w.Field + " option[value=" + cssString(w.Is) + "]:checked"
		}
		b.WriteString(wrap + "{display:none}\n")
		b.WriteString("form:has(" + on + ") " + wrap + "{display:block}\n")
	}
	if b.Len() == 0 {
		return ""
	}
	return "@supports selector(:has(a)){\n" + b.String() + "}\n"
}

// cssString quotes a value for a CSS string, every character outside
// letters, digits and spaces escaped, so a choice cannot end the rule.
func cssString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == ' ':
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, "\\%x ", r)
		}
	}
	b.WriteByte('"')
	return b.String()
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
	// Files are the files it carries, kept beside it (upload.go).
	Files []FileRef `json:"files,omitempty"`
	// data are the files' bytes, from arrival until Put writes them.
	data map[string][]byte
}

// Accept turns a submitted set of values into a submission, or refuses it.
//
// values are whatever arrived. Unknown names are dropped rather than refused:
// a browser extension adding a field, or a form served from a cached older
// version, should not make a person's message vanish.
func Accept(f *Form, values map[string]string, source string,
	now time.Time) (Submission, error) {
	return accept(f, values, source, now, true)
}

// AcceptShare takes a submission that arrived from the operating system's
// share sheet rather than from a rendered form.
//
// # Why the human checks are skipped, and what replaces them
//
// The honeypot and the timing stamp both depend on the sender having loaded a
// page this server rendered: one is a field only a script fills in, the other
// is a number only that page carries. A share has neither, because it comes
// from the platform's share dialog with three values and nothing else. There
// is no stamp to forge and none to check.
//
// Skipping them is therefore not a weakening of the check — the check cannot
// run — but it does leave /share as an unauthenticated write with no bot
// defence of its own. That is replaced at the handler by the same rate limiter
// the forms use, keyed on the source, and it is the honest trade: a share
// endpoint is exactly as exposed as a public form and has one fewer defence,
// so it gets a harder limit.
//
// Everything else is identical. Only declared fields are accepted, kinds are
// still checked, required fields are still required, and the submission lands
// in the same store with the same retention. There is no second write path
// with its own bugs.
func AcceptShare(f *Form, values map[string]string, source string,
	now time.Time) (Submission, error) {
	return accept(f, values, source, now, false)
}

// ErrSpam is a submission refused as a script's: the honeypot filled, the
// timing stamp missing, or the form answered faster than a person can read
// it. The sender is told only that it was not accepted, as before.
var ErrSpam = errors.New("this submission was not accepted")

// ErrOld is a page that was opened longer ago than the route answering it
// allows: a replayed form, or a tab that sat open for a week and is
// answering questions that may have changed. It is not ErrSpam, and is not
// told to the shield, because a person who left a tab open is not a script.
// The words are the form's, which shows them as they are; a booking says it
// in its own.
var ErrOld = errors.New("this form was opened more than a day ago. Reload it and send " +
	"again — the questions may have changed since")

// OldestPage is how long ago a page may have been opened for a form or a
// booking on it still to be taken.
const OldestPage = 24 * time.Hour

// CheckHuman makes the two checks a page this server rendered lets a route
// make of what came back from it: the field nobody sees (Honeypot), and
// when the page was read (StampField). It answers ErrSpam for a script's,
// ErrOld for a page opened more than oldest ago, and nil for a person's.
// An oldest of zero is no upper bound, for a route whose page may be
// cached, as a newsletter sign-up in a page's footer is.
//
// A form, a booking and the newsletter's sign-up each made these checks in
// a copy of their own, so a change to one (what a stamp may look like, how
// quickly a person reads) would have reached one route and not the others.
// Each route still tells the shield under its own name and answers in its
// own words; this is only the judgement.
func CheckHuman(honeypot, stamp string, now time.Time, oldest time.Duration) error {
	// The honeypot. A person never sees this field; anything filling in
	// every field it finds does.
	if strings.TrimSpace(honeypot) != "" {
		return ErrSpam
	}
	// The timing check. A person cannot read a form and answer it in under
	// two seconds; a script does it in twenty milliseconds. A missing or
	// unparseable stamp is refused rather than waved through — otherwise
	// removing the field is how the check is bypassed. A stamp from the
	// future is refused with them: it is less than two seconds old.
	started, err := strconv.ParseInt(strings.TrimSpace(stamp), 10, 64)
	if err != nil {
		return ErrSpam
	}
	elapsed := now.Unix() - started
	if elapsed < MinFillSeconds {
		return ErrSpam
	}
	if oldest > 0 && elapsed > int64(oldest/time.Second) {
		return ErrOld
	}
	return nil
}

func accept(f *Form, values map[string]string, source string,
	now time.Time, human bool) (Submission, error) {
	return acceptAll(f, values, nil, source, now, human)
}

func acceptAll(f *Form, values map[string]string, files map[string]Upload, source string,
	now time.Time, human bool) (Submission, error) {

	if f.Closed {
		return Submission{}, fmt.Errorf(
			"%q is not accepting submissions", f.Name)
	}

	// The honeypot and the timing check, with a day's bound on the page's
	// age (CheckHuman).
	//
	// Both need the sender to have loaded a page this server rendered. A
	// share from the operating system did not, so AcceptShare skips them —
	// see the note there for what replaces them.
	if human {
		if err := CheckHuman(values[Honeypot], values[StampField], now, OldestPage); err != nil {
			return Submission{}, err
		}
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
	var uploaded int64
	for _, fl := range f.Fields {
		// A field asked only on an answer is neither required nor kept
		// when the answer was not given, whatever arrived for it.
		if !fl.When.holds(out.Values) {
			continue
		}
		if fl.Kind == File {
			u, sent := files[fl.Name]
			if !sent || len(u.Data) == 0 {
				if fl.Required {
					return Submission{}, fmt.Errorf("%s is required", fl.Label)
				}
				continue
			}
			ref, err := checkUpload(fl, u, now)
			if err != nil {
				return Submission{}, fmt.Errorf("%s %w", fl.Label, err)
			}
			if uploaded += ref.Size; uploaded > MaxUploadBytes {
				return Submission{}, fmt.Errorf("the files are over %d MB together", MaxUploadBytes>>20)
			}
			if out.data == nil {
				out.data = map[string][]byte{}
			}
			out.data[fl.Name] = u.Data
			out.Files = append(out.Files, ref)
			out.Values[fl.Name] = fmt.Sprintf("%s (%s, %d KB)", ref.Name, ref.Format, (ref.Size+1023)/1024)
			continue
		}
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
type Store struct {
	dir string
	// FileCeiling is the most the files kept here may come to together;
	// zero is MaxKeptFileBytes. A submission whose files would take them
	// past it is refused with ErrFilesFull.
	FileCeiling int64
	// files makes counting what is kept and writing a submission's files
	// one step, so two arriving together cannot both take the room that
	// was left for one.
	files sync.Mutex
}

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

// Put writes one submission, and the files it carries first, when they
// fit under the store's ceiling (upload.go).
func (st *Store) Put(s Submission) error {
	p, err := st.path(s.Form, s.ID)
	if err != nil {
		return err
	}
	if len(s.data) > 0 {
		st.files.Lock()
		defer st.files.Unlock()
		if err := st.roomFor(s); err != nil {
			return err
		}
	}
	if err := st.putFiles(s); err != nil {
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
// errNoSubmission is returned when there is nothing there to remove.
//
// A value rather than a new error each time, so Expire can tell "already gone"
// from "the disk is broken" — which is the difference between carrying on with
// the sweep and stopping it.
var errNoSubmission = errors.New("there is no such submission")

func (st *Store) Delete(form, id string) error {
	p, err := st.path(form, id)
	if err != nil {
		return err
	}
	// Its files go with it, and first: a submission that is gone keeps no
	// file behind.
	if dir, derr := st.filesDir(form, id); derr == nil {
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	if err := os.Remove(p); err != nil {
		if os.IsNotExist(err) {
			return errNoSubmission
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
			if s.At >= cutoff {
				continue
			}
			// A submission that is already gone is this function's own work,
			// done by somebody else. Two servers sweep now, and a person can
			// delete one from the forms screen while a sweep is walking the
			// directory — reporting that as a failure would abandon the rest
			// of the sweep over a file that reached the state it was headed
			// for anyway.
			if err := st.Delete(f.Name, s.ID); err != nil {
				if errors.Is(err, errNoSubmission) {
					continue
				}
				return n, err
			}
			n++
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
