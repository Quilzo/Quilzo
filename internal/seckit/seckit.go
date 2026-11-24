// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package seckit is the values the security screens are made of: a figure
// with where it came from, a status with its word, a table whose cells are
// one or the other, an approval request with the hash of what is approved.
//
// # Why the values and not the markup
//
// The markup is in the admin's templates (internal/admin/assets/seckit.html),
// where every part is a named template, and its look is the section of the
// admin's stylesheet headed "security kit". This package is what those templates are given,
// and it is the half that carries the rule: every figure on a security
// screen comes from a typed value that code made, and never from text.
//
// A Figure is a count and what it is counted out of, as integers, with the
// sources it came from, the moment its facts are from, the hash it can be
// checked against and the grade of its facts. Its fields are not exported
// and New is the only way to make one, so a figure that lacks its source or
// its hash does not exist to be shown, and nothing can make one from a
// sentence. A model's words can be shown on a screen, fenced and labelled as
// a model's, by a screen that chooses to; they cannot become a number, a
// status, a date or a name here, because no value in this package is parsed
// from text.
//
// There is no score. A Figure is "n of N" of something named, and nothing in
// the kit divides one by the other.
//
// # The parts
//
//	Header    the page's one h1, with what the page is
//	Tile      one figure and its label, for the top of a screen
//	Table     a caption, column headings, and rows of cells
//	Badge     a status: a word and an icon, never a colour alone
//	Evidence  a list of what shows how something stood
//	Approval  what is to be approved, its hash, and who may approve it
//	Event     one entry of a timeline
//	Empty     what a screen says when there is nothing to show
//	Problem   one error of a form, for the summary and beside its field
package seckit

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/register"
)

// MaxLabel is the longest a label on a screen may be, in bytes.
const MaxLabel = 200

// label holds text a screen shows to one plain line: what code wrote, or a
// label a record already holds. It is not a place for a paragraph, and it
// is escaped by the template that writes it.
func label(what, s string) (string, error) {
	switch {
	case strings.TrimSpace(s) == "":
		return "", fmt.Errorf("%s is empty", what)
	case len(s) > MaxLabel:
		return "", fmt.Errorf("%s is %d bytes; a label is at most %d", what, len(s), MaxLabel)
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return "", fmt.Errorf("%s holds a control character", what)
		}
	}
	if _, hidden := plaintext.Visible(s); hidden > 0 {
		return "", fmt.Errorf("%s holds a character that is not shown", what)
	}
	return s, nil
}

var reHash = regexp.MustCompile(`^(sha256:)?[0-9a-f]{64}$`)

// Source names where a figure came from: a source record, or the register
// itself.
type Source struct {
	// Name is what people call the source.
	Name string
	// ID is its record in the register, when it has one, and Href the
	// screen that shows it.
	ID   register.ID
	Href string
}

// TheRegister is the source of a count of the register's own records.
var TheRegister = Source{Name: "The register"}

// Figure is a number on a screen, with everything that lets a reader check
// it: what it counts, out of how many, from where, as of when, against which
// hash, and how its facts reached the record.
type Figure struct {
	n, of   int64
	counted bool
	unit    string
	sources []Source
	at      time.Time
	hash    string
	grade   register.Grade
	age     string
	stale   bool
}

// FigureOf is what a figure is made from.
type FigureOf struct {
	// N is how many, and Of how many it is out of. A figure with no
	// denominator, a plain count, sets Count and leaves Of.
	N, Of int64
	Count bool
	// Unit is what is counted, as the screen says it: "controls passing".
	Unit string
	// Sources is where the facts came from. At least one.
	Sources []Source
	// At is the moment the facts are from, and Hash what the figure can be
	// checked against: a commit of the register, or a record's own hash.
	At   time.Time
	Hash string
	// Grade is the weakest grade among the facts. A count of the
	// register's own records has none.
	Grade register.Grade
	// Now is when the screen is drawn, and Window how old the facts may be
	// before the figure is shown as stale. A zero Window is never stale.
	Now    time.Time
	Window time.Duration
}

// New makes a figure, or says what it lacks. A figure appears with its
// denominator, its source, its age and its grade, or it does not appear.
func New(f FigureOf) (Figure, error) {
	unit, err := label("the figure's unit", f.Unit)
	if err != nil {
		return Figure{}, err
	}
	switch {
	case f.N < 0:
		return Figure{}, fmt.Errorf("a figure counts something; %d is not a count", f.N)
	case !f.Count && f.Of < f.N:
		return Figure{}, fmt.Errorf("a figure is n of N, and %d is more than %d", f.N, f.Of)
	case len(f.Sources) == 0:
		return Figure{}, fmt.Errorf("the figure %q has no source", unit)
	case f.At.IsZero():
		return Figure{}, fmt.Errorf("the figure %q does not say when its facts are from", unit)
	case !reHash.MatchString(f.Hash):
		return Figure{}, fmt.Errorf("the figure %q has no hash to be checked against", unit)
	case f.Now.IsZero():
		return Figure{}, fmt.Errorf("the figure %q does not say when it is being shown, so its age cannot be said", unit)
	}
	if f.Grade == "" {
		if !f.Count {
			return Figure{}, fmt.Errorf("the figure %q has no grade", unit)
		}
	} else if f.Grade.Rank() >= len(f.Grade.Values()) {
		return Figure{}, fmt.Errorf("the figure %q has a grade nobody defined", unit)
	}
	out := Figure{n: f.N, of: f.Of, counted: f.Count, unit: unit, at: f.At.UTC(), hash: f.Hash, grade: f.Grade}
	for _, s := range f.Sources {
		name, err := label("a source's name", s.Name)
		if err != nil {
			return Figure{}, err
		}
		if s.ID != "" && !s.ID.Valid() {
			return Figure{}, fmt.Errorf("the source %q is named by something that is not a record's identifier", name)
		}
		if s.Href != "" && !strings.HasPrefix(s.Href, "/") {
			return Figure{}, fmt.Errorf("the source %q links somewhere that is not a screen of this program", name)
		}
		out.sources = append(out.sources, Source{Name: name, ID: s.ID, Href: s.Href})
	}
	old := f.Now.Sub(f.At)
	out.age = Age(old)
	out.stale = f.Window > 0 && old > f.Window
	return out, nil
}

// Must is New for a figure code knows to be whole; it panics on one that is
// not, which is a mistake in the program.
func Must(f FigureOf) Figure {
	out, err := New(f)
	if err != nil {
		panic("seckit: " + err.Error())
	}
	return out
}

// N is how many, and Of how many it is out of.
func (f Figure) N() int64  { return f.n }
func (f Figure) Of() int64 { return f.of }

// HasOf reports whether the figure has a denominator. A plain count has
// none.
func (f Figure) HasOf() bool { return !f.counted }

// Unit is what is counted.
func (f Figure) Unit() string { return f.unit }

// Sources is where the facts came from.
func (f Figure) Sources() []Source { return f.sources }

// Stamp is the moment the facts are from, as a machine reads it, and When
// as a person does. Both are UTC and absolute: a time on evidence is never
// "recently".
func (f Figure) Stamp() string { return f.at.Format(time.RFC3339) }
func (f Figure) When() string  { return When(f.at) }

// Age is how old the facts were when the screen was drawn, in words.
func (f Figure) Age() string { return f.age }

// Stale reports whether the facts are older than their source allows, and
// Freshness says so as a status.
func (f Figure) Stale() bool { return f.stale }
func (f Figure) Freshness() Badge {
	if f.stale {
		return Stale
	}
	return Fresh
}

// Hash is what the figure can be checked against, and Short its first
// twelve characters, for a line that has no room for all of it.
func (f Figure) Hash() string  { return f.hash }
func (f Figure) Short() string { return Short(f.hash) }

// Grade is how the facts reached the record, as a word; empty for a count
// of the register's own records.
func (f Figure) Grade() string { return GradeWord(f.grade) }

// Zero reports whether the figure was never made, so a template can leave
// its place empty.
func (f Figure) Zero() bool { return f.unit == "" }

// When is a moment as the security screens write it.
func When(t time.Time) string {
	if t.IsZero() {
		return "not recorded"
	}
	return t.UTC().Format("2 Jan 2006, 15:04") + " UTC"
}

// Short is a hash's first twelve characters after any prefix.
func Short(hash string) string {
	h := strings.TrimPrefix(hash, "sha256:")
	return plaintext.Clip(h, 12, "")
}

// Age is a length of time in words: "3 hours", "2 days".
func Age(d time.Duration) string {
	plural := func(n int64, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d < 0:
		return "not yet"
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return plural(int64(d/time.Minute), "minute")
	case d < 48*time.Hour:
		return plural(int64(d/time.Hour), "hour")
	}
	return plural(int64(d/(24*time.Hour)), "day")
}

// GradeWord is a grade as a screen says it.
func GradeWord(g register.Grade) string {
	switch g {
	case register.GradeConnector:
		return "Fetched by a connector"
	case register.GradeCI:
		return "Pushed by a pipeline"
	case register.GradeSigned:
		return "Signed by a third party"
	case register.GradeImported:
		return "Imported from another tool"
	case register.GradeUploaded:
		return "Uploaded by a person"
	case register.GradeScreenshot:
		return "A screenshot"
	}
	return ""
}

// Tone is what sort of thing a status is. It chooses the icon and the
// colour, and neither is the message: the word is.
type Tone string

const (
	Good    Tone = "good"
	Bad     Tone = "bad"
	Warn    Tone = "warn"
	Neutral Tone = "neutral"
	Info    Tone = "info"
)

// Badge is a status: a word, with an icon beside it. The word is always
// shown, so the status reads the same in one colour, in forced colours and
// aloud.
type Badge struct {
	tone Tone
	word string
}

// NewBadge makes a status of a tone and a word. The word is code's, or a
// value of one of the register's enumerations: it is short, and it is one
// line.
func NewBadge(tone Tone, word string) (Badge, error) {
	switch tone {
	case Good, Bad, Warn, Neutral, Info:
	default:
		return Badge{}, fmt.Errorf("%q is not a tone a status has", tone)
	}
	w, err := label("a status's word", word)
	if err != nil {
		return Badge{}, err
	}
	if len(w) > 40 {
		return Badge{}, fmt.Errorf("a status is a word or two, not %d bytes", len(w))
	}
	return Badge{tone: tone, word: w}, nil
}

// MustBadge is NewBadge for a status written in the program.
func MustBadge(tone Tone, word string) Badge {
	b, err := NewBadge(tone, word)
	if err != nil {
		panic("seckit: " + err.Error())
	}
	return b
}

// The statuses every security screen shares, so one state has one word.
var (
	Passing     = MustBadge(Good, "Passing")
	Failing     = MustBadge(Bad, "Failing")
	NoEvidence  = MustBadge(Neutral, "No evidence")
	NeverFailed = MustBadge(Warn, "Never failed")
	Stale       = MustBadge(Warn, "Stale")
	Fresh       = MustBadge(Good, "Fresh")
	Waiting     = MustBadge(Info, "Waiting for a person")
	Alone       = MustBadge(Warn, "Approved alone")
	Lapsed      = MustBadge(Bad, "Lapsed")
)

// Tone and Word are the status's two halves, Icon the symbol its tone
// draws, and IconWord the icon's own text alternative: what sort of status
// it is, said before the word, so "Problem: Failing" is what a screen
// reader reads and what a person sees in one colour.
func (b Badge) Tone() string { return string(b.tone) }
func (b Badge) Word() string { return b.word }
func (b Badge) IconWord() string {
	switch b.tone {
	case Good:
		return "Good"
	case Bad:
		return "Problem"
	case Warn:
		return "Needs attention"
	case Info:
		return "Note"
	}
	return "Unknown"
}
func (b Badge) Icon() string {
	switch b.tone {
	case Good:
		return "check_circle"
	case Bad:
		return "dangerous"
	case Warn:
		return "warning"
	case Info:
		return "info"
	}
	return "help"
}

// Zero reports whether the status was never made.
func (b Badge) Zero() bool { return b.word == "" }

// Header is the top of a page: its one h1, and a line saying what the page
// is.
type Header struct {
	Title string
	Lead  string
}

// Tile is one figure with its label, for the row at the top of a screen.
type Tile struct {
	Label  string
	Figure Figure
	// Status is said under the figure when the tile has one.
	Status Badge
	// Href is where the tile leads, when it leads somewhere.
	Href string
}

// Cell is one cell of a table: text, a figure, a status, a link, a moment
// or a hash.
type Cell struct {
	text   string
	href   string
	figure *Figure
	badge  *Badge
	at     time.Time
	hash   string
}

// TextCell, FigureCell, BadgeCell, LinkCell, TimeCell and HashCell make a
// cell of each sort.
func TextCell(s string) Cell       { return Cell{text: s} }
func FigureCell(f Figure) Cell     { return Cell{figure: &f} }
func BadgeCell(b Badge) Cell       { return Cell{badge: &b} }
func LinkCell(href, s string) Cell { return Cell{text: s, href: href} }
func TimeCell(t time.Time) Cell    { return Cell{at: t.UTC()} }
func HashCell(hash string) Cell    { return Cell{hash: hash} }

// Kind is which sort of cell it is, for the template.
func (c Cell) Kind() string {
	switch {
	case c.figure != nil:
		return "figure"
	case c.badge != nil:
		return "badge"
	case c.href != "":
		return "link"
	case !c.at.IsZero():
		return "time"
	case c.hash != "":
		return "hash"
	case c.text == "":
		return "none"
	}
	return "text"
}

func (c Cell) Text() string   { return c.text }
func (c Cell) Href() string   { return c.href }
func (c Cell) Figure() Figure { return *c.figure }
func (c Cell) Badge() Badge   { return *c.badge }
func (c Cell) Stamp() string  { return c.at.Format(time.RFC3339) }
func (c Cell) When() string   { return When(c.at) }
func (c Cell) Hash() string   { return c.hash }
func (c Cell) Short() string  { return Short(c.hash) }

// Row is one row of a table: the cell that names the row, and the rest.
type Row struct {
	Head  Cell
	Cells []Cell
}

// Table is a table of sourced values: a caption that says what it is, a
// heading for each column, and rows.
type Table struct {
	caption string
	columns []string
	rows    []Row
}

// NewTable makes a table, and refuses one a screen reader could not make
// sense of: no caption, a column with no heading, or a row that is not as
// wide as the headings.
func NewTable(caption string, columns []string, rows []Row) (Table, error) {
	c, err := label("the table's caption", caption)
	if err != nil {
		return Table{}, err
	}
	if len(columns) < 2 {
		return Table{}, fmt.Errorf("the table %q needs a column that names each row and at least one more", c)
	}
	for _, col := range columns {
		if _, err := label("a column's heading", col); err != nil {
			return Table{}, err
		}
	}
	for i, r := range rows {
		if len(r.Cells) != len(columns)-1 {
			return Table{}, fmt.Errorf("row %d of the table %q has %d cells under %d headings", i+1, c, len(r.Cells)+1, len(columns))
		}
		if k := r.Head.Kind(); k != "text" && k != "link" {
			return Table{}, fmt.Errorf("row %d of the table %q is not named by text", i+1, c)
		}
	}
	return Table{caption: c, columns: columns, rows: rows}, nil
}

func (t Table) Caption() string   { return t.caption }
func (t Table) Columns() []string { return t.columns }
func (t Table) Rows() []Row       { return t.rows }

// Evidence is one piece of what shows how something stood: what it is, how
// it came out, when, at which grade, and the hash it is held under.
type Evidence struct {
	Title  string
	Status Badge
	At     time.Time
	Grade  register.Grade
	Hash   string
	Source Source
	Href   string
}

func (e Evidence) Stamp() string     { return e.At.UTC().Format(time.RFC3339) }
func (e Evidence) When() string      { return When(e.At) }
func (e Evidence) Short() string     { return Short(e.Hash) }
func (e Evidence) GradeWord() string { return GradeWord(e.Grade) }

// Approval is a request for a person's decision: what is to be approved,
// the hash of exactly what they are shown, and who may approve it. The hash
// is on the page beside the button, because it is what their authentication
// is bound to and what the receipt will carry.
type Approval struct {
	// What is the thing to be approved, in a line.
	What string
	// Hash is the hash of the surface: the record, the evidence it cites
	// and the change.
	Hash register.Digest
	// Who says who may approve, in a sentence code writes from the
	// separation policy: "Anybody who may accept risks, other than the
	// person who raised this one."
	Who string
	// Needed and Of are how many approvers are needed, of how many
	// eligible.
	Needed, Of int
	// Alone says the person looking is the only one eligible, so their
	// approval will be recorded as made alone, with a review due.
	Alone bool
	// Action is where the form posts, and Fields what it carries. With no
	// Action the request is shown and cannot be decided here.
	Action string
	Fields []Field
	// Button is the button's words: "Approve the exception".
	Button string
}

// Field is a hidden field of a form.
type Field struct{ Name, Value string }

// Short is the start of the surface's hash, and AloneBadge the status an
// approval made alone carries wherever it is shown.
func (a Approval) Short() string     { return Short(string(a.Hash)) }
func (a Approval) AloneBadge() Badge { return Alone }

// Valid reports whether the request can be shown: it says what, it has the
// hash, and it says who.
func (a Approval) Valid() error {
	if _, err := label("what is to be approved", a.What); err != nil {
		return err
	}
	if !a.Hash.Valid() {
		return fmt.Errorf("an approval request shows the hash of what is approved, and this one has none")
	}
	if _, err := label("who may approve", a.Who); err != nil {
		return err
	}
	if a.Needed < 1 || a.Of < 1 {
		return fmt.Errorf("an approval request says how many approvers it needs, of how many")
	}
	if a.Action != "" {
		if _, err := label("the button", a.Button); err != nil {
			return err
		}
	}
	return nil
}

// Event is one entry of a timeline: when, what happened, who did it as the
// record names them, and the hash the entry is held under.
type Event struct {
	At     time.Time
	What   string
	By     string
	Status Badge
	Hash   string
}

func (e Event) Stamp() string { return e.At.UTC().Format(time.RFC3339) }
func (e Event) When() string  { return When(e.At) }
func (e Event) Short() string { return Short(e.Hash) }

// Empty is what a screen says when it has nothing to show: that there is
// nothing, why, and what would put something there.
type Empty struct {
	Title string
	Body  string
	// Href and Action are a link to what would put something there.
	Href, Action string
}

// Problem is one thing wrong with what a form was sent. It is said twice:
// in the summary at the top of the page, which links to the field, and in
// words beside the field itself.
type Problem struct {
	// Field is the id of the form control it is about.
	Field string
	// Label is the control's label, and Message what is wrong with it.
	Label, Message string
}
