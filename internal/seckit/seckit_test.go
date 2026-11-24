// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package seckit

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/register"
)

var (
	now   = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	hash  = "sha256:" + strings.Repeat("ab", 32)
	entra = Source{Name: "Entra ID", ID: "0123456789abcdef0123456789abcdef"}
)

func whole() FigureOf {
	return FigureOf{N: 412, Of: 500, Unit: "accounts with a second factor", Sources: []Source{entra},
		At: now.Add(-3 * time.Hour), Hash: hash, Grade: register.GradeConnector, Now: now, Window: 24 * time.Hour}
}

// A figure appears with its denominator, its source, its age and its
// grade, or it does not appear: New refuses one that lacks any of them.
func TestAFigureHasItsSourceTimeHashAndGrade(t *testing.T) {
	f, err := New(whole())
	if err != nil {
		t.Fatal(err)
	}
	if f.N() != 412 || f.Of() != 500 || !f.HasOf() || f.Age() != "3 hours" || f.Stale() ||
		f.Grade() != "Fetched by a connector" || f.Short() != "abababababab" || f.When() != "24 Nov 2026, 07:00 UTC" {
		t.Errorf("the figure reads %d of %d, %q old, stale %v, %q, %q, %q", f.N(), f.Of(), f.Age(), f.Stale(), f.Grade(), f.Short(), f.When())
	}
	for what, change := range map[string]func(*FigureOf){
		"no source":                func(o *FigureOf) { o.Sources = nil },
		"no time":                  func(o *FigureOf) { o.At = time.Time{} },
		"no hash":                  func(o *FigureOf) { o.Hash = "" },
		"a hash that is not one":   func(o *FigureOf) { o.Hash = "recent" },
		"no grade":                 func(o *FigureOf) { o.Grade = "" },
		"a grade nobody defined":   func(o *FigureOf) { o.Grade = "trusted" },
		"n above N":                func(o *FigureOf) { o.N = 501 },
		"a negative count":         func(o *FigureOf) { o.N = -1 },
		"no unit":                  func(o *FigureOf) { o.Unit = "" },
		"a unit of two lines":      func(o *FigureOf) { o.Unit = "accounts\nall fine" },
		"a unit with hidden text":  func(o *FigureOf) { o.Unit = "accounts​" },
		"no moment it is drawn at": func(o *FigureOf) { o.Now = time.Time{} },
		"a source with no name":    func(o *FigureOf) { o.Sources = []Source{{ID: entra.ID}} },
		"a source not a record":    func(o *FigureOf) { o.Sources = []Source{{Name: "Entra", ID: "entra"}} },
	} {
		o := whole()
		change(&o)
		if _, err := New(o); err == nil {
			t.Errorf("a figure with %s was made", what)
		}
	}
	// A plain count of the register's own records has no denominator and no
	// grade, and says so.
	c, err := New(FigureOf{N: 7, Count: true, Unit: "controls", Sources: []Source{TheRegister}, At: now, Hash: hash, Now: now})
	if err != nil || c.HasOf() || c.Grade() != "" {
		t.Errorf("a count is %+v, %v", c, err)
	}
	old := whole()
	old.At = now.Add(-49 * time.Hour)
	if f, _ := New(old); !f.Stale() || f.Age() != "2 days" {
		t.Errorf("facts two days old in a day's window are %q and stale %v", f.Age(), f.Stale())
	}
}

// Nothing in the kit is a score: no value divides one count by another, and
// no figure can be made from text.
func TestTheKitHasNoScoreAndParsesNoFigureFromText(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(Figure{}), reflect.TypeOf(Tile{}), reflect.TypeOf(Cell{})} {
		for i := 0; i < typ.NumMethod(); i++ {
			name := strings.ToLower(typ.Method(i).Name)
			for _, banned := range []string{"score", "percent", "ratio", "pct"} {
				if strings.Contains(name, banned) {
					t.Errorf("%s has a method %s", typ.Name(), typ.Method(i).Name)
				}
			}
		}
	}
	ft := reflect.TypeOf(Figure{})
	for i := 0; i < ft.NumField(); i++ {
		if ft.Field(i).IsExported() {
			t.Errorf("a figure's %s can be set without New", ft.Field(i).Name)
		}
	}
	if (Figure{}).Zero() != true {
		t.Error("a figure nobody made is not empty")
	}
}

// A status is a word with an icon and a word for the icon, in one of five
// tones; never a colour alone.
func TestAStatusIsAWordAndAnIcon(t *testing.T) {
	for _, b := range []Badge{Passing, Failing, NoEvidence, NeverFailed, Stale, Fresh, Waiting, Alone, Lapsed} {
		if b.Word() == "" || b.Icon() == "" || b.IconWord() == "" || b.Tone() == "" {
			t.Errorf("the status %+v is missing a part", b)
		}
	}
	if Failing.Icon() == Passing.Icon() || Failing.IconWord() == Passing.IconWord() {
		t.Error("a failure and a pass draw the same icon")
	}
	for what, b := range map[string][2]string{
		"an unknown tone":    {"red", "Failing"},
		"no word":            {"bad", ""},
		"a paragraph":        {"bad", strings.Repeat("failing ", 10)},
		"a word on two rows": {"bad", "Fail\ning"},
	} {
		if _, err := NewBadge(Tone(b[0]), b[1]); err == nil {
			t.Errorf("a status with %s was made", what)
		}
	}
}

// A table a screen reader can make sense of, or none: a caption, a heading
// for every column, rows as wide as the headings and each named by text.
func TestATableHasItsCaptionHeadingsAndRowNames(t *testing.T) {
	f := Must(whole())
	row := Row{Head: TextCell("Identity"), Cells: []Cell{FigureCell(f), BadgeCell(Passing)}}
	tb, err := NewTable("Coverage by domain", []string{"Domain", "Accounts", "Status"}, []Row{row})
	if err != nil || tb.Caption() != "Coverage by domain" || len(tb.Rows()) != 1 {
		t.Fatalf("%+v %v", tb, err)
	}
	for what, args := range map[string]struct {
		caption string
		cols    []string
		rows    []Row
	}{
		"no caption":            {"", []string{"Domain", "Accounts", "Status"}, []Row{row}},
		"one column":            {"Coverage", []string{"Domain"}, nil},
		"a column with no name": {"Coverage", []string{"Domain", "", "Status"}, []Row{row}},
		"a ragged row":          {"Coverage", []string{"Domain", "Accounts"}, []Row{row}},
		"a row named by a figure": {"Coverage", []string{"Domain", "Accounts", "Status"},
			[]Row{{Head: FigureCell(f), Cells: []Cell{BadgeCell(Passing), BadgeCell(Passing)}}}},
	} {
		if _, err := NewTable(args.caption, args.cols, args.rows); err == nil {
			t.Errorf("a table with %s was made", what)
		}
	}
	for want, c := range map[string]Cell{"figure": FigureCell(f), "badge": BadgeCell(Failing), "link": LinkCell("/x", "x"),
		"time": TimeCell(now), "hash": HashCell(hash), "text": TextCell("x"), "none": {}} {
		if c.Kind() != want {
			t.Errorf("a %s cell is a %s", want, c.Kind())
		}
	}
}

// An approval request says what is approved, the hash of exactly what is
// shown, who may approve and how many must; it cannot be shown without them.
func TestAnApprovalRequestShowsItsHashAndWhoMayApprove(t *testing.T) {
	a := Approval{What: "Accept the risk R-12", Hash: register.Digest(hash),
		Who: "Anybody who may accept risks, other than the person who raised this one", Needed: 1, Of: 3,
		Action: "/register/approve", Button: "Approve the risk"}
	if err := a.Valid(); err != nil {
		t.Fatal(err)
	}
	for what, change := range map[string]func(*Approval){
		"no hash":           func(a *Approval) { a.Hash = "" },
		"nothing to say":    func(a *Approval) { a.What = "" },
		"nobody who may":    func(a *Approval) { a.Who = "" },
		"no number needed":  func(a *Approval) { a.Needed = 0 },
		"a form, no button": func(a *Approval) { a.Button = "" },
	} {
		b := a
		change(&b)
		if err := b.Valid(); err == nil {
			t.Errorf("an approval request with %s can be shown", what)
		}
	}
}

// Ages read as a person says them, and a moment absolutely, in UTC.
func TestAgesAndMomentsReadPlainly(t *testing.T) {
	for d, want := range map[time.Duration]string{
		-time.Minute: "not yet", 30 * time.Second: "under a minute", time.Minute: "1 minute",
		5 * time.Minute: "5 minutes", time.Hour: "1 hour", 47 * time.Hour: "47 hours", 72 * time.Hour: "3 days",
	} {
		if got := Age(d); got != want {
			t.Errorf("%v is %q, not %q", d, got, want)
		}
	}
	if When(time.Time{}) != "not recorded" || When(now.In(time.FixedZone("X", 3600))) != "24 Nov 2026, 10:00 UTC" {
		t.Error("a moment is not said in UTC")
	}
}
