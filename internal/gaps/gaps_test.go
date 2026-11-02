// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package gaps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// What is kept has no one's details in it: an address, a telephone number
// and a card are masked, and the site's own address is not.
func TestAQuestionIsKeptWithoutAnybodysDetails(t *testing.T) {
	got := Clean("Can you email ana.lopez@gmail.com or ring 07700 900123 about card 4111 1111 1111 1111? Or write to orders@hartsbakery.co.uk",
		[]string{"hartsbakery.co.uk"})
	for _, leak := range []string{"ana.lopez", "07700", "4111 1111"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q kept %q", got, leak)
		}
	}
	if !strings.Contains(got, "[email]") || !strings.Contains(got, "orders@hartsbakery.co.uk") {
		t.Errorf("%q", got)
	}
	if len(Clean(strings.Repeat("why ", 400), nil)) > MaxQuestion {
		t.Error("a long question was kept whole")
	}
}

// Questions are grouped by what they are about, most asked first; a group
// closed stays closed until somebody asks again.
func TestQuestionsAreGroupedAndClosed(t *testing.T) {
	l := Ledger{Dir: t.TempDir()}
	day := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	for i, q := range []string{
		"Do you deliver?", "do you deliver to Bath?", "Do you deliver on Sundays?", "Do you deliver?",
		"Is there parking near the bakery?", "where can I park",
		"Are your loaves vegan?",
	} {
		if err := l.Add("help", q, day.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := l.Read("help", day.Add(-time.Hour))
	if err != nil || len(entries) != 7 {
		t.Fatalf("%d %v", len(entries), err)
	}
	groups := Groups(entries, nil)
	if len(groups) != 3 {
		for _, g := range groups {
			t.Logf("%d %v", g.Count, g.Questions)
		}
		t.Fatalf("%d groups", len(groups))
	}
	if g := groups[0]; g.Count != 4 || g.Distinct != 3 || g.Questions[0] != "Do you deliver?" {
		t.Errorf("%+v", g)
	}
	if g := groups[1]; g.Count != 2 {
		t.Errorf("parking: %+v", g)
	}
	// Closed when the chatbot answers it, and open again when it is asked
	// after that.
	deliver := groups[0].Key
	if err := l.Close("help", deliver, Closure{At: day.Add(time.Hour), By: "quilzo", How: "answered", Page: "delivery"}); err != nil {
		t.Fatal(err)
	}
	closed, _ := l.Closures("help")
	groups = Groups(entries, closed)
	if groups[len(groups)-1].Key != deliver || groups[len(groups)-1].Open() || groups[len(groups)-1].Closed.Page != "delivery" {
		t.Fatalf("a closed group: %+v", groups)
	}
	if err := l.Add("help", "do you deliver to Bristol?", day.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	entries, _ = l.Read("help", day.Add(-time.Hour))
	for _, g := range Groups(entries, closed) {
		if g.Key == deliver && (!g.Open() || g.Since != 1) {
			t.Errorf("asked again after it was answered: %+v", g)
		}
	}
	for _, bad := range []string{"../x", "Help", ""} {
		if err := l.Add(bad, "q", day); err == nil {
			t.Errorf("kept under %q", bad)
		}
	}
}

// Days older than the keeping are deleted whole, and only those.
func TestOldDaysAreDeletedWhole(t *testing.T) {
	l := Ledger{Dir: t.TempDir()}
	now := time.Date(2026, 11, 30, 12, 0, 0, 0, time.UTC)
	for _, ago := range []int{0, 10, 29, 31, 90} {
		if err := l.Add("help", "do you deliver", now.AddDate(0, 0, -ago)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(l.Dir, "help", "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := l.Prune(30*24*time.Hour, now)
	if err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	entries, _ := l.Read("help", time.Time{})
	if len(entries) != 3 {
		t.Fatalf("%d left", len(entries))
	}
	if _, err := os.Stat(filepath.Join(l.Dir, "help", "notes.txt")); err != nil {
		t.Error("a file that is not a day was deleted")
	}
}
