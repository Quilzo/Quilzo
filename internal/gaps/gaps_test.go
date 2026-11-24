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

// A visitor who says who and where they are is kept without it: "I am
// Janet Zqwood, ..., 14 Rose Lane, Leeds LS1 4AB" was kept whole, shown to
// staff and offered as the name of the page to write, under a promise that
// anything that could name the visitor is taken out.
func TestAQuestionIsKeptWithoutTheNameAndAddressItGives(t *testing.T) {
	for q, leaks := range map[string][]string{
		"Do you ship to Zqbarra island? I am Janet Zqwood, janet.zqwood@gmail.com, 14 Rose Lane, Leeds LS1 4AB, card 4111 1111 1111 1111": {
			"Janet", "Zqwood", "14 Rose Lane", "LS1 4AB", "4111"},
		"Do you deliver to Zqmoor farm? I am Peter Zqhill of 9 Mill Road, York YO1 7HH": {"Peter", "Zqhill", "9 Mill Road", "YO1 7HH"},
		"Hi, my name is Ana María López and I live at 221B Baker Street":                {"Ana", "López", "221B Baker Street"},
		"This is Tom Brady from 1600 Pennsylvania Avenue, Washington DC 20500-0003":     {"Tom Brady", "1600 Pennsylvania", "20500"},
		"I'm Sam O'Neill, can you post to SW1A 1AA?":                                    {"Sam", "O'Neill", "SW1A 1AA"},
	} {
		got := Clean(q, nil)
		for _, leak := range leaks {
			if strings.Contains(got, leak) {
				t.Errorf("%q kept %q", got, leak)
			}
		}
	}
	if got := Clean("Hi, I'm Sam O'Neill. Delivered to 9 Mill Road, YO1 7HH?", nil); got != "Hi, I'm [name]. Delivered to [address], [postcode]?" {
		t.Errorf("masked as %q", got)
	}
	// What a question is about is kept.
	for q, want := range map[string]string{
		"I am looking for gluten-free bread":               "I am looking for gluten-free bread",
		"Do you ship to Zqbarra island? I am Janet Zqwood": "Do you ship to Zqbarra island? I am [name]",
		"Is Rose Lane car park open on Sundays?":           "Is Rose Lane car park open on Sundays?",
		"Do you have 3 bags of flour?":                     "Do you have 3 bags of flour?",
	} {
		if got := Clean(q, nil); !strings.Contains(got, want) {
			t.Errorf("Clean(%q) = %q, which lost %q", q, got, want)
		}
	}
}

// An address is one without its capitals, as people type into a chat box,
// and a name is one after its title wherever it stands. "i am janet zqwood,
// 14 rose lane, leeds ls1 4ab" was kept with its street, and the page
// offered for "i am janet zqwood of 14 rose lane leeds and i want to know
// if you ship to zqbarra" was 14-rose-lane-leeds-and-i-want-to; "Order for
// Mr Peter Zqhill has not arrived" was kept, and named its page, whole.
func TestAnAddressTypedWithoutCapitalsAndATitledNameAreTakenOut(t *testing.T) {
	for q, leaks := range map[string][]string{
		"do you ship to zqbarra island? i am janet zqwood, 14 rose lane, leeds ls1 4ab":     {"14 rose lane", "rose", "ls1 4ab"},
		"can you deliver to 22b baker street london":                                        {"22b", "baker"},
		"i am janet zqwood of 14 rose lane leeds and i want to know if you ship to zqbarra": {"14 rose lane", "rose"},
		"my parcel for 9 mill road never came":                                              {"9 mill road", "mill"},
		"Order for Mr Peter Zqhill has not arrived":                                         {"Peter", "Zqhill"},
		"Can Dr. Ana López collect the order for Mrs Janet Zqwood-Smith from the depot?":    {"Ana", "López", "Janet", "Zqwood"},
	} {
		got := Clean(q, nil)
		for _, leak := range leaks {
			if strings.Contains(got, leak) {
				t.Errorf("%q kept %q", got, leak)
			}
			if name := Topic(got); strings.Contains(name, leak) {
				t.Errorf("the page for %q is named %q, with %q in it", q, name, leak)
			}
		}
	}
	// A figure before a road is not always a house, and a title is not
	// always a person's.
	for _, q := range []string{
		"Is it 3 miles down the road?",
		"is there a 1 way street near you",
		"are you 10 minutes up the road from the station",
		"Is it a 5 minute walk from the station?",
		"do you sell 2 for the road mugs",
		"Do you sell Dr Martens boots?",
		"Is Mr Kipling cake vegan?",
	} {
		if got := Clean(q, nil); got != q {
			t.Errorf("Clean(%q) = %q", q, got)
		}
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

// A question whose answer did not help is kept as one, counted in its
// group, and keeps the group from being closed by answering it again;
// ratings are counted with nothing else, and let go with their days.
func TestAnAnswerThatDidNotHelpIsAGap(t *testing.T) {
	l := Ledger{Dir: t.TempDir()}
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	if err := l.Add("help", "do you ship to Norway", now); err != nil {
		t.Fatal(err)
	}
	if err := l.Unhelpful("help", "do you ship to Norway and how long", now); err != nil {
		t.Fatal(err)
	}
	entries, err := l.Read("help", now.Add(-time.Hour))
	if err != nil || len(entries) != 2 || entries[1].Why != WhyUnhelpful {
		t.Fatalf("%+v %v", entries, err)
	}
	g := Groups(entries, nil)
	if len(g) != 1 || g[0].Unhelpful != 1 || g[0].Answerable() {
		t.Fatalf("%+v", g)
	}
	for _, helpful := range []bool{true, true, false} {
		if err := l.Rate("help", helpful, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Rate("help", true, now.Add(-40*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if h, d, err := l.Ratings("help", now.Add(-24*time.Hour)); err != nil || h != 2 || d != 1 {
		t.Fatalf("%d %d %v", h, d, err)
	}
	if n, _ := l.Prune(30*24*time.Hour, now); n != 1 {
		t.Fatalf("pruned %d", n)
	}
	if h, _, _ := l.Ratings("help", now.Add(-60*24*time.Hour)); h != 2 {
		t.Fatalf("an old day's ratings outlived it: %d", h)
	}
	if err := l.Rate("../x", true, now); err == nil {
		t.Error("a name that is not a chatbot's")
	}
}

// The page offered for a question is named for what was asked, not for who
// asked it. Topic took the first sentence and left out what Clean had
// masked, so a name Clean does not know for one, typed without capitals or
// before the question, was still the page's name: "i am janet zqwood, do
// you ship to zqbarra island?" offered i-am-janet-zqwood-do-you-ship-to.
func TestATopicIsWhatWasAskedNotWhoAsked(t *testing.T) {
	for q, want := range map[string]string{
		"Do you ship to Zqbarra island? I am Janet Zqwood, 14 Rose Lane":          "Do you ship to Zqbarra island",
		"i am janet zqwood, do you ship to zqbarra island?":                       "do you ship to zqbarra island",
		"my name is janet zqwood. do you ship to zqbarra island?":                 "do you ship to zqbarra island",
		"Hi, Janet Zqwood here from 14 Rose Lane. Do you ship to Zqbarra island?": "Do you ship to Zqbarra island",
		"this is janet zqwood from leeds and i want to know if you ship pallets":  "leeds and i want to know if you",
		"Do you ship to Zqbarra island":                                           "Do you ship to Zqbarra island",
		"I am looking for the opening hours of the Zqvel bakery on Sundays":       "opening hours of the Zqvel bakery on Sundays",
	} {
		if got := Topic(Clean(q, nil)); got != want {
			t.Errorf("Topic(%q) = %q, not %q", q, got, want)
		}
	}
	for _, q := range []string{
		"i am janet zqwood, do you ship to zqbarra island?",
		"my name is janet zqwood and i live in leeds. do you ship?",
		"I'm Dr. Janet Zqwood, do you ship to Zqbarra island?",
	} {
		if got := strings.ToLower(Topic(Clean(q, nil))); strings.Contains(got, "janet") || strings.Contains(got, "zqwood") {
			t.Errorf("Topic(%q) = %q, which names the visitor", q, got)
		}
	}
}

// A title before a name is part of it, and a name after "my name is" is one
// without its capitals: "I'm Dr. Janet Zqwood" was kept as "I'm [name].
// Janet Zqwood", and "my name is janet zqwood" whole.
func TestANameIsKnownWithItsTitleAndWithoutItsCapitals(t *testing.T) {
	for q, want := range map[string]string{
		"I'm Dr. Janet Zqwood and want to know if you ship":   "I'm [name] and want to know if you ship",
		"I am Mrs Janet Zqwood, do you ship?":                 "I am [name], do you ship?",
		"my name is janet zqwood and I want to know":          "my name is [name] and I want to know",
		"My name's janet. Do you ship?":                       "My name's [name]. Do you ship?",
		"I am looking for gluten-free bread, my name is Sam.": "I am looking for gluten-free bread, my name is [name].",
	} {
		if got := Clean(q, nil); got != want {
			t.Errorf("Clean(%q) = %q, not %q", q, got, want)
		}
	}
}
