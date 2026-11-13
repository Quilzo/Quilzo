// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package gaps keeps what visitors asked a chatbot that it could not
// answer, so somebody can write what the site is missing, and checks
// afterwards that the chatbot answers now.
//
// # Why it is off until somebody turns it on
//
// What a visitor asks a site is theirs, and the audit log keeps only that
// a question went unanswered, never the question. Keeping the words is a
// choice the owner makes (chatbots.gap_ledger), for a purpose: finding what
// the site does not say. So it keeps as little as does that:
//   - personal data is masked before anything is written: card numbers,
//     credentials, bank accounts, email addresses, national numbers and
//     telephone numbers become [email] and the like (internal/pii), and
//     any other run of eight digits or more becomes [number];
//   - no visitor is named, counted or linked: a question and the day;
//   - each day is a file of its own, and days older than chatbots.gap_days
//     are deleted whole, so nothing outlives the purpose;
//   - the public site appends and nothing else; reading, grouping and
//     closing happen in the admin and on the command line.
//
// A question a chatbot did answer, and the visitor said the answer did not
// help, is kept the same way, marked so (Unhelpful): what a page says
// badly is as much a gap as what it does not say. Whether answers helped
// at all is counted, a mark a rating, with nothing else (Rate).
//
// # The loop
//
// Questions are grouped by what they are about (Groups). Somebody, or an
// agent asked to, writes the page that answers a group; when the site is
// published, the group's questions are put to the chatbot again (Check in
// the caller), and a group it now answers is closed, naming the page it
// answered from. A group asked about again after it was closed opens
// again.
package gaps

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/pii"
)

// Bounds on what is kept.
const (
	// MaxQuestion is the longest question kept, in bytes.
	MaxQuestion = 500
	// MaxDay is the most questions kept for one chatbot in one day; past
	// it they are counted, not kept, so a flood cannot fill the disk.
	MaxDay = 2000
	// MaxShown is how many of a group's questions are listed.
	MaxShown = 8
)

var reName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Entry is one question that went unanswered, or whose answer a visitor
// said did not help (Why is WhyUnhelpful).
type Entry struct {
	At  time.Time `json:"at"`
	Q   string    `json:"q"`
	Why string    `json:"why,omitempty"`
}

// WhyUnhelpful marks a question that was answered, and the visitor said the
// answer did not help.
const WhyUnhelpful = "unhelpful"

// MaxRatings is the most ratings counted for one chatbot in one day.
const MaxRatings = 50_000

// Ledger is the folder gaps are kept in: one folder per chatbot, one file
// per day.
type Ledger struct{ Dir string }

func (l Ledger) dir(chatbot string) (string, error) {
	if !reName.MatchString(chatbot) {
		return "", fmt.Errorf("%q is not a chatbot's name", chatbot)
	}
	return filepath.Join(l.Dir, chatbot), nil
}

var (
	rePlaceholder = regexp.MustCompile(`<quilzo:([a-z-]+):\d+>`)
	// reDigits are long runs of digits however they are spaced: a
	// telephone number written the way a country writes its own, an
	// account or an order number. None says what a question is about.
	reDigits = regexp.MustCompile(`\+?\(?\d[\d ().-]{6,}\d`)

	// Who and where a visitor says they are. Visitors type it into a
	// chatbot as they would into a letter, "I am Janet Zqwood, 14 Rose
	// Lane, Leeds LS1 4AB", and it was kept whole, shown to staff and
	// offered as the name of the page to write, under a promise that
	// anything that could name them is taken out. A name is the
	// capitalised words after "I am", "my name is" or "this is", with the
	// title before them; a street address a house number, capitalised
	// words and a street's word; a postcode a British one, or an American
	// ZIP after its state.
	//
	// After "my name is" a name is one without its capitals, as people
	// type into a chat box: nothing else follows those words. After "I am"
	// it is not, or "I am looking for bread" would lose what it asks. And
	// the full stop after a street's word is the address's only when the
	// word is short for one, "St." or "Rd.": taken after "Lane" as well,
	// it ran the sentence that gives an address into the one that asks.
	reIntroduced = regexp.MustCompile(`((?i:\b(?:i am|i'm|i’m|my name is|my name's|my name’s|this is|name is)\s+))(?:(?i:dr|mr|mrs|ms|miss|prof|sir|dame)\b\.?\s+)?\p{Lu}[\p{L}'’-]*(?:\s+\p{Lu}[\p{L}'’-]*){0,3}`)
	reNamed      = regexp.MustCompile(`((?i:\bmy name(?: is|'s|’s)\s+))\p{L}[\p{L}'’-]*(?:\s+\p{L}[\p{L}'’-]*)?`)
	reStreet     = regexp.MustCompile(`\b\d{1,5}[A-Za-z]?,?\s+(?:\p{Lu}[\p{L}'’-]*\s+){1,3}(?:(?i:street|road|lane|avenue|drive|close|way|place|court|crescent|terrace|gardens|grove|square|boulevard|hill|row|mews|walk|park)\b|(?i:st|rd|ln|ave|dr|pl|ct|blvd)\b\.?)`)
	rePostcode   = regexp.MustCompile(`(?i)\b[a-z]{1,2}\d[a-z\d]?\s*\d[a-z]{2}\b|\b\d{5}-\d{4}\b|\b[A-Z]{2}\s+\d{5}\b`)

	// A name after its title, wherever it stands, and an address typed
	// without its capitals. "Order for Mr Peter Zqhill has not arrived" says
	// who without saying "I am", and "i am janet zqwood, 14 rose lane, leeds"
	// is how an address is typed into a chat box on a telephone: each was
	// kept whole, and named the page offered for it.
	//
	// A title names a person when a forename and a surname follow it, so
	// "Dr Martens boots" and "Mr Kipling cake" are still what was asked
	// about. And a figure before a road is a house only before the words
	// that are a street's and nothing else's, with a name between them:
	// "3 miles down the road" and "a 5 minute walk" are not addresses
	// (notAStreet).
	reTitled      = regexp.MustCompile(`\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Sir|Dame)\b\.?\s+\p{Lu}[\p{L}'’-]*\s+\p{Lu}[\p{L}'’-]*`)
	reStreetTyped = regexp.MustCompile(`(?i)\b\d{1,5}[a-z]?,?\s+((?:[\p{L}'’-]+\s+){1,3})(?:street|road|lane|avenue|boulevard|mews)\b`)
)

// notAStreet are the words between a figure and "road" that make it a
// distance, a time or a turn of phrase, not a house on one.
var notAStreet = map[string]bool{
	"the": true, "a": true, "an": true, "of": true, "for": true, "to": true,
	"in": true, "on": true, "at": true, "up": true, "down": true, "from": true,
	"and": true, "or": true, "per": true, "along": true, "off": true,
	"way": true, "mile": true, "miles": true, "minute": true, "minutes": true,
	"min": true, "mins": true, "hour": true, "hours": true, "door": true,
	"doors": true, "yard": true, "yards": true, "metre": true, "metres": true,
	"meter": true, "meters": true, "km": true,
}

// typedStreet masks an address reStreetTyped found, unless a word of it
// says it is none.
func typedStreet(found string) string {
	m := reStreetTyped.FindStringSubmatch(found)
	if m == nil {
		return found
	}
	for _, w := range strings.Fields(strings.ToLower(m[1])) {
		if notAStreet[w] {
			return found
		}
	}
	return "[address]"
}

// Clean is a question as it is kept: personal data masked, whitespace
// collapsed, cut at MaxQuestion. allowed are the site's own email domains,
// which are not personal.
func Clean(q string, allowed []string) string {
	m := &pii.Masker{Allowed: allowed}
	q = rePlaceholder.ReplaceAllString(m.Mask(q, false), "[$1]")
	q = reIntroduced.ReplaceAllString(q, "${1}[name]")
	q = reNamed.ReplaceAllString(q, "${1}[name]")
	q = reTitled.ReplaceAllString(q, "[name]")
	q = reStreet.ReplaceAllString(q, "[address]")
	q = reStreetTyped.ReplaceAllStringFunc(q, typedStreet)
	q = rePostcode.ReplaceAllString(q, "[postcode]")
	q = reDigits.ReplaceAllStringFunc(q, func(s string) string {
		n := 0
		for _, r := range s {
			if r >= '0' && r <= '9' {
				n++
			}
		}
		if n < 8 {
			return s
		}
		return "[number]"
	})
	q = strings.Join(strings.Fields(q), " ")
	if len(q) > MaxQuestion {
		q = strings.ToValidUTF8(q[:MaxQuestion], "")
	}
	return q
}

// reMasked is what Clean put in place of something personal.
var reMasked = regexp.MustCompile(`\[[a-z]+\]`)

// reSentenceEnd ends a sentence of a question, and reIntroduces is where
// its writer says who they are: the words that say so and the three after
// them at most, to the end of their clause.
var (
	reSentenceEnd = regexp.MustCompile(`[.?!]+(\s+|$)|\n+`)
	reIntroduces  = regexp.MustCompile(`(?i)\b(?:i am|i'm|i’m|my name is|my name's|my name’s|this is|name is)(?:\s+[^\s,;:]+){0,3}[,;:]?`)
)

// Topic is what a kept question is about, to name the page that answers
// it: the sentence that asks, or its first, without what Clean took out
// and without where the writer says who they are, in at most eight words.
// The name had been the whole question, so a page offered to be written
// for "Do you ship to Zqbarra island? I am Janet Zqwood, 14 Rose Lane"
// would have published a visitor's name and street in its address.
//
// Not the first sentence whatever it is, and not trusting Clean to have
// known the name: "i am janet zqwood, do you ship to zqbarra island?" is
// one sentence, with a name Clean cannot tell from "i am looking for
// bread", and the page offered for it was i-am-janet-zqwood-do-you-ship-to.
// What follows "I am" is left out of a page's name either way; it is
// seldom what a question asks.
func Topic(q string) string {
	asked := ""
	for rest := q; rest != ""; {
		s, end := rest, ""
		if at := reSentenceEnd.FindStringIndex(rest); at != nil {
			s, end, rest = rest[:at[0]], rest[at[0]:at[1]], rest[at[1]:]
		} else {
			rest = ""
		}
		if strings.TrimSpace(s) == "" {
			continue
		}
		if asked == "" {
			asked = s
		}
		if strings.Contains(end, "?") {
			asked = s
			break
		}
	}
	asked = reIntroduces.ReplaceAllString(asked, " ")
	words := strings.Fields(reMasked.ReplaceAllString(asked, " "))
	if len(words) > 8 {
		words = words[:8]
	}
	return strings.Join(words, " ")
}

// Add keeps one unanswered question, already Clean.
func (l Ledger) Add(chatbot, q string, now time.Time) error {
	return l.add(chatbot, Entry{Q: q}, now)
}

// Unhelpful keeps one question, already Clean, whose answer the visitor
// said did not help.
func (l Ledger) Unhelpful(chatbot, q string, now time.Time) error {
	return l.add(chatbot, Entry{Q: q, Why: WhyUnhelpful}, now)
}

func (l Ledger) add(chatbot string, e Entry, now time.Time) error {
	q := strings.TrimSpace(e.Q)
	if q == "" {
		return nil
	}
	d, err := l.dir(chatbot)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	p := filepath.Join(d, now.UTC().Format("2006-01-02")+".jsonl")
	if fi, err := os.Stat(p); err == nil && fi.Size() > MaxDay*(MaxQuestion+64) {
		return nil
	}
	line, err := json.Marshal(Entry{At: now.UTC().Truncate(time.Second), Q: q, Why: e.Why})
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(line, '\n'))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// Read is a chatbot's questions since a moment, oldest first.
func (l Ledger) Read(chatbot string, since time.Time) ([]Entry, error) {
	d, err := l.dir(chatbot)
	if err != nil {
		return nil, err
	}
	days, err := os.ReadDir(d)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, day := range days {
		name := day.Name()
		at, perr := time.Parse("2006-01-02", strings.TrimSuffix(name, ".jsonl"))
		if perr != nil || !strings.HasSuffix(name, ".jsonl") || at.Add(24*time.Hour).Before(since) {
			continue
		}
		f, err := os.Open(filepath.Join(d, name))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 4096), 64<<10)
		n := 0
		for sc.Scan() && n < MaxDay {
			var e Entry
			if json.Unmarshal(sc.Bytes(), &e) == nil && !e.At.Before(since) && e.Q != "" {
				out = append(out, e)
				n++
			}
		}
		f.Close()
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

// Prune deletes every chatbot's days older than keep, and says how many.
func (l Ledger) Prune(keep time.Duration, now time.Time) (int, error) {
	bots, err := os.ReadDir(l.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	cut := now.UTC().Add(-keep).Truncate(24 * time.Hour)
	n := 0
	for _, b := range bots {
		if !b.IsDir() || !reName.MatchString(b.Name()) {
			continue
		}
		days, _ := os.ReadDir(filepath.Join(l.Dir, b.Name()))
		for _, day := range days {
			stem, ok := strings.CutSuffix(day.Name(), ".jsonl")
			if !ok {
				stem, ok = strings.CutSuffix(day.Name(), ratingsSuffix)
			}
			at, err := time.Parse("2006-01-02", stem)
			if err != nil || !ok || !at.Before(cut) {
				continue
			}
			if os.Remove(filepath.Join(l.Dir, b.Name(), day.Name())) == nil {
				n++
			}
		}
	}
	return n, nil
}

// ratingsSuffix names a day's ratings: one byte a rating, + or -.
const ratingsSuffix = ".ratings"

// Rate counts one rating of an answer, and nothing about it or who gave it.
func (l Ledger) Rate(chatbot string, helpful bool, now time.Time) error {
	d, err := l.dir(chatbot)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	p := filepath.Join(d, now.UTC().Format("2006-01-02")+ratingsSuffix)
	if fi, err := os.Stat(p); err == nil && fi.Size() >= MaxRatings {
		return nil
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	mark := []byte{'-'}
	if helpful {
		mark[0] = '+'
	}
	_, werr := f.Write(mark)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// Ratings are how many answers a chatbot's visitors said helped, and did
// not, since a day.
func (l Ledger) Ratings(chatbot string, since time.Time) (helped, didNot int, err error) {
	d, err := l.dir(chatbot)
	if err != nil {
		return 0, 0, err
	}
	days, err := os.ReadDir(d)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	from := since.UTC().Truncate(24 * time.Hour)
	for _, day := range days {
		stem, ok := strings.CutSuffix(day.Name(), ratingsSuffix)
		at, perr := time.Parse("2006-01-02", stem)
		if !ok || perr != nil || at.Before(from) {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(d, day.Name()))
		if rerr != nil {
			continue
		}
		if len(b) > MaxRatings {
			b = b[:MaxRatings]
		}
		for _, c := range b {
			switch c {
			case '+':
				helped++
			case '-':
				didNot++
			}
		}
	}
	return helped, didNot, nil
}

// Closure is how a group was closed: answered from a page, or dismissed
// by a person.
type Closure struct {
	At   time.Time `json:"at"`
	By   string    `json:"by"`
	How  string    `json:"how"` // answered or dismissed
	Page string    `json:"page,omitempty"`
}

func (l Ledger) closedPath(chatbot string) (string, error) {
	d, err := l.dir(chatbot)
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "closed.json"), nil
}

// Closures are a chatbot's closed groups, by key.
func (l Ledger) Closures(chatbot string) (map[string]Closure, error) {
	p, err := l.closedPath(chatbot)
	if err != nil {
		return nil, err
	}
	out := map[string]Closure{}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return out, nil
}

// Close closes a group.
func (l Ledger) Close(chatbot, key string, c Closure) error {
	p, err := l.closedPath(chatbot)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return atomicfile.Update(p, func(m *map[string]Closure) error {
		if *m == nil {
			*m = map[string]Closure{}
		}
		(*m)[key] = c
		// Closures for groups long gone are not kept for ever.
		for k, v := range *m {
			if c.At.Sub(v.At) > 400*24*time.Hour {
				delete(*m, k)
			}
		}
		return nil
	})
}

// Group is questions about one thing.
type Group struct {
	// Key names the group as long as its first question's words do.
	Key string
	// Questions are its distinct questions, most asked first, at most
	// MaxShown.
	Questions []string
	// Count is how many times it was asked, Distinct in how many ways.
	Count, Distinct int
	First, Last     time.Time
	// Closed is how it was closed, when it was and nobody has asked since.
	Closed *Closure
	// Since is how many times it was asked after it was closed.
	Since int
	// Unhelpful is how many of its questions were answered, and the
	// visitor said the answer did not help. A chatbot answering one again
	// says nothing about whether the answer helps now, so a group with
	// any is not closed by asking again: a person closes it.
	Unhelpful int
}

// Answerable reports whether asking a group's questions again can show it
// is answered: not when a visitor said an answer did not help.
func (g Group) Answerable() bool { return g.Unhelpful == 0 }

// Open reports whether the group still wants a page.
func (g Group) Open() bool { return g.Closed == nil }

// Groups are questions grouped by what they are about, most asked first,
// with each group's closure where it still holds: a group asked about
// again after it was closed is open again, and says how often.
func Groups(entries []Entry, closed map[string]Closure) []Group {
	type acc struct {
		g     Group
		words map[string]bool
		asked map[string]int
		order []string
	}
	var groups []*acc
	for _, e := range entries {
		w := Words(e.Q)
		if len(w) == 0 {
			continue
		}
		var into *acc
		best := 0.0
		for _, g := range groups {
			if s := similar(w, g.words); s > best {
				best, into = s, g
			}
		}
		if best < 0.5 {
			into = &acc{words: w, asked: map[string]int{}, g: Group{Key: keyOf(w), First: e.At}}
			groups = append(groups, into)
		}
		norm := strings.ToLower(e.Q)
		if into.asked[norm] == 0 {
			into.order = append(into.order, e.Q)
		}
		into.asked[norm]++
		into.g.Count++
		if e.Why == WhyUnhelpful {
			into.g.Unhelpful++
		}
		into.g.Last = e.At
	}
	out := make([]Group, 0, len(groups))
	for _, a := range groups {
		g := a.g
		sort.SliceStable(a.order, func(i, j int) bool {
			return a.asked[strings.ToLower(a.order[i])] > a.asked[strings.ToLower(a.order[j])]
		})
		g.Distinct = len(a.order)
		g.Questions = a.order[:min(len(a.order), MaxShown)]
		if c, ok := closed[g.Key]; ok {
			since := 0
			for _, e := range entries {
				if e.At.After(c.At) && similar(Words(e.Q), a.words) >= 0.5 {
					since++
				}
			}
			if since == 0 {
				g.Closed = &c
			} else {
				g.Since = since
			}
		}
		out = append(out, g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Open() != out[j].Open() {
			return out[i].Open()
		}
		return out[i].Count > out[j].Count
	})
	return out
}

// stop are words that say nothing about what a question is about.
var stop = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`a an the is are was were be been do does did can could would should will shall
		may might must i me my we our you your it its this that these those there their they them he she his her
		to of in on at by for with from about into over under and or but if then so as than not no yes any some
		what when where which who whom whose why how much many please tell know want need get got have has had
		hello hi thanks thank there's what's whats im i'm ive i've dont don't doesnt doesn't`) {
		stop[w] = true
	}
}

// Words are what a question is about: its words, lower case, without the
// ones every question has, and with a plural or -ing taken off.
func Words(q string) map[string]bool {
	out := map[string]bool{}
	for _, f := range strings.FieldsFunc(strings.ToLower(q), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '\''
	}) {
		f = strings.Trim(f, "'")
		if len(f) < 2 || stop[f] {
			continue
		}
		for _, suf := range []string{"ing", "es", "s"} {
			if len(f) > len(suf)+3 && strings.HasSuffix(f, suf) {
				f = strings.TrimSuffix(f, suf)
				break
			}
		}
		out[f] = true
	}
	return out
}

// similar is how much two questions share: the words in both over the
// words in the shorter, so "do you deliver" and "do you deliver to Bath
// on Sundays" are about the same thing.
func similar(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	both := 0
	for w := range a {
		if b[w] {
			both++
		}
	}
	return float64(both) / float64(min(len(a), len(b)))
}

func keyOf(words map[string]bool) string {
	list := make([]string, 0, len(words))
	for w := range words {
		list = append(list, w)
	}
	slices.Sort(list)
	sum := sha256.Sum256([]byte(strings.Join(list, " ")))
	return hex.EncodeToString(sum[:5])
}
