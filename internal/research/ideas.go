// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package research

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/quilzo/quilzo/internal/plaintext"
)

// Ideas: hypotheses a model proposes, judged against each other, and — the
// part the whole feature turns on — followed into execution and decided by
// a person.
//
// # Why pairs, and why both orders
//
// Google's AI co-scientist ranks hypotheses by having a model judge pairs of
// them. A single-order pairwise judgement is a documented bias machine: a
// model shown a pair prefers whichever came first often enough that order
// decides more than content (Zheng et al., MT-Bench, 2023). So every match
// is judged twice, once each way, and only a preference that survives the
// swap is a win; a split is a tie. Each order's reason is kept, so a split
// shows what each side said.
//
// # Why Bradley–Terry, not Elo
//
// Elo replayed over a record gives different ratings for the same results
// in a different order, and the order here would be an accident of ids.
// The Bradley–Terry fit (Hunter's MM algorithm, 2004) depends only on who
// beat whom, which is what a standing should say; LMSYS's Chatbot Arena
// moved to it for that reason. A weak prior — one virtual tie against a
// fixed anchor — keeps an unbeaten idea or an unconnected one finite, and
// an idea with fewer than MinMatches matches is listed as provisional
// rather than ranked: one lucky win is not a standing.
//
// # Why the record shows execution and a person's verdict
//
// The ideation–execution study (Si et al., 2025) found what a ranking alone
// hides: model-written ideas were judged more novel before anybody ran
// them, and lost that lead once executed. A rating is what judges thought
// of the prose. So every idea's standing is printed beside its execution —
// the computations that ran it, whether they finished and reproduced — and
// beside the verdict a person recorded from the claims those computations
// produced. An idea proposed after the data was first seen is marked as
// such, because testing a hypothesis on the data that suggested it is
// exploration, not confirmation.
//
// # What the model is never allowed to do
//
// The model writes hypotheses, critiques and judgements, each recorded as
// the model's. It never writes the plan, never writes a claim (only
// computations do), never records a verdict, and never revises an idea: a
// later idea is a new entrant, so the record stays a record of what was
// proposed. Its text is cleaned of invisible characters and screened for
// instructions addressed to a model; an idea that reads as an instruction
// is held out of judging, with the reason, for a person to look at.

// Limits.
const (
	MaxIdeas       = 100
	MaxIdeaTitle   = 200
	MaxHypothesis  = 1500
	MaxCritique    = 2000
	MaxJudgeReason = 500
	MaxMatchesKept = 4000
	MaxVerdictNote = 2000
	// MaxRoundPairs is how many pairs one round judges, each twice.
	MaxRoundPairs = 24
	// MinMatches is how many matches an idea plays before it is ranked.
	MinMatches = 3
	// MaxRoundIdeas is how many ideas one round may ask for.
	MaxRoundIdeas = 10
)

// reIdea is an idea's identifier.
var reIdea = regexp.MustCompile(`^i-[0-9a-f]{8}$`)

// ValidIdeaID reports whether a string names an idea.
func ValidIdeaID(s string) bool { return reIdea.MatchString(s) }

// NewIdeaID mints an idea's identifier.
func NewIdeaID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "i-" + hex.EncodeToString(b), nil
}

// Idea is one proposed hypothesis.
type Idea struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Hypothesis string `json:"hypothesis"`
	// Critique is the model's own critique of its idea, recorded verbatim
	// and bounded: an idea shown without its critique is an idea shown in
	// better light than it arrived in.
	Critique string    `json:"critique,omitempty"`
	Model    string    `json:"model,omitempty"`
	By       string    `json:"by"`
	At       time.Time `json:"at"`
	// AfterData says the idea was proposed after the project's first
	// computation had run, so the data may have suggested it.
	AfterData bool `json:"after_data,omitempty"`
	// Held is why the idea's text read as an instruction to a model; a held
	// idea is kept and shown, and never judged.
	Held []string `json:"held,omitempty"`
	// Verdict is what a person concluded once it was tested.
	Verdict *Verdict `json:"verdict,omitempty"`
}

// Verdict is a person's conclusion about an idea, from the claims that
// computations produced.
type Verdict struct {
	// Outcome is supported, refuted or inconclusive.
	Outcome string    `json:"outcome"`
	Claims  []string  `json:"claims,omitempty"`
	Note    string    `json:"note,omitempty"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
}

// Outcomes a verdict may have.
var verdictOutcomes = map[string]bool{"supported": true, "refuted": true, "inconclusive": true}

// Match is one pair judged, both ways round.
type Match struct {
	A string `json:"a"`
	B string `json:"b"`
	// First is the winner as judged with A shown first, Second with B
	// shown first, each in A/B terms: "a", "b" or "tie".
	First  string `json:"first"`
	Second string `json:"second"`
	Winner string `json:"winner"`
	// FirstReason and SecondReason are each order's stated reason.
	FirstReason  string    `json:"first_reason,omitempty"`
	SecondReason string    `json:"second_reason,omitempty"`
	Model        string    `json:"model,omitempty"`
	By           string    `json:"by"`
	At           time.Time `json:"at"`
}

// ValidateIdea checks an idea on its own.
func ValidateIdea(i Idea) error {
	if !ValidIdeaID(i.ID) {
		return fmt.Errorf("%q is not an idea's id", i.ID)
	}
	title := strings.TrimSpace(i.Title)
	if title == "" || len(title) > MaxIdeaTitle || strings.ContainsAny(title, "\r\n") {
		return fmt.Errorf("%s: a title is one line of 1 to %d bytes", i.ID, MaxIdeaTitle)
	}
	h := strings.TrimSpace(i.Hypothesis)
	if h == "" || len(h) > MaxHypothesis {
		return fmt.Errorf("%s: a hypothesis is 1 to %d bytes", i.ID, MaxHypothesis)
	}
	if len(i.Critique) > MaxCritique {
		return fmt.Errorf("%s: a critique is at most %d bytes", i.ID, MaxCritique)
	}
	if v := i.Verdict; v != nil {
		if !verdictOutcomes[v.Outcome] {
			return fmt.Errorf("%s: %q is not a verdict; it is supported, refuted or inconclusive", i.ID, v.Outcome)
		}
		if len(v.Note) > MaxVerdictNote {
			return fmt.Errorf("%s: a verdict's note is at most %d bytes", i.ID, MaxVerdictNote)
		}
	}
	return nil
}

// CombineOrders decides a match's winner from its two judgements.
//
// A judge that answers the same pair differently depending on which came
// first has split, and a split is a tie: the countermeasure to the
// first-shown preference, enforced here rather than left to whoever records
// the match.
func CombineOrders(first, second string) string {
	if first == second {
		return first
	}
	return "tie"
}

// validateMatch checks a match on its own.
func validateMatch(m Match) error {
	if !ValidIdeaID(m.A) || !ValidIdeaID(m.B) || m.A == m.B {
		return fmt.Errorf("a match is between two different ideas")
	}
	if m.A > m.B {
		return fmt.Errorf("a match is recorded with its ideas in order, %s before %s", m.B, m.A)
	}
	for _, w := range []string{m.First, m.Second, m.Winner} {
		if w != "a" && w != "b" && w != "tie" {
			return fmt.Errorf("%q is not a judgement", w)
		}
	}
	if m.Winner != CombineOrders(m.First, m.Second) {
		return fmt.Errorf("the match's winner does not follow from its two orders")
	}
	if len(m.FirstReason) > MaxJudgeReason || len(m.SecondReason) > MaxJudgeReason {
		return fmt.Errorf("a judge's reason is at most %d bytes", MaxJudgeReason)
	}
	return nil
}

// CheckIdeas checks a project's ideas and matches as a whole: each valid,
// ids unique, every match between ideas the project holds, within the
// bounds. Called on every load, so a record edited by hand cannot carry
// what the code would never have written.
func (p Project) CheckIdeas() error {
	if len(p.Ideas) > MaxIdeas {
		return fmt.Errorf("%s holds %d ideas; a project keeps at most %d", p.Name, len(p.Ideas), MaxIdeas)
	}
	if len(p.Matches) > MaxMatchesKept {
		return fmt.Errorf("%s holds %d matches; a project keeps at most %d", p.Name, len(p.Matches), MaxMatchesKept)
	}
	ids := map[string]bool{}
	for _, i := range p.Ideas {
		if err := ValidateIdea(i); err != nil {
			return err
		}
		if ids[i.ID] {
			return fmt.Errorf("the idea %s is listed twice", i.ID)
		}
		ids[i.ID] = true
	}
	for _, m := range p.Matches {
		if err := validateMatch(m); err != nil {
			return err
		}
		if !ids[m.A] || !ids[m.B] {
			return fmt.Errorf("a match names an idea the project does not hold")
		}
	}
	return nil
}

// Ranked is an idea with its standing and its execution.
type Ranked struct {
	Idea
	// Rating is the Bradley–Terry strength on the Elo scale, 1200 even.
	Rating float64
	// Played is how many matches the idea has played; until it has played
	// MinMatches, or met every other idea, it is provisional, not ranked.
	Played  int
	Ranked  bool
	Outcome Outcome
}

// Outcome is what execution made of an idea.
type Outcome struct {
	Runs           int `json:"runs"`
	OK             int `json:"ok"`
	Failed         int `json:"failed"`
	DidNotRepro    int `json:"did_not_reproduce"`
	Values         int `json:"values"`
	ClaimsFromRuns int `json:"claims"`
}

// Tested says any computation ever executed this idea.
func (o Outcome) Tested() bool { return o.Runs > 0 }

// strengths fits Bradley–Terry strengths to the matches.
//
// Hunter's minorisation–maximisation update, with a tie counted as half a
// win for each side and a prior of one virtual tie against an anchor of
// strength one. The result depends only on the set of results, never on
// their order.
func strengths(ideas []Idea, matches []Match) (map[string]float64, map[string]int) {
	idx := map[string]int{}
	for k, i := range ideas {
		idx[i.ID] = k
	}
	n := len(ideas)
	wins := make([]float64, n)
	games := make([]map[int]float64, n)
	played := map[string]int{}
	for k := range games {
		games[k] = map[int]float64{}
	}
	for _, m := range matches {
		a, okA := idx[m.A]
		b, okB := idx[m.B]
		if !okA || !okB {
			continue
		}
		games[a][b]++
		games[b][a]++
		played[m.A]++
		played[m.B]++
		switch m.Winner {
		case "a":
			wins[a]++
		case "b":
			wins[b]++
		default:
			wins[a] += .5
			wins[b] += .5
		}
	}
	pi := make([]float64, n)
	for k := range pi {
		pi[k] = 1
	}
	for iter := 0; iter < 500; iter++ {
		moved := 0.0
		next := make([]float64, n)
		for k := 0; k < n; k++ {
			// The prior: one tie against the anchor, strength 1.
			num := wins[k] + .5
			den := 1 / (pi[k] + 1)
			for j, g := range games[k] {
				den += g / (pi[k] + pi[j])
			}
			next[k] = num / den
			moved = math.Max(moved, math.Abs(math.Log(next[k])-math.Log(pi[k])))
		}
		pi = next
		if moved < 1e-9 {
			break
		}
	}
	out := map[string]float64{}
	for k, i := range ideas {
		out[i.ID] = 1200 + 400*math.Log10(pi[k])
	}
	return out, played
}

// Standings fits the matches and returns the ideas, ranked first and best
// first, then the provisional ones, each with what execution made of it.
// Ties break by id, so the same record always stands the same way.
func (p Project) Standings(runs []Run) []Ranked {
	rating, played := strengths(p.Ideas, p.Matches)
	outcomes := map[string]Outcome{}
	pinned := map[string]int{}
	for _, c := range p.Claims {
		pinned[c.Run]++
	}
	for _, r := range runs {
		if r.Idea == "" {
			continue
		}
		o := outcomes[r.Idea]
		o.Runs++
		switch {
		case r.DidNotReproduce():
			o.DidNotRepro++
		case r.OK():
			o.OK++
			o.Values += len(r.Values)
		default:
			o.Failed++
		}
		o.ClaimsFromRuns += pinned[r.ID]
		outcomes[r.Idea] = o
	}
	// Ranked after MinMatches matches, or after meeting every other idea
	// when there are fewer than that to meet.
	live := 0
	for _, i := range p.Ideas {
		if len(i.Held) == 0 {
			live++
		}
	}
	need := min(MinMatches, live-1)
	out := make([]Ranked, 0, len(p.Ideas))
	for _, i := range p.Ideas {
		out = append(out, Ranked{Idea: i, Rating: rating[i.ID], Played: played[i.ID],
			Ranked: need > 0 && played[i.ID] >= need && len(i.Held) == 0, Outcome: outcomes[i.ID]})
	}
	sort.SliceStable(out, func(x, y int) bool {
		if out[x].Ranked != out[y].Ranked {
			return out[x].Ranked
		}
		if out[x].Rating != out[y].Rating {
			return out[x].Rating > out[y].Rating
		}
		return out[x].ID < out[y].ID
	})
	return out
}

// NextPairs chooses the matches a round should judge, at most max.
//
// Not every pair: that is quadratic in the ideas, two model calls each.
// Each idea that has played fewer than MinMatches is paired with the
// opponents nearest its current rating that it has not met — the Swiss
// system's rule, which is where a comparison says most — and the leaders
// then play each other until the top of the table is settled by matches
// rather than by who happened to meet whom. Held ideas never play.
func (p Project) NextPairs(max int) [][2]string {
	rating, played := strengths(p.Ideas, p.Matches)
	met := map[[2]string]bool{}
	for _, m := range p.Matches {
		met[key(m.A, m.B)] = true
	}
	var live []Idea
	for _, i := range p.Ideas {
		if len(i.Held) == 0 {
			live = append(live, i)
		}
	}
	sort.SliceStable(live, func(x, y int) bool {
		if played[live[x].ID] != played[live[y].ID] {
			return played[live[x].ID] < played[live[y].ID]
		}
		return live[x].ID < live[y].ID
	})
	var out [][2]string
	add := func(a, b string) bool {
		k := key(a, b)
		if a == b || met[k] || len(out) >= max {
			return false
		}
		met[k] = true
		played[a]++
		played[b]++
		out = append(out, k)
		return true
	}
	nearest := func(id string) []string {
		var others []string
		for _, o := range live {
			if o.ID != id {
				others = append(others, o.ID)
			}
		}
		sort.SliceStable(others, func(x, y int) bool {
			dx, dy := math.Abs(rating[others[x]]-rating[id]), math.Abs(rating[others[y]]-rating[id])
			if dx != dy {
				return dx < dy
			}
			return others[x] < others[y]
		})
		return others
	}
	for _, i := range live {
		for _, o := range nearest(i.ID) {
			if played[i.ID] >= MinMatches || len(out) >= max {
				break
			}
			add(i.ID, o)
		}
	}
	// The top of the table: the three highest play each other.
	byRating := append([]Idea(nil), live...)
	sort.SliceStable(byRating, func(x, y int) bool {
		if rating[byRating[x].ID] != rating[byRating[y].ID] {
			return rating[byRating[x].ID] > rating[byRating[y].ID]
		}
		return byRating[x].ID < byRating[y].ID
	})
	for x := 0; x < len(byRating) && x < 3; x++ {
		for y := x + 1; y < len(byRating) && y < 3; y++ {
			add(byRating[x].ID, byRating[y].ID)
		}
	}
	return out
}

// key orders a pair the way a match records it.
func key(a, b string) [2]string {
	if a > b {
		return [2]string{b, a}
	}
	return [2]string{a, b}
}

// SetVerdict records a person's conclusion about an idea. Every claim it
// rests on must be one of the project's, made by a computation that ran the
// idea: a verdict is about what the work produced.
func SetVerdict(p *Project, runs []Run, id, outcome string, claims []string, note, by string, now time.Time) error {
	if !verdictOutcomes[outcome] {
		return fmt.Errorf("%q is not a verdict; it is supported, refuted or inconclusive", outcome)
	}
	k := -1
	for x := range p.Ideas {
		if p.Ideas[x].ID == id {
			k = x
		}
	}
	if k < 0 {
		return fmt.Errorf("%q is not an idea of %s", id, p.Name)
	}
	ran := map[string]bool{}
	for _, r := range runs {
		if r.Idea == id {
			ran[r.ID] = true
		}
	}
	if len(ran) == 0 {
		return fmt.Errorf("%s has not been run: a verdict follows a computation, run one with --idea %s", id, id)
	}
	for _, name := range claims {
		found := false
		for _, c := range p.Claims {
			if c.Name == name && ran[c.Run] {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("%q is not a claim made by a computation that ran %s", name, id)
		}
	}
	note = plaintext.Clean(strings.TrimSpace(note))
	if len(note) > MaxVerdictNote {
		return fmt.Errorf("a verdict's note is at most %d bytes", MaxVerdictNote)
	}
	p.Ideas[k].Verdict = &Verdict{Outcome: outcome, Claims: claims, Note: note, By: by, At: now}
	return nil
}

// ReadIdeas reads what a model proposed: one JSON array of titles and
// hypotheses, strictly, and nothing after it.
//
// A wrapper of markdown fences is tolerated because models write it anyway;
// everything else — prose, a nested object, a second value — is refused
// rather than guessed at. Text is cleaned of invisible characters and
// screened for instructions to a model. The ids and the rest of an idea's
// record are this program's to give.
func ReadIdeas(answer []byte, now time.Time, model, by string, afterData bool) ([]Idea, error) {
	var drafts []struct {
		Title      string `json:"title"`
		Hypothesis string `json:"hypothesis"`
	}
	if err := decodeOne(answer, &drafts); err != nil {
		return nil, fmt.Errorf("the model's answer is not one JSON array of ideas: %w", err)
	}
	if len(drafts) == 0 {
		return nil, fmt.Errorf("the model proposed no ideas")
	}
	var out []Idea
	for _, d := range drafts {
		id, err := NewIdeaID()
		if err != nil {
			return nil, err
		}
		i := Idea{ID: id, Title: strings.TrimSpace(plaintext.Clean(d.Title)),
			Hypothesis: strings.TrimSpace(plaintext.Clean(d.Hypothesis)),
			Model:      model, By: by, At: now, AfterData: afterData}
		if err := ValidateIdea(i); err != nil {
			return nil, err
		}
		i.Held = screen(i.Title + "\n" + i.Hypothesis)
		out = append(out, i)
	}
	return out, nil
}

// screen is the planted-instruction check, set by the caller that has the
// screening rules; nil screens nothing. A variable so this package does not
// import the assistant's.
var screen = func(string) []string { return nil }

// SetScreen sets the check new ideas and critiques are screened with.
func SetScreen(f func(string) []string) {
	if f != nil {
		screen = f
	}
}

// ReadCritiques reads the model's critiques of its ideas: one JSON array of
// ids and critiques, strictly. An id that was not among the new ideas is
// refused: a critique of an idea that was not proposed is the model editing
// the record.
func ReadCritiques(answer []byte, newIDs map[string]bool, into map[string]string) error {
	var arr []struct {
		ID       string `json:"id"`
		Critique string `json:"critique"`
	}
	if err := decodeOne(answer, &arr); err != nil {
		return fmt.Errorf("the model's critiques are not one JSON array: %w", err)
	}
	for _, c := range arr {
		if !newIDs[c.ID] {
			return fmt.Errorf("the model critiqued %q, which was not among the new ideas", c.ID)
		}
		crit := strings.TrimSpace(plaintext.Clean(c.Critique))
		if len(crit) > MaxCritique {
			return fmt.Errorf("%s: a critique is at most %d bytes", c.ID, MaxCritique)
		}
		into[c.ID] = crit
	}
	return nil
}

// ReadJudgment reads one pairwise verdict, in the terms of the prompt the
// model saw: "a" is the hypothesis it was shown first.
func ReadJudgment(answer []byte) (winner, reason string, err error) {
	var v struct {
		Winner string `json:"winner"`
		Reason string `json:"reason"`
	}
	if err := decodeOne(answer, &v); err != nil {
		return "", "", fmt.Errorf("the judgement is not one JSON object: %w", err)
	}
	switch v.Winner {
	case "a", "b", "tie":
	default:
		return "", "", fmt.Errorf("%q is not a judgement", v.Winner)
	}
	reason = strings.TrimSpace(plaintext.Clean(v.Reason))
	if len(reason) > MaxJudgeReason {
		reason = clipUTF8(reason, MaxJudgeReason)
	}
	return v.Winner, reason, nil
}

// decodeOne decodes exactly one JSON value, strictly, from a model's answer
// with any markdown fence around it taken off.
func decodeOne(answer []byte, into any) error {
	dec := json.NewDecoder(strings.NewReader(stripFences(string(answer))))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("there is more after the first JSON value")
	}
	return nil
}

// stripFences takes markdown code fences off an answer, if that is all that
// wraps it.
func stripFences(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	s = strings.TrimPrefix(s, "```")
	if i := strings.IndexByte(s, '\n'); i >= 0 &&
		(strings.TrimSpace(s[:i]) == "json" || strings.TrimSpace(s[:i]) == "") {
		s = s[i+1:]
	}
	return strings.TrimSuffix(strings.TrimSpace(s), "```")
}

// clipUTF8 cuts a string to at most n bytes at a character boundary.
func clipUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// Duplicates names the existing ideas a new one repeats, if any.
//
// Word overlap above 0.85 (Dice, over words with punctuation taken off) is
// a repeat — unless the two differ in a word that turns a claim around: an
// idea and its negation share almost every word and are the two hypotheses
// a project most needs, not one hypothesis twice.
func (p Project) Duplicates(candidate Idea) []string {
	words := wordSet(candidate.Title + " " + candidate.Hypothesis)
	var dups []string
	for _, i := range p.Ideas {
		other := wordSet(i.Title + " " + i.Hypothesis)
		if overlap(words, other) >= 0.85 && !turnsAround(words, other) {
			dups = append(dups, i.ID)
		}
	}
	return dups
}

// turners are the words whose presence in one statement and not the other
// changes what is claimed.
var turners = []string{"not", "no", "never", "without", "cannot", "doesn't", "don't", "isn't",
	"increases", "decreases", "increase", "decrease", "raises", "lowers", "raise", "lower",
	"higher", "more", "less", "fewer", "faster", "slower", "before", "after"}

func turnsAround(a, b map[string]bool) bool {
	for _, w := range turners {
		if a[w] != b[w] {
			return true
		}
	}
	return false
}

func wordSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '\''
	}) {
		out[w] = true
	}
	return out
}

func overlap(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	shared := 0
	for w := range a {
		if b[w] {
			shared++
		}
	}
	return 2.0 * float64(shared) / float64(len(a)+len(b))
}
