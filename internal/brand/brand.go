// Package brand refuses claims the business cannot stand behind.
//
// # Why a word list is the wrong feature, and what this is instead
//
// Every content tool that has tried this shipped a list of forbidden words and
// a warning banner, and every team turned it off within a month. The reason is
// always the same: the list is right about the word and wrong about the
// sentence. A shop selling a kettle cannot use "guaranteed" even when it has a
// two-year guarantee written down, so the rule fires on the copy that is
// actually true, an author overrides it once, then overrides it always, and the
// control is decoration.
//
// So the unit here is not a word. It is a claim and its substantiation. A term
// is blocked *unless* the same content carries the field that backs it up:
// "guaranteed" is fine on a page with guarantee_terms, "clinically proven" is
// fine with evidence_url, and "cures" is fine nowhere because nothing this
// system can check would make it fine.
//
// That inverts what the author experiences. The message is not "you may not say
// that", which invites an override. It is "say that and also say where it comes
// from", which is a thing they can do — and when they cannot do it, they have
// learnt something true about the claim.
//
// # Where it runs
//
// At publish, with the other content gates, before the gate about people. A
// claim nobody can substantiate should be caught before two colleagues are
// asked to approve it, for the same reason an accessibility failure is: asking
// somebody to review what the tool is going to refuse teaches them that
// approval is a formality.
//
// It runs over pages and over records, because in a shop the product copy is a
// record and gating only pages would gate the part nobody sells anything with.
//
// # What this does not claim to be
//
// Not a compliance certification, not legal advice, and not adversarial. An
// author who wants to route around it can spell a word differently and this
// will not notice, which is fine: the person writing the copy is not the
// attacker, they are the colleague who did not know that "hypoallergenic" is a
// regulated term in the market they just expanded into. Rules are for people
// trying to get it right.
package brand

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Term is one claim, and what would make it sayable.
type Term struct {
	// Match is the phrase, matched case-insensitively on word boundaries.
	// Whole words, so "car" does not fire inside "scarcity".
	Match string `json:"match"`

	// Why explains the rule to whoever hits it. Required: a refusal an author
	// cannot act on is one they route around, and "blocked term" is not a
	// reason, it is a restatement.
	Why string `json:"why"`

	// Needs names a field that substantiates the claim. When the content
	// carries it, non-empty, the term is allowed.
	//
	// This is the whole design. A term with no Needs is one nothing can make
	// sayable, which is a real category — but it should be small, and a rules
	// file where every term is unconditional is a word list wearing a costume.
	Needs string `json:"needs,omitempty"`

	// Fields, if set, limits the rule to named fields. Empty means every
	// field, which is the safe default: a claim in a summary is a claim.
	Fields []string `json:"fields,omitempty"`

	re *regexp.Regexp
}

// Rules are what this install refuses to say.
type Rules struct {
	Terms []Term `json:"terms"`
}

// Finding is one claim found without its substantiation.
type Finding struct {
	// Where is the page or record the claim is in.
	Where string `json:"where"`
	// Field is which field of it.
	Field string `json:"field"`
	// Term is the phrase that fired.
	Term string `json:"term"`
	// Why is the rule's explanation.
	Why string `json:"why"`
	// Needs is the field that would make it sayable, if any.
	Needs string `json:"needs,omitempty"`
}

func (f Finding) String() string {
	s := fmt.Sprintf("%s: %q — %s", f.Where, f.Term, f.Why)
	if f.Field != "" {
		s = fmt.Sprintf("%s (%s): %q — %s", f.Where, f.Field, f.Term, f.Why)
	}
	if f.Needs != "" {
		s += fmt.Sprintf("\n      say it and set %s, or say something else",
			f.Needs)
	}
	return s
}

// Compile prepares the rules and refuses ones that cannot mean anything.
//
// Called before any content is checked, so a malformed rules file is a
// configuration error at the top rather than a claim that quietly stops being
// checked halfway down the list.
func (r *Rules) Compile() error {
	seen := map[string]bool{}
	for i := range r.Terms {
		t := &r.Terms[i]
		phrase := strings.TrimSpace(t.Match)
		if phrase == "" {
			return fmt.Errorf("a rule has no phrase to match")
		}
		if strings.TrimSpace(t.Why) == "" {
			return fmt.Errorf(
				"the rule for %q does not say why. A refusal an author cannot "+
					"act on is one they route around, and \"blocked term\" is "+
					"a restatement rather than a reason", phrase)
		}
		key := strings.ToLower(phrase)
		if seen[key] {
			return fmt.Errorf(
				"%q has two rules, and which one an author is shown would be "+
					"decided by the order they happen to be listed in", phrase)
		}
		seen[key] = true

		// Word boundaries, so a rule about "free" does not fire on "freedom",
		// and internal whitespace matches any run of it, so a phrase split
		// across a line break is still the phrase.
		parts := strings.Fields(strings.ToLower(phrase))
		for i, p := range parts {
			parts[i] = regexp.QuoteMeta(p)
		}
		t.re = regexp.MustCompile(`(?i)\b` + strings.Join(parts, `\s+`) + `\b`)
	}
	return nil
}

// Check reports every claim in one piece of content that lacks its
// substantiation.
//
// where names the page or record, for the message. fields is its content.
func (r *Rules) Check(where string, fields map[string]any) []Finding {
	var out []Finding
	// Sorted, so the same content reports the same findings in the same order
	// twice. A gate whose output reorders between runs is one nobody can diff.
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)

	for i := range r.Terms {
		t := &r.Terms[i]
		if t.re == nil {
			// Not compiled. Refusing to check silently would be the worst of
			// the options, so this is reported as a finding against the rule
			// itself.
			out = append(out, Finding{Where: where, Term: t.Match,
				Why: "this rule was never compiled, so nothing was checked " +
					"against it"})
			continue
		}
		// Substantiation is a property of the whole content, not of the field
		// the claim appears in: the guarantee terms live in their own field,
		// which is exactly why the claim is allowed in the description.
		if t.Needs != "" && has(fields, t.Needs) {
			continue
		}
		for _, name := range names {
			if !t.applies(name) {
				continue
			}
			text, ok := asText(fields[name])
			if !ok {
				continue
			}
			if m := t.re.FindString(text); m != "" {
				out = append(out, Finding{
					Where: where, Field: name, Term: m,
					Why: t.Why, Needs: t.Needs})
			}
		}
	}
	return out
}

// applies reports whether a rule looks at a given field.
func (t *Term) applies(field string) bool {
	if len(t.Fields) == 0 {
		return true
	}
	for _, f := range t.Fields {
		if strings.EqualFold(f, field) {
			return true
		}
	}
	return false
}

// has reports whether a field is present and carries something.
//
// Present-but-empty is absent. A rule satisfied by `"evidence_url": ""` is one
// satisfied by adding a blank box, which is worse than no rule because it looks
// like the claim was substantiated.
func has(fields map[string]any, name string) bool {
	for k, v := range fields {
		if !strings.EqualFold(k, name) {
			continue
		}
		text, ok := asText(v)
		return ok && strings.TrimSpace(text) != ""
	}
	return false
}

// asText renders a field for matching.
//
// Strings and lists of strings, which is what copy is. Numbers and booleans are
// deliberately not searched: a claim is language, and stringifying every field
// to run a regex over it finds "true" inside a boolean and reports it as a word
// somebody wrote.
func asText(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case []any:
		var parts []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				parts = append(parts, s)
			}
		}
		if len(parts) == 0 {
			return "", false
		}
		return strings.Join(parts, "\n"), true
	case []string:
		return strings.Join(t, "\n"), true
	default:
		return "", false
	}
}

// CheckAll runs the rules over a whole set of content.
func (r *Rules) CheckAll(content map[string]map[string]any) []Finding {
	var out []Finding
	names := make([]string, 0, len(content))
	for k := range content {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, r.Check(n, content[n])...)
	}
	return out
}

// Starter is a small set of rules that are true of most shops.
//
// Offered rather than imposed: `quilzo brand init` writes this and an operator
// edits it. Every entry has a Needs except the ones nothing could substantiate,
// which is the ratio a healthy rules file has.
func Starter() Rules {
	return Rules{Terms: []Term{
		{Match: "guaranteed", Needs: "guarantee_terms",
			Why: "a guarantee is a promise somebody has to honour, so the " +
				"terms have to be written down and linked"},
		{Match: "clinically proven", Needs: "evidence_url",
			Why: "a clinical claim needs the study it comes from"},
		{Match: "best in the world", Needs: "evidence_url",
			Why: "a superlative comparison is a factual claim about " +
				"competitors and needs a source"},
		{Match: "100% recycled", Needs: "materials_evidence",
			Why: "a materials claim is regulated in most markets and needs " +
				"the certification behind it"},
		{Match: "cures", Why: "nothing sold as a consumer good may be " +
			"described as curing anything; there is no field that would " +
			"make this sayable"},
		{Match: "risk free", Why: "no purchase is risk free, and this " +
			"phrasing is treated as misleading by most consumer regulators"},
	}}
}
