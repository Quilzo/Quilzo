package brand

import (
	"strings"
	"testing"
)

func compiled(t *testing.T, r Rules) *Rules {
	t.Helper()
	if err := r.Compile(); err != nil {
		t.Fatal(err)
	}
	return &r
}

// The design, in one test: the claim is refused, and then the same claim with
// its substantiation is allowed.
//
// This is the difference between this and a word list. A rule that fires on
// copy which is actually true is a rule an author overrides once and then
// always, and the control becomes decoration.
func TestAClaimIsAllowedOnceItIsSubstantiated(t *testing.T) {
	r := compiled(t, Rules{Terms: []Term{
		{Match: "guaranteed", Needs: "guarantee_terms", Why: "somebody has to honour it"},
	}})

	found := r.Check("kettle", map[string]any{
		"description": "Guaranteed for two years.",
	})
	if len(found) != 1 {
		t.Fatalf("an unsubstantiated guarantee was allowed: %v", found)
	}
	if found[0].Needs != "guarantee_terms" {
		t.Errorf("the finding does not say what would make it sayable: %+v", found[0])
	}
	// The message has to be actionable, or it gets overridden rather than fixed.
	if !strings.Contains(found[0].String(), "guarantee_terms") {
		t.Errorf("the message does not tell the author what to do: %s", found[0])
	}

	ok := r.Check("kettle", map[string]any{
		"description":     "Guaranteed for two years.",
		"guarantee_terms": "https://example.com/guarantee",
	})
	if len(ok) != 0 {
		t.Errorf("a substantiated guarantee was still refused: %v", ok)
	}
}

// Present-but-empty is absent.
//
// A rule satisfied by a blank box is worse than no rule, because the claim now
// looks substantiated to everybody reading the record.
func TestAnEmptySubstantiationDoesNotCount(t *testing.T) {
	r := compiled(t, Rules{Terms: []Term{
		{Match: "guaranteed", Needs: "guarantee_terms", Why: "somebody has to honour it"},
	}})
	for _, blank := range []any{"", "   ", "\n", nil, 0} {
		found := r.Check("kettle", map[string]any{
			"description": "Guaranteed for life.", "guarantee_terms": blank,
		})
		if len(found) == 0 {
			t.Errorf("guarantee_terms = %#v satisfied the rule", blank)
		}
	}
}

// Some claims nothing makes sayable, and that category is real.
func TestSomeClaimsHaveNoSubstantiation(t *testing.T) {
	r := compiled(t, Rules{Terms: []Term{
		{Match: "cures", Why: "no consumer good may be described as curing anything"},
	}})
	found := r.Check("balm", map[string]any{
		"description":  "Cures dry skin.",
		"evidence_url": "https://example.com/study",
		"cures":        "yes",
	})
	if len(found) != 1 {
		t.Fatalf("an unconditional rule was satisfied by adding a field: %v", found)
	}
	if found[0].Needs != "" {
		t.Errorf("it offered a way to make it sayable: %+v", found[0])
	}
}

// Whole words, so a rule about one thing does not fire on another.
//
// Substring matching is why these features get switched off: a rule about
// "free" that fires on "freedom of movement" trains the author to stop reading.
func TestMatchingIsOnWholeWords(t *testing.T) {
	r := compiled(t, Rules{Terms: []Term{
		{Match: "free", Why: "free means no cost to the customer in any circumstance"},
		{Match: "car", Why: "a test rule"},
	}})
	clean := r.Check("page", map[string]any{
		"body": "Freedom of movement, and scarcity of parts. Carefully made.",
	})
	if len(clean) != 0 {
		t.Errorf("a rule fired inside a longer word: %v", clean)
	}
	fires := r.Check("page", map[string]any{"body": "Free delivery."})
	if len(fires) != 1 {
		t.Errorf("a whole-word match did not fire: %v", fires)
	}
}

// A phrase split across a line break is still the phrase.
func TestAPhraseMatchesAcrossWhitespace(t *testing.T) {
	r := compiled(t, Rules{Terms: []Term{
		{Match: "clinically proven", Needs: "evidence_url", Why: "needs the study"},
	}})
	for _, body := range []string{
		"clinically proven", "Clinically  proven", "clinically\nproven",
		"CLINICALLY PROVEN",
	} {
		if got := r.Check("p", map[string]any{"body": body}); len(got) != 1 {
			t.Errorf("%q did not match", body)
		}
	}
}

// Substantiation is a property of the content, not of the field the claim is in.
//
// The guarantee terms live in their own field, which is precisely why the claim
// is allowed in the description. A per-field rule would demand the terms be
// repeated inside the sentence.
func TestSubstantiationIsReadFromTheWholeRecord(t *testing.T) {
	r := compiled(t, Rules{Terms: []Term{
		{Match: "guaranteed", Needs: "guarantee_terms",
			Fields: []string{"description"}, Why: "somebody has to honour it"},
	}})
	if got := r.Check("kettle", map[string]any{
		"description":     "Guaranteed for two years.",
		"guarantee_terms": "https://example.com/terms",
	}); len(got) != 0 {
		t.Errorf("the claim was refused despite substantiation elsewhere: %v", got)
	}
	// And a rule scoped to a field ignores the others.
	if got := r.Check("kettle", map[string]any{
		"summary": "Guaranteed for two years.",
	}); len(got) != 0 {
		t.Errorf("a rule scoped to description fired on summary: %v", got)
	}
}

// Only language is searched.
//
// Stringifying every field to run a regex over it finds "true" inside a boolean
// and reports it as a word somebody wrote.
func TestOnlyTextFieldsAreSearched(t *testing.T) {
	r := compiled(t, Rules{Terms: []Term{
		{Match: "true", Why: "a test rule"},
		{Match: "12", Why: "a test rule"},
	}})
	if got := r.Check("p", map[string]any{
		"in_stock": true, "quantity": 12, "featured": false,
	}); len(got) != 0 {
		t.Errorf("a rule fired on a non-text field: %v", got)
	}
	// A list of strings is copy and is searched.
	if got := r.Check("p", map[string]any{
		"bullets": []any{"made well", "true to size"},
	}); len(got) != 1 {
		t.Errorf("a list of strings was not searched: %v", got)
	}
}

// A rules file that cannot mean anything is refused at the top.
func TestRulesThatCannotMeanAnythingAreRefused(t *testing.T) {
	for name, r := range map[string]Rules{
		"no phrase": {Terms: []Term{{Why: "because"}}},
		"no reason": {Terms: []Term{{Match: "guaranteed"}}},
		"duplicate": {Terms: []Term{
			{Match: "free", Why: "one"}, {Match: "FREE", Why: "two"}}},
	} {
		if err := r.Compile(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// An uncompiled rule reports itself rather than silently checking nothing.
//
// The quiet failure this avoids: rules load, one fails to compile, and every
// page passes a gate that is examining nothing.
func TestAnUncompiledRuleIsReportedRatherThanSkipped(t *testing.T) {
	r := Rules{Terms: []Term{{Match: "cures", Why: "no"}}} // never compiled
	got := r.Check("p", map[string]any{"body": "Cures everything."})
	if len(got) != 1 {
		t.Fatal("an uncompiled rule checked nothing and said nothing")
	}
	if !strings.Contains(got[0].Why, "never compiled") {
		t.Errorf("it did not say the rule had not been compiled: %+v", got[0])
	}
}

// The starter rules are mostly substantiable, which is what a healthy file
// looks like.
func TestTheStarterRulesAreMostlySubstantiable(t *testing.T) {
	r := Starter()
	if err := r.Compile(); err != nil {
		t.Fatalf("the rules this ships do not compile: %v", err)
	}
	var conditional int
	for _, t := range r.Terms {
		if t.Needs != "" {
			conditional++
		}
	}
	if conditional*2 < len(r.Terms) {
		t.Errorf("%d of %d starter rules can be substantiated. A file where "+
			"most terms are unconditional is a word list wearing a costume, "+
			"and it is the shape that gets switched off",
			conditional, len(r.Terms))
	}
}

// A claim inside a section is a claim.
//
// Check read a field's own value and stopped, so the identical sentence was
// caught at the top level of a page and invisible in a prose section — which is
// where the shipped layouts put prose. The gate that refuses a publication for
// an unsubstantiated claim passed the page that made one, and it did it on the
// content shape the product recommends.
//
// Demonstrated by writing the same sentence at two depths on a real store and
// watching one of them publish.
func TestAClaimInsideASectionIsFound(t *testing.T) {
	r := &Rules{Terms: []Term{{
		Match: "guaranteed", Needs: "guarantee_terms",
		Why: "a guarantee is a promise somebody has to honour",
	}}}
	if err := r.Compile(); err != nil {
		t.Fatal(err)
	}

	nested := map[string]any{
		"title": "Our cloth",
		"sections": []any{
			map[string]any{"prose": map[string]any{
				"paragraphs": []any{"Guaranteed for life."},
			}},
		},
	}
	found := r.Check("index", nested)
	if len(found) != 1 {
		t.Fatalf("a claim inside a section produced %d finding(s); at the top "+
			"level the same sentence is caught, and the layouts put prose in "+
			"sections", len(found))
	}
	if found[0].Field != "sections" {
		t.Errorf("the finding points at %q rather than the field the claim is "+
			"under", found[0].Field)
	}

	// And it can be satisfied where the claim is: an author writing a
	// guarantee inside a section puts its terms in that section.
	beside := map[string]any{
		"title": "Our cloth",
		"sections": []any{
			map[string]any{"prose": map[string]any{
				"guarantee_terms": "https://example.com/guarantee",
				"paragraphs":      []any{"Guaranteed for life."},
			}},
		},
	}
	if rest := r.Check("index", beside); len(rest) != 0 {
		t.Errorf("evidence in the same section did not satisfy the rule, so "+
			"the only way to answer it is to move the evidence away from what "+
			"it evidences: %v", rest)
	}

	// A blank evidence field is still absent — a rule satisfied by an empty box
	// is worse than no rule.
	blank := map[string]any{"sections": []any{
		map[string]any{"prose": map[string]any{
			"guarantee_terms": "   ",
			"paragraphs":      []any{"Guaranteed for life."},
		}},
	}}
	if len(r.Check("index", blank)) == 0 {
		t.Error("a blank evidence field satisfied the rule")
	}

	// One finding per rule per field: a claim repeated in six paragraphs is one
	// thing to fix.
	repeated := map[string]any{"sections": []any{
		map[string]any{"prose": map[string]any{"paragraphs": []any{
			"Guaranteed for life.", "Guaranteed, again.", "Guaranteed."}}},
	}}
	if n := len(r.Check("index", repeated)); n != 1 {
		t.Errorf("a claim repeated three times produced %d findings", n)
	}
}
