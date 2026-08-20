package assist

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/tmpl"
)

// The prompt told the model a language smaller than the one it was writing for.
//
// "There are no filters, no function calls, no arithmetic, no includes." Three
// of those four are true. There are sixteen filters, and have been for a long
// time — the sentence was written when there were none, and nothing made it
// wrong when they arrived.
//
// Nothing surfaces this. A model told the language has no filters writes
// templates that render, so every test passes and every output looks fine;
// what is missing is a `| slug` that never got written and a value uppercased
// by storing it a second time.
//
// So the prompt is generated from the filter table, and this is the check that
// it still is.
func TestThePromptNamesEveryFilterTheRendererHas(t *testing.T) {
	p := systemPrompt()

	names := tmpl.FilterNames()
	if len(names) == 0 {
		t.Fatal("the renderer reports no filters at all; this test would " +
			"pass trivially and prove nothing")
	}
	for _, name := range names {
		if !strings.Contains(p, name) {
			t.Errorf("the renderer has a %q filter and the prompt does not "+
				"mention it, so the model will never use it", name)
		}
	}
	t.Logf("%d filter(s) checked", len(names))
}

// The exact sentence that was wrong, so nobody writes it again. A model that
// believes this produces worse templates and no error.
func TestThePromptDoesNotClaimThereAreNoFilters(t *testing.T) {
	p := strings.ToLower(systemPrompt())
	for _, claim := range []string{"no filters", "there are no filter"} {
		if strings.Contains(p, claim) {
			t.Errorf("the prompt says %q. There are %d.",
				claim, len(tmpl.FilterNames()))
		}
	}
}

// The three that are true have to stay in, or the prompt stops describing the
// property the language exists for. A model that thinks it may call a function
// writes a template the renderer refuses, which is a worse failure than a
// missing filter: the page does not render at all.
func TestThePromptStillRefusesWhatTheLanguageDoesNotHave(t *testing.T) {
	p := systemPrompt()
	for _, absent := range []string{
		"no function calls", "no arithmetic", "no includes", "no comparisons",
	} {
		if !strings.Contains(p, absent) {
			t.Errorf("the prompt no longer says %q, and the language still "+
				"has none of it", absent)
		}
	}
	// The refusal, not the token. Checking only for "{% raw %}" passed a
	// sabotage that changed "Never use {% raw %}" into "Use {% raw %} when you
	// need to" — the string was still there and the instruction was inverted.
	if !strings.Contains(p, "Never use {% raw %}") {
		t.Error("the prompt no longer forbids {% raw %}, which is the one " +
			"construct that turns escaping off. Mentioning it is not enough; " +
			"the prompt has to refuse it.")
	}
}

// A filter argument is a literal and can never name another value. That is the
// line between a filter set and an expression language, and a model that
// thinks otherwise writes templates the parser rejects.
func TestThePromptSaysAnArgumentIsALiteral(t *testing.T) {
	if !strings.Contains(systemPrompt(), "never name another value") {
		t.Error("the prompt does not say a filter argument is a literal")
	}
}
