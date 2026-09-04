package public

import (
	"encoding/json"

	"github.com/quilzo/quilzo/internal/csp"
	"net/http/httptest"
	"strings"
	"testing"
)

// The whole point: instant navigation without loosening the policy.
//
// The Speculation Rules API is normally an inline script, and this site sends
// script-src 'none'. Reaching for the element would have meant either a
// feature that silently never runs or a policy widened for a speed
// optimisation — and a policy widened once is widened permanently.
func TestSpeculationDoesNotWidenTheContentSecurityPolicy(t *testing.T) {
	// The generated policy, which is what a real site sends. defaultCSP is a
	// fallback for a Site built without a generator, and public.go says so:
	// asserting against it would be asserting about a test fixture.
	policy := (&csp.Policy{}).Build()
	if !strings.Contains(policy, "script-src 'none'") {
		t.Fatalf("this site no longer forbids script, so the reason this "+
			"feature is a header rather than an element is gone: %s", policy)
	}
	if strings.Contains(policy, "unsafe-inline") &&
		strings.Contains(policy, "script-src 'self'") {
		t.Errorf("the policy permits inline script: %s", policy)
	}
	// And no element was introduced anywhere, which is the mistake this
	// design exists to avoid: a speculationrules script tag is valid markup,
	// renders no error, and never runs.
	if strings.Contains(SpeculatePrefetch.rules(), "<script") {
		t.Error("the rules are wrapped in a script element")
	}
}

// A document response points at the rules, and other responses do not.
//
// Only HTML: a stylesheet has nothing to speculate about, and the header on
// every response is bytes spent on nothing.
func TestOnlyADocumentResponseNamesTheRules(t *testing.T) {
	st := &Site{}

	page := httptest.NewRecorder()
	page.Header().Set("Content-Type", "text/html; charset=utf-8")
	st.setSpeculationHeader(page)
	if got := page.Header().Get("Speculation-Rules"); got != `"`+SpeculationPath+`"` {
		t.Errorf("an HTML response says %q, want %q", got,
			`"`+SpeculationPath+`"`)
	}

	asset := httptest.NewRecorder()
	asset.Header().Set("Content-Type", "text/css")
	st.setSpeculationHeader(asset)
	if got := asset.Header().Get("Speculation-Rules"); got != "" {
		t.Errorf("a stylesheet response says %q", got)
	}
}

// The rules document has to be valid JSON and served as the one media type a
// browser will accept for it. Anything else is ignored, silently.
func TestTheRulesAreServedAsTheTypeABrowserAccepts(t *testing.T) {
	st := &Site{}
	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec,
		httptest.NewRequest("GET", SpeculationPath, nil))

	if rec.Code != 200 {
		t.Fatalf("the rules answered %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != SpeculationType {
		t.Errorf("Content-Type is %q, want %q. A browser ignores any other "+
			"type and reports nothing", got, SpeculationType)
	}

	var parsed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("the rules are not JSON: %v\n%s", err, rec.Body.String())
	}
	list, ok := parsed["prefetch"].([]any)
	if !ok || len(list) == 0 {
		t.Fatalf("the default rules do not prefetch: %v", parsed)
	}
	rule, _ := list[0].(map[string]any)
	if rule["eagerness"] != "moderate" {
		t.Errorf("eagerness is %v; anything eager spends a reader's "+
			"bandwidth on links they never touched", rule["eagerness"])
	}
}

// Turning it off means no header and no document, rather than an empty one.
func TestSpeculationCanBeTurnedOff(t *testing.T) {
	st := &Site{Speculate: SpeculateOff}

	page := httptest.NewRecorder()
	page.Header().Set("Content-Type", "text/html; charset=utf-8")
	st.setSpeculationHeader(page)
	if got := page.Header().Get("Speculation-Rules"); got != "" {
		t.Errorf("a site with speculation off still sends %q", got)
	}

	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec,
		httptest.NewRequest("GET", SpeculationPath, nil))
	if rec.Code != 404 {
		t.Errorf("the rules document answered %d with speculation off",
			rec.Code)
	}
}

// Prerender is available and is not what a site does unless it says so.
func TestPrerenderIsOptIn(t *testing.T) {
	def := (&Site{}).speculation()
	if def != SpeculatePrefetch {
		t.Errorf("the default is %q; prerender downloads and lays out pages "+
			"nobody may read", def)
	}

	st := &Site{Speculate: SpeculatePrerender}
	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec,
		httptest.NewRequest("GET", SpeculationPath, nil))
	var parsed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed["prerender"]; !ok {
		t.Errorf("a site asking for prerender got %v", parsed)
	}
}

// A setting nobody recognises must not become one that speculates anyway.
func TestAnUnknownSettingSpeculatesNothing(t *testing.T) {
	st := &Site{Speculate: Speculation("aggressive")}
	if got := st.speculation(); got != SpeculateOff {
		t.Errorf("an unrecognised setting resolved to %q", got)
	}
}

// The rules must not speculate on things that are not pages.
func TestTheRulesExcludeWhatIsNotADocument(t *testing.T) {
	body := SpeculatePrefetch.rules()
	for _, want := range []string{"/media/*", "nofollow"} {
		if !strings.Contains(body, want) {
			t.Errorf("the rules do not exclude %q:\n%s", want, body)
		}
	}
	if !strings.Contains(body, `"source": "document"`) {
		t.Error("the rules do not restrict themselves to document navigations")
	}
}
