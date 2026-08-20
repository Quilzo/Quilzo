package oscal

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/posture"
)

func scan(t *testing.T) ([]posture.Finding, map[string]posture.Rule) {
	t.Helper()
	rules := posture.RuleIndex()
	if len(rules) < 20 {
		t.Fatalf("%d rules; this test would check almost nothing", len(rules))
	}
	// Two findings against real rules, so the control mappings are the real
	// ones rather than fixtures that cannot go out of date.
	var picked []posture.Finding
	for id, r := range rules {
		if len(r.Controls) == 0 {
			continue
		}
		picked = append(picked, posture.Finding{
			Rule: id, Title: r.Title, Severity: r.Severity,
			Resource: "the deployment",
			Detail:   "a finding constructed for this test",
		})
		if len(picked) == 2 {
			break
		}
	}
	if len(picked) != 2 {
		t.Fatal("no rules carry control mappings, so nothing here is exercised")
	}
	return picked, rules
}

// The required fields, at every level the schema names them.
//
// Read from NIST's published schema rather than from an example: an example
// shows one valid document, and the schema shows which parts of it were
// load-bearing.
func TestTheDocumentCarriesEveryRequiredField(t *testing.T) {
	findings, rules := scan(t)
	doc, err := From(findings, rules, time.Now(), Options{System: "test"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}

	// The root has exactly one key, because the schema's own required list is
	// ["assessment-results"] — a flat object fails before anything inside it
	// is read.
	ar, ok := m["assessment-results"].(map[string]any)
	if !ok {
		t.Fatal("the document is not nested under assessment-results")
	}
	for _, k := range []string{"uuid", "metadata", "import-ap", "results"} {
		if _, there := ar[k]; !there {
			t.Errorf("assessment-results has no %q", k)
		}
	}
	meta := ar["metadata"].(map[string]any)
	for _, k := range []string{"title", "last-modified", "version", "oscal-version"} {
		if v, there := meta[k]; !there || v == "" {
			t.Errorf("metadata has no %q", k)
		}
	}
	if meta["oscal-version"] != Version {
		t.Errorf("oscal-version is %v, want %s", meta["oscal-version"], Version)
	}

	results := ar["results"].([]any)
	if len(results) == 0 {
		t.Fatal("no results; the schema requires at least one")
	}
	res := results[0].(map[string]any)
	for _, k := range []string{"uuid", "title", "description", "start", "reviewed-controls"} {
		if _, there := res[k]; !there {
			t.Errorf("result has no %q", k)
		}
	}

	for _, o := range res["observations"].([]any) {
		ob := o.(map[string]any)
		for _, k := range []string{"uuid", "description", "methods", "collected"} {
			if _, there := ob[k]; !there {
				t.Errorf("observation has no %q", k)
			}
		}
		methods := ob["methods"].([]any)
		if len(methods) == 0 {
			t.Error("observation has an empty methods array; the schema wants at least one")
		}
		for _, mth := range methods {
			switch mth {
			case "EXAMINE", "INTERVIEW", "TEST", "UNKNOWN":
			default:
				t.Errorf("observation method %v is not one the schema allows", mth)
			}
		}
	}

	for _, f := range res["findings"].([]any) {
		fi := f.(map[string]any)
		for _, k := range []string{"uuid", "title", "description", "target"} {
			if _, there := fi[k]; !there {
				t.Errorf("finding has no %q", k)
			}
		}
		tgt := fi["target"].(map[string]any)
		for _, k := range []string{"type", "target-id", "status"} {
			if _, there := tgt[k]; !there {
				t.Errorf("finding target has no %q", k)
			}
		}
		if tgt["type"] != "objective-id" && tgt["type"] != "statement-id" {
			t.Errorf("finding target type %v is not one the schema allows", tgt["type"])
		}
		st := tgt["status"].(map[string]any)
		if st["state"] != "satisfied" && st["state"] != "not-satisfied" {
			t.Errorf("status state %v is not one the schema allows; OSCAL has "+
				"two values and a scanner wanting to say \"probably\" has to "+
				"pick one", st["state"])
		}
	}
}

// Every UUID is a real version-4 UUID.
//
// Written by hand because there is no require block, which means the format is
// this project's problem. A malformed uuid is refused by an assessor's tooling
// after the package is submitted, which is the worst time to find out.
func TestEveryUUIDIsWellFormed(t *testing.T) {
	findings, rules := scan(t)
	doc, err := From(findings, rules, time.Now(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(doc)
	re := regexp.MustCompile(
		`"uuid":"([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})"`)
	all := regexp.MustCompile(`"uuid":"([^"]*)"`).FindAllStringSubmatch(string(b), -1)
	good := re.FindAllString(string(b), -1)
	if len(all) == 0 {
		t.Fatal("no uuids at all")
	}
	if len(good) != len(all) {
		t.Errorf("%d of %d uuids are not version-4 UUIDs", len(all)-len(good), len(all))
		for _, m := range all[:min(3, len(all))] {
			t.Logf("  %s", m[1])
		}
	}
	// And they are distinct: reusing one merges two findings in an assessor's
	// tooling rather than erroring.
	seen := map[string]bool{}
	for _, m := range all {
		if seen[m[1]] {
			t.Errorf("uuid %s appears twice", m[1])
		}
		seen[m[1]] = true
	}
}

// reviewed-controls lists what was checked, and nothing else.
//
// The field most often overstated. Claiming to have reviewed a control that
// nothing checked is precisely what makes automated evidence worthless, and it
// is invisible unless somebody compares the list against the rules.
func TestReviewedControlsListsOnlyWhatTheRulesCover(t *testing.T) {
	findings, rules := scan(t)
	doc, err := From(findings, rules, time.Now(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	real := map[string]bool{}
	for _, r := range rules {
		for _, c := range r.Controls {
			real[strings.ToLower(c)] = true
		}
	}
	listed := doc.AssessmentResults.Results[0].
		ReviewedControls.ControlSelections[0].IncludeControls
	if len(listed) == 0 {
		t.Fatal("no controls listed as reviewed")
	}
	for _, c := range listed {
		if !real[c.ControlID] {
			t.Errorf("%s is listed as reviewed and no rule bears on it", c.ControlID)
		}
	}
	if len(listed) != len(real) {
		t.Errorf("%d controls listed, %d covered by rules", len(listed), len(real))
	}
}

// A rule touching three controls produces three findings.
//
// An assessor reads by control. One finding referencing three would be
// invisible under two of them.
func TestOneFindingPerControlTheRuleBearsOn(t *testing.T) {
	rules := posture.RuleIndex()
	var multi string
	var want int
	for id, r := range rules {
		if len(r.Controls) > want {
			multi, want = id, len(r.Controls)
		}
	}
	if want < 2 {
		t.Skip("no rule maps to more than one control")
	}
	f := []posture.Finding{{Rule: multi, Title: "t", Detail: "d",
		Severity: posture.Severity("high")}}
	doc, err := From(f, rules, time.Now(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := len(doc.AssessmentResults.Results[0].Findings)
	if got != want {
		t.Errorf("one finding against a rule covering %d controls produced "+
			"%d OSCAL findings, want %d", want, got, want)
	}
	// And exactly one observation, because one thing was looked at.
	if n := len(doc.AssessmentResults.Results[0].Observations); n != 1 {
		t.Errorf("%d observations for one finding, want 1", n)
	}
}

// The document says what it is not.
//
// A machine-readable artefact travels further than the conversation that
// produced it, so "this is not a certification" has to be inside the file.
func TestTheDocumentDisclaimsBeingACertification(t *testing.T) {
	findings, rules := scan(t)
	doc, err := From(findings, rules, time.Now(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	remarks := doc.AssessmentResults.Metadata.Remarks
	for _, want := range []string{"not a certification", "compliant"} {
		if !strings.Contains(remarks, want) {
			t.Errorf("the metadata remarks do not mention %q: %q", want, remarks)
		}
	}
}

// Two runs over the same input diff cleanly apart from the identifiers.
func TestTheOrderIsDeterministic(t *testing.T) {
	findings, rules := scan(t)
	at := time.Now()
	a, _ := From(findings, rules, at, Options{})
	b, _ := From(findings, rules, at, Options{})

	ids := regexp.MustCompile(`"uuid":"[^"]*"`)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if ids.ReplaceAllString(string(ja), "") != ids.ReplaceAllString(string(jb), "") {
		t.Error("two runs over the same scan differ beyond their uuids, so an " +
			"assessor comparing months sees a reshuffle rather than a change")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
