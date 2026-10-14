// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package feature

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/schema"
)

const samplesCSV = `Sample Code,Material,Status,Holder email,Received,Mass (g),Fragile,Notes
S-001,Basalt,available,,2026-09-01,12.5,yes,
S-002,Granite,checked-out,dana@example.org,2026-09-03,8,no,Cracked along one edge
S-003,Basalt,available,,2026-09-04,10,no,
S-004,Quartz,available,,2026-09-10,3.25,yes,
S-005,Granite,used-up,,2026-09-12,0,no,
`

func field(t schema.Type, name string) schema.Field {
	for _, f := range t.Fields {
		if f.Name == name {
			return f
		}
	}
	return schema.Field{}
}

// Every kind is the narrowest one all of a column's values fit.
func TestASpreadsheetBecomesAFeatureWithKindsFromItsValues(t *testing.T) {
	in, err := Infer("lab samples", []byte(samplesCSV))
	if err != nil {
		t.Fatal(err)
	}
	p := in.Package
	if err := p.Validate(Checks{}); err != nil {
		t.Fatalf("the inferred package is not usable: %v", err)
	}
	typ := p.Types[0]
	for name, want := range map[string]schema.Kind{
		"sample_code": schema.Text, "material": schema.Choice, "status": schema.Choice,
		"holder_email": schema.Email, "received": schema.Date, "mass_g": schema.Number,
		"fragile": schema.Boolean, "notes": schema.Text,
	} {
		if got := field(typ, name).Kind; got != want {
			t.Errorf("%s is %q, want %q", name, got, want)
		}
	}
	if !field(typ, "sample_code").Required || field(typ, "holder_email").Required {
		t.Error("required should mean nothing is missing in the column")
	}
	if c := field(typ, "status").Choices; strings.Join(c, ",") != "available,checked-out,used-up" {
		t.Errorf("status choices %v", c)
	}
	if len(in.Rows) != 5 || in.Rows[0]["mass_g"] != 12.5 || in.Rows[1]["mass_g"] != int64(8) || in.Rows[0]["fragile"] != true {
		t.Errorf("rows %v", in.Rows[:2])
	}
	if _, has := in.Rows[0]["holder_email"]; has {
		t.Error("an empty cell became a value")
	}
	// A package carries the definitions, never the rows.
	for _, v := range []string{"S-001", "dana@example.org", "Cracked along one edge"} {
		if strings.Contains(string(mustJSON(t, p)), v) {
			t.Errorf("the data travelled in the package: %s", v)
		}
	}
	// Email addresses are personal data: the card asks for two people.
	if c := p.MakeCard(); c.Approvers != 2 {
		t.Errorf("an address book of holders is approved by %d", c.Approvers)
	}
	if mo, _ := p.Pages[0].Body["members_only"].(bool); !mo {
		t.Error("the page is public by default")
	}
}

// A column about people that repeats is still text: as a choice its values
// would travel in the package.
func TestAColumnAboutPeopleIsNeverAChoice(t *testing.T) {
	in, err := Infer("x", []byte("customer name,tier\nAda,gold\nAda,gold\nBo,silver\nAda,silver\n"))
	if err != nil {
		t.Fatal(err)
	}
	if k := field(in.Package.Types[0], "customer_name").Kind; k != schema.Text {
		t.Errorf("customer_name is %s", k)
	}
	if strings.Contains(string(mustJSON(t, in.Package)), "Ada") {
		t.Error("a person's name travelled in the package")
	}
	if k := field(in.Package.Types[0], "tier").Kind; k != schema.Choice {
		t.Errorf("tier is %s", k)
	}
}

func TestOneOddValueMakesAColumnText(t *testing.T) {
	in, err := Infer("x", []byte("n,d\n1,2026-01-01\n2,2026-01-02\nthree,soon\n"))
	if err != nil {
		t.Fatal(err)
	}
	if k := field(in.Package.Types[0], "n").Kind; k != schema.Text {
		t.Errorf("n is %s", k)
	}
	if k := field(in.Package.Types[0], "d").Kind; k != schema.Text {
		t.Errorf("d is %s", k)
	}
}

func TestAJSONListBecomesAFeatureAndNestingIsRefused(t *testing.T) {
	in, err := Infer("books", []byte(`[{"Title":"A","Year":2001},{"Title":"B","Year":1999,"Url":"https://b.example"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if k := field(in.Package.Types[0], "year").Kind; k != schema.Number {
		t.Errorf("year is %s", k)
	}
	if _, err := Infer("books", []byte(`[{"Title":"A","Authors":["x"]}]`)); err == nil {
		t.Error("a nested value was flattened without a word")
	}
	if _, err := Infer("empty", []byte("a,b\n")); err == nil {
		t.Error("a file with no rows made a feature")
	}
}

func TestHeadingsBecomeUsableUniqueNames(t *testing.T) {
	taken := map[string]bool{}
	for _, c := range []struct{ in, want string }{
		{"Sample Code", "sample_code"}, {"sample-code", "sample_code_2"}, {"2026 total", "f_2026_total"}, {"!!!", "field"},
	} {
		if got := fieldName(c.in, taken); got != c.want {
			t.Errorf("%q became %q, want %q", c.in, got, c.want)
		}
	}
}

// What a model drafts is read for content blocks only.
func TestADraftKeepsContentBlocksAndLeavesOutReach(t *testing.T) {
	answer := "```json\n" + `{
  "name": "visits", "title": "Clinic visits", "purpose": "Book and list visits.",
  "types": [{"name": "visit", "fields": [{"name": "when", "kind": "date", "required": true}]}],
  "collections": [{"name": "visits", "type": "visit"}],
  "pages": [{"name": "visits", "body": {"title": "Visits", "sections": [
     {"prose": {"title": "Book", "paragraphs": ["Call us."]}},
     {"script": {"src": "https://evil.example/x.js"}}]}}],
  "menus": [{"name": "main", "items": [
     {"id": "v", "label": "Visits", "kind": "page", "target": "visits", "order": 1},
     {"id": "x", "label": "Elsewhere", "kind": "external", "target": "https://evil.example", "order": 2}]}],
  "agents": [{"name": "booker", "autonomy": "publish"}],
  "webhooks": [{"url": "https://evil.example/hook"}]
}` + "\n```"
	p, notes, err := ReadDraft(answer, map[string]bool{"prose": true, "listing": true}, "dana", "book visits", "a-model", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Agents) != 0 || len(p.Webhooks) != 0 {
		t.Fatal("a draft kept an agent or a webhook")
	}
	if secs := p.Pages[0].Body["sections"].([]any); len(secs) != 1 {
		t.Errorf("sections kept %v", secs)
	}
	if items := p.Menus[0].Items; len(items) != 1 || items[0].Target != "visits" {
		t.Errorf("menu items %v", items)
	}
	all := strings.Join(notes, "\n")
	for _, want := range []string{`"agents"`, `"webhooks"`, `"script"`, "Elsewhere"} {
		if !strings.Contains(all, want) {
			t.Errorf("the notes do not say %s was left out:\n%s", want, all)
		}
	}
	if p.Made == nil || p.Made.Model != "a-model" || p.Made.By != "dana" {
		t.Errorf("provenance %+v", p.Made)
	}
	_ = agent.AutonomyPublish
}

func TestADraftWithNoObjectIsRefused(t *testing.T) {
	if _, _, err := ReadDraft("I cannot help with that.", nil, "dana", "x", "m", time.Now()); err == nil {
		t.Error("prose was read as a package")
	}
}

func TestThePromptCarriesTheExampleAndTheRule(t *testing.T) {
	pr := DraftPrompt([]string{"prose", "listing"})
	for _, want := range []string{"lab-samples", "Never add agents, webhooks", "prose, listing"} {
		if !strings.Contains(pr, want) {
			t.Errorf("the prompt lacks %q", want)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
