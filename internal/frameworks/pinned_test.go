// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package frameworks_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/frameworks"
	"github.com/quilzo/quilzo/internal/posture"
)

// published is a fixture: a copy of one published list, with where it was
// copied from, and for a list that was renumbered the edition it replaced.
type published struct {
	List    string                   `json:"list"`
	Edition string                   `json:"edition"`
	Source  string                   `json:"source"`
	Entries []frameworks.Requirement `json:"entries"`
	Retired *struct {
		Edition string                   `json:"edition"`
		Entries []frameworks.Requirement `json:"entries"`
	} `json:"retired"`
}

func fixture(t *testing.T, name string) published {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var p published
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(p.Entries) == 0 || !strings.HasPrefix(p.Source, "https://") || p.Edition == "" {
		t.Fatalf("%s does not say what it is a copy of", name)
	}
	return p
}

// cited is every requirement of one framework the posture rules bear on,
// by rule.
func cited(framework string) map[string][]string {
	out := map[string][]string{}
	for _, r := range posture.Rules() {
		for _, ref := range frameworks.Refs(r.ID, r.Controls) {
			if ref.Framework == framework {
				out[r.ID] = append(out[r.ID], ref.ID)
			}
		}
	}
	return out
}

// titled is what each rule's references to one list name, by the titles
// the list gives them, sorted.
func titled(t *testing.T, list published, framework string) map[string][]string {
	t.Helper()
	title := map[string]string{}
	for _, e := range list.Entries {
		title[e.ID] = e.Title
	}
	out := map[string][]string{}
	for rule, ids := range cited(framework) {
		for _, id := range ids {
			tl, ok := title[id]
			if !ok {
				t.Errorf("%s cites %s %s, which is not in the %s %s list", rule, framework, id, list.List, list.Edition)
				continue
			}
			out[rule] = append(out[rule], tl)
		}
		slices.Sort(out[rule])
	}
	return out
}

// The OWASP list for applications built on language models is its 2026
// edition, entry for entry as published, and every check citing it means
// the risk the 2026 entry names.
//
// The 2026 edition renumbered the list. A check that cited LLM06 for an
// agent writing with no role meant Excessive Agency, which was LLM06 in
// 2025 and is Unbounded Consumption now: the citation pointed a reader at
// the wrong risk without a character of it changing. So each check's
// citations are pinned here by the title they mean, which a renumbering
// cannot move, and a new citation is not accepted until it is added here.
func TestOWASPLLM2026Pinned(t *testing.T) {
	list := fixture(t, "owasp-llm-2026.json")
	if got := frameworks.List("owasp-llm"); !reflect.DeepEqual(got, list.Entries) {
		t.Errorf("the catalogue carries\n\t%v\nand the 2026 list published is\n\t%v", got, list.Entries)
	}
	fw, ok := frameworks.Get("owasp-llm")
	if !ok || fw.Version != list.Edition {
		t.Errorf("the catalogue says it maps to edition %q of %s; the fixture is %s", fw.Version, list.List, list.Edition)
	}

	meant := map[string][]string{
		"ai.agent-followed-plant":       {"Prompt Injection"},
		"privacy.model-egress":          {"Sensitive Information Disclosure"},
		"agent.write-without-role":      {"Excessive Agency"},
		"agent.shared-human-credential": {"Excessive Agency"},
		"ai.agent-flagged":              {"Excessive Agency"},
		"integration.unpinned":          {"Supply Chain"},
		"integration.tool-changed":      {"Supply Chain"},
		"agent.memory-held":             {"Data and Model Poisoning"},
		"ai.chatbot-unevaluated":        {"Misinformation"},
		"content.raw-template":          {"Improper Output Handling"},
	}
	if got := titled(t, list, "owasp-llm"); !reflect.DeepEqual(got, meant) {
		for rule, want := range meant {
			if !slices.Equal(got[rule], want) {
				t.Errorf("%s cites %v; it means %v", rule, got[rule], want)
			}
		}
		for rule, g := range got {
			if _, ok := meant[rule]; !ok {
				t.Errorf("%s cites %v, which nobody has checked against the 2026 titles: add it here", rule, g)
			}
		}
	}

	// The OWASP category a rule names on the Security screen, where it is
	// on this list, is its 2026 entry by number and title.
	label := regexp.MustCompile(`^(LLM\d\d):(\d{4}) (.+)$`)
	title := map[string]string{}
	for _, e := range list.Entries {
		title[e.ID] = e.Title
	}
	for _, r := range posture.Rules() {
		if !strings.HasPrefix(r.OWASP, "LLM") {
			continue
		}
		m := label.FindStringSubmatch(r.OWASP)
		if m == nil || m[2] != list.Edition || title[m[1]] != m[3] {
			t.Errorf("%s names %q; the 2026 entry is %s:%s %s", r.ID, r.OWASP, m[1], list.Edition, title[m[1]])
		}
	}
}

// The OWASP list for agentic applications is carried entry for entry as
// published, ASI01 to ASI10, and each check citing it means the risk the
// entry names.
func TestASIIDsPinned(t *testing.T) {
	list := fixture(t, "owasp-asi-2026.json")
	if len(list.Entries) != 10 {
		t.Fatalf("the fixture has %d entries; the list has ten", len(list.Entries))
	}
	for i, e := range list.Entries {
		if want := "ASI" + []string{"01", "02", "03", "04", "05", "06", "07", "08", "09", "10"}[i]; e.ID != want {
			t.Errorf("entry %d is %s; want %s", i+1, e.ID, want)
		}
	}
	if got := frameworks.List("owasp-asi"); !reflect.DeepEqual(got, list.Entries) {
		t.Errorf("the catalogue carries\n\t%v\nand the list published is\n\t%v", got, list.Entries)
	}
	fw, ok := frameworks.Get("owasp-asi")
	if !ok || fw.Version != list.Edition {
		t.Errorf("the catalogue's %s is edition %q; the fixture is %s", list.List, fw.Version, list.Edition)
	}
	meant := map[string][]string{
		"ai.agent-followed-plant":       {"Agent Goal Hijack"},
		"agent.write-without-role":      {"Identity & Privilege Abuse"},
		"agent.shared-human-credential": {"Identity & Privilege Abuse"},
		"integration.unpinned":          {"Agentic Supply Chain Vulnerabilities"},
		"integration.tool-changed":      {"Agentic Supply Chain Vulnerabilities"},
		"agent.memory-held":             {"Memory & Context Poisoning"},
		"ai.agent-flagged":              {"Rogue Agents"},
	}
	got := titled(t, list, "owasp-asi")
	for rule, want := range meant {
		if !slices.Equal(got[rule], want) {
			t.Errorf("%s cites %v; it means %v", rule, got[rule], want)
		}
	}
	for rule, g := range got {
		if _, ok := meant[rule]; !ok {
			t.Errorf("%s cites %v, which nobody has checked against the published titles: add it here", rule, g)
		}
	}
}

// NIS2's Article 21(2) is carried as its ten points, (a) to (j), in the
// Directive's words, and the checks that bear on the obvious ones do.
func TestNIS2Art21IDs(t *testing.T) {
	list := fixture(t, "nis2-art21.json")
	if len(list.Entries) != 10 {
		t.Fatalf("Article 21(2) has ten points and the fixture %d", len(list.Entries))
	}
	for i, e := range list.Entries {
		if want := "Art. 21(2)(" + string(rune('a'+i)) + ")"; e.ID != want {
			t.Errorf("point %d is %q; want %q", i+1, e.ID, want)
		}
	}
	if got := frameworks.List("nis2"); !reflect.DeepEqual(got, list.Entries) {
		t.Errorf("the catalogue carries\n\t%v\nand Article 21(2) reads\n\t%v", got, list.Entries)
	}
	if _, ok := frameworks.Get("nis2"); !ok {
		t.Fatal("NIS2 is not in the catalogue")
	}
	if got := frameworks.Title("nis2", "Art. 21(2)(j)"); !strings.HasPrefix(got, "the use of multi-factor authentication") {
		t.Errorf("point (j) is titled %q", got)
	}

	refs := cited("nis2")
	for rule, want := range map[string]string{
		"mfa.no-second-factor":   "Art. 21(2)(j)", // multi-factor authentication
		"expose.cleartext":       "Art. 21(2)(h)", // cryptography and encryption
		"access.sole-admin":      "Art. 21(2)(c)", // business continuity
		"self.kev-missing":       "Art. 21(2)(e)", // vulnerability handling
		"privacy.model-egress":   "Art. 21(2)(d)", // supply chain: a service provider
		"access.no-policy":       "Art. 21(2)(i)", // access control policies
		"audit.chain-broken":     "Art. 21(2)(b)", // incident handling: the log it rests on
		"ai.chatbot-unevaluated": "Art. 21(2)(f)", // assessing effectiveness
	} {
		if !slices.Contains(refs[rule], want) {
			t.Errorf("%s does not bear on %s (%s): %v", rule, want, frameworks.Title("nis2", want), refs[rule])
		}
	}
}

// No check cites an identifier its list no longer has, or a number from an
// edition that was replaced, and the OWASP category each rule names is an
// entry of the edition it says, by number and title.
func TestNoMappingToRetiredID(t *testing.T) {
	lists := map[string]published{
		"owasp-llm": fixture(t, "owasp-llm-2026.json"),
		"owasp-asi": fixture(t, "owasp-asi-2026.json"),
		"nis2":      fixture(t, "nis2-art21.json"),
	}
	for framework, list := range lists {
		current := map[string]bool{}
		for _, e := range list.Entries {
			current[e.ID] = true
		}
		for rule, ids := range cited(framework) {
			for _, id := range ids {
				if !current[id] {
					t.Errorf("%s cites %s %s, which %s %s does not have", rule, framework, id, list.List, list.Edition)
				}
			}
		}
	}

	// The retired edition's numbers are not the ones a label carries.
	llm := lists["owasp-llm"]
	if llm.Retired == nil || llm.Retired.Edition == llm.Edition {
		t.Fatal("the fixture does not keep the edition the 2026 list replaced")
	}
	web := fixture(t, "owasp-top10-2025.json")
	editions := map[string]published{"LLM": llm, "A": web}
	label := regexp.MustCompile(`^(LLM|A)(\d\d):(\d{4}) (.+)$`)
	check := func(who, category string) {
		m := label.FindStringSubmatch(category)
		if m == nil {
			t.Errorf("%s names %q, which is not shaped like an OWASP category", who, category)
			return
		}
		list := editions[m[1]]
		if m[3] != list.Edition {
			t.Errorf("%s names %q, from edition %s; the current one is %s", who, category, m[3], list.Edition)
		}
		var title string
		for _, e := range list.Entries {
			if e.ID == m[1]+m[2] {
				title = e.Title
			}
		}
		if title != m[4] {
			t.Errorf("%s names %q; %s%s:%s is %q in %s", who, category, m[1], m[2], list.Edition, title, list.List)
		}
	}
	for _, r := range posture.Rules() {
		if r.OWASP != "" {
			check(r.ID, r.OWASP)
		}
	}

	// And every other rule that names one: the code scan's and the
	// settings', read from the source, since each keeps its own list.
	field := regexp.MustCompile(`OWASP:\s*"([^"]+)"`)
	found := 0
	for _, dir := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range field.FindAllStringSubmatch(string(b), -1) {
				found++
				check(filepath.ToSlash(path), m[1])
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if found < 50 {
		t.Errorf("only %d OWASP categories were found in the source; this is reading the wrong tree", found)
	}
	if fw, _ := frameworks.Get("owasp-llm"); fw.Version == llm.Retired.Edition {
		t.Errorf("the catalogue still maps to the %s edition", fw.Version)
	}
}
