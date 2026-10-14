// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/research"
)

// The project's page shows each number as a link to the computation it
// came from, marks a number nobody can trace where it sits, and lists the
// works cited.
func TestAProjectPageShowsWhereEveryNumberCameFrom(t *testing.T) {
	srv, token := emptyStore(t)
	at := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	run := research.Run{ID: "r-20261014-0000abcd", Project: "fever", Started: at, Took: "1.2s",
		Code:        research.File{Path: "analysis.py", Digest: strings.Repeat("a", 64)},
		Inputs:      []research.File{{Path: "data/trial.csv", Digest: strings.Repeat("b", 64)}},
		Environment: research.Environment{Interpreter: "python3", Version: "Python 3.12.3", Box: "native"},
		Values:      []research.Value{{Name: "fever_drop", Value: 0.9, Unit: "degrees"}}}
	proj := research.Project{Name: "fever", Question: "Does aspirin lower fever?",
		Plan: research.Plan{Text: "Compare means.", Digest: research.Digest("Compare means."), Registered: at, By: "dana", BeforeData: true,
			Signature: &research.Signature{KeyID: "k1", Ed25519: "sig", Algorithms: []string{"ed25519"}}},
		Claims: []research.Claim{{Name: "fever_drop", Run: run.ID, Value: 0.9, Unit: "degrees"}},
		Sources: []research.Source{{Key: "smith2021", ID: "doi:10.1000/a", Title: "Aspirin and fever", Year: 2021,
			Authors: []string{"Ann Smith"}, Abstract: "Aspirin lowered fever.", Resolver: "OpenAlex", Resolved: at,
			URL: "https://doi.org/10.1000/a"}},
		Report: "# Results\n\nFever fell by {{fever_drop}}. Aspirin lowered fever [@smith2021]. Then 2 people felt better."}
	no := false
	rerun := research.Run{ID: "r-20261014-1111abcd", Project: "fever", Started: at.Add(time.Hour), Took: "1s", Code: run.Code,
		Rerun: run.ID, Reproduced: &no, Differs: []string{"fever_drop 0.9 degrees, then 1 degrees"}}
	srv.Research = &Research{
		List: func() ([]research.Project, error) { return []research.Project{proj}, nil },
		Load: func(name string) (research.Project, []research.Run, []research.Finding, error) {
			if name != "fever" {
				return research.Project{}, nil, nil, errors.New("none")
			}
			return proj, []research.Run{rerun, run}, research.Check(proj, []research.Run{run}), nil
		},
	}
	for path, wants := range map[string][]string{
		"/research": {`href="/research/fever"`, "registered before the data"},
		"/research/fever": {`<a class="value" href="#r-20261014-0000abcd"`, ">0.9 degrees</a>",
			`<span class="tag tag-bad" title="a number nobody can trace">2</span>`, "Ann Smith (2021). Aspirin and fever.",
			"1 problem", `id="r-20261014-0000abcd"`, `<span class="tag tag-bad">did not reproduce</span>`},
	} {
		w := get(t, srv, path, token)
		body := w.Body.String()
		if w.Code != 200 || strings.Contains(body, "<!-- render error:") {
			t.Fatalf("%s: %d\n%s", path, w.Code, body)
		}
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Errorf("%s has no %q", path, want)
			}
		}
		for _, f := range a11y.Check(path, body).Findings {
			if f.Severity == a11y.Blocking {
				t.Errorf("%s: %s — %s", path, f.Rule, f.Detail)
			}
		}
	}
	if w := get(t, srv, "/research/nothing", token); w.Code != 404 {
		t.Errorf("a project that is not here: %d", w.Code)
	}
}
