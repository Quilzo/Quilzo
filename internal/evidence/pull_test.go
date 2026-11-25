// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"errors"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/register"
)

// A source takes facts only from the kind of actor that made it: a
// person's table read through a tool's map is graded as a service's export
// is, and is still refused under a source a service made.
func TestASourceTakesFactsOnlyFromTheKindThatMadeIt(t *testing.T) {
	w := newWorld(t, false)
	m := laptopMap()
	m.Tool = "An asset tool"
	w.confirm(t, m)
	// A service's export makes the source, graded imported.
	if _, err := w.g.Ingest(service, "", Input{Format: FormatCSV, Body: []byte(laptops), Source: "assets", Map: m}); err != nil {
		t.Fatal(err)
	}
	before := w.reg.Head()
	edited := strings.Replace(laptops, "C02X2,mac-02,false", "C02X2,mac-02,true", 1)
	_, err := w.g.Ingest(person, "", Input{Format: FormatCSV, Body: []byte(edited), Source: "assets", Map: m})
	if !errors.Is(err, ErrNotTheirs) {
		t.Fatalf("a person's table under a service's source: %v", err)
	}
	if w.reg.Head() != before {
		t.Error("the refused table wrote something")
	}
	// The person's own source takes it.
	if _, err := w.g.Ingest(person, "", Input{Format: FormatCSV, Body: []byte(edited), Source: "my-laptops", Map: m}); err != nil {
		t.Errorf("a person's table under their own source: %v", err)
	}
}

// A connector's run is not a format anybody names, and is written only by
// the service that ran it, under a connector's source.
func TestARunComesOnlyThroughCollect(t *testing.T) {
	w := newWorld(t, false)
	if _, ok := FormatNamed("pull"); ok {
		t.Error("a run's format can be named")
	}
	if _, err := w.g.Ingest(service, "", Input{Format: FormatPull, Body: []byte(`{}`)}); !errors.Is(err, ErrUnreadable) {
		t.Errorf("a run brought as a file: %v", err)
	}
	src := register.Source{Name: "idp", Type: "connector", Fresh: 3600, Hosts: []string{"idp.example.com"},
		Grade: register.GradeConnector, By: "service", Recipe: "nothing"}
	if _, err := w.g.Collect(person, "", src, []byte(`{}`)); !errors.Is(err, ErrNotTheirs) {
		t.Errorf("a person wrote a run: %v", err)
	}
	if _, err := w.g.Collect(service, "", src, []byte(`{}`)); !errors.Is(err, ErrUnreadable) {
		t.Errorf("a run of a recipe nobody registered: %v", err)
	}
	upload := src
	upload.Type, upload.Grade = "upload", register.GradeUploaded
	if _, err := w.g.Collect(service, "", upload, []byte(`{}`)); !errors.Is(err, ErrNotTheirs) {
		t.Errorf("a run under a source that is not a connector's: %v", err)
	}
}

// A push is filed only under a pipeline's source that names the job's
// repository and workflow, and names no other repository; it is graded
// "ci", and the source must have been made by a person first.
func TestAPushIsHeldToItsJob(t *testing.T) {
	w := newWorld(t, false)
	src := register.Source{Name: "docs-ci", Type: "ci", Fresh: 86400, Grade: register.GradeCI, By: "service",
		Repository: "octo/docs", Workflow: ".github/workflows/evidence.yml"}
	job := Workload{Platform: "github", Repository: "octo/docs", Workflow: ".github/workflows/evidence.yml"}
	in := Input{Format: FormatSARIF, Body: []byte(sarifFor("https://github.com/octo/docs"))}
	if _, err := w.g.Push(service, "", in, src, job); !errors.Is(err, register.ErrNotFound) {
		t.Errorf("a push to a source nobody made: %v", err)
	}
	if _, err := w.reg.Put(person, "a pipeline's source", src); err != nil {
		t.Fatal(err)
	}
	res, err := w.g.Push(service, "", in, src, job)
	if err != nil {
		t.Fatal(err)
	}
	if res.Batch.Grade != register.GradeCI || res.Batch.Raw.Grade != register.GradeCI {
		t.Errorf("a push is graded %s", res.Batch.Grade)
	}
	for _, o := range observations(t, w.reg) {
		if o.Grade != register.GradeCI {
			t.Errorf("a pushed fact is graded %s", o.Grade)
		}
	}
	for name, j := range map[string]Workload{
		"another repository": {Repository: "octo/payroll", Workflow: job.Workflow},
		"another workflow":   {Repository: job.Repository, Workflow: ".github/workflows/other.yml"},
		"no repository":      {Workflow: job.Workflow},
	} {
		if _, err := w.g.Push(service, "", in, src, j); !errors.Is(err, ErrNotTheirs) {
			t.Errorf("%s: %v", name, err)
		}
	}
	other := Input{Format: FormatSARIF, Body: []byte(sarifFor("https://github.com/octo/payroll"))}
	if _, err := w.g.Push(service, "", other, src, job); !errors.Is(err, ErrNotTheirs) {
		t.Errorf("a file naming another repository: %v", err)
	}
	if _, err := w.g.Push(person, "", in, src, job); !errors.Is(err, ErrNotTheirs) {
		t.Errorf("a person pushed as a job: %v", err)
	}
	// Read again, a push checks as the job its source names.
	checks, err := w.g.Verify()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		if !c.OK() {
			t.Errorf("a pushed file does not check: %+v", c)
		}
	}
}

func sarifFor(repo string) string {
	return `{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"scanner","rules":[{"id":"R1"}]}},` +
		`"versionControlProvenance":[{"repositoryUri":"` + repo + `"}],"results":[{"ruleId":"R1","level":"error","message":{"text":"x"}}]}]}`
}
