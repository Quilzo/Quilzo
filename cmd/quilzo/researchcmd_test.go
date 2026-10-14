// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/agentbox"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
	"github.com/quilzo/quilzo/internal/research"
	"github.com/quilzo/quilzo/internal/shell"
	"github.com/quilzo/quilzo/internal/store"
)

const analysis = `import csv, json
rows = list(csv.DictReader(open("data/trial.csv")))
treated = [float(r["fever"]) for r in rows if r["arm"] == "aspirin"]
control = [float(r["fever"]) for r in rows if r["arm"] == "placebo"]
diff = sum(control) / len(control) - sum(treated) / len(treated)
json.dump({"fever_drop": round(diff, 3), "patients": {"value": len(rows), "unit": "patients"}}, open("values.json", "w"))
open("summary.txt", "w").write("done\n")
`

// researchStoreWithBox is a store with dana administering, a project with
// its code and data, and a box to compute in.
func researchStoreWithBox(t *testing.T) (string, *Caller) {
	t.Helper()
	root, _ := identityStore(t)
	n := agentbox.Native{Exe: os.Args[0], Init: []string{"agentbox-init"}, Shim: []string{"agentbox-shim"}}
	if a := n.Check(); !a.OK {
		t.Skip("no box here: " + a.Why)
	}
	if _, err := shell.Find("python3"); err != nil {
		t.Skip("no Python here")
	}
	testBackend = n
	t.Cleanup(func() { testBackend = nil })
	dana := asAdmin("dana")
	if err := researchNew(root, "fever", "Does aspirin lower fever in adults?", dana); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := researchAdd(root, "fever", []string{write("analysis.py", analysis)}, "", dana); err != nil {
		t.Fatal(err)
	}
	data := "arm,fever\naspirin,37.2\naspirin,37.4\nplacebo,38.1\nplacebo,38.3\n"
	if _, err := researchAdd(root, "fever", []string{write("trial.csv", data)}, "data", dana); err != nil {
		t.Fatal(err)
	}
	return root, dana
}

// The whole of it: a plan registered before the data, a computation whose
// numbers become claims, a report that states only those, and a re-run
// that reproduces them.
func TestAReportStatesOnlyNumbersItsCodeProduced(t *testing.T) {
	root, dana := researchStoreWithBox(t)
	if _, err := researchSetPlan(root, "fever", "Compare mean temperature between arms.", "", dana); err != nil {
		t.Fatal(err)
	}
	p, err := researchRegister(root, "fever", dana)
	if err != nil || !p.Plan.BeforeData || p.Plan.Signature == nil {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	// Anybody holding the published keys can check the registration.
	signer, _ := headSigner(root)
	s := p.Plan.Signature
	if err := signer.Verifier().VerifyStatement(research.PlanContext, []byte(p.Plan.Digest),
		audit.Statement{KeyID: s.KeyID, Ed25519: s.Ed25519, MLDSA: s.MLDSA, Algorithms: s.Algorithms}); err != nil {
		t.Fatalf("the registration does not verify: %v", err)
	}

	r, err := researchRunScript(context.Background(), root, "fever", "analysis.py", []string{"data/trial.csv"}, "", dana)
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK() || len(r.Values) != 2 || r.Values[0].Name != "fever_drop" || r.Values[0].Value != 0.9 ||
		r.Values[1].Unit != "patients" || len(r.Inputs) != 1 || r.Environment.Version == "" {
		t.Fatalf("%+v", r)
	}
	if len(r.Outputs) != 2 || r.Outputs[0].Path != "summary.txt" {
		t.Errorf("outputs %+v", r.Outputs)
	}
	if _, err := os.Stat(filepath.Join(researchStore(root).RunDir("fever", r.ID), "out", "data", "trial.csv")); err == nil {
		t.Error("an input was kept as if it were an output")
	}
	if _, err := researchClaim(root, "fever", r.ID, nil, dana); err != nil {
		t.Fatal(err)
	}

	fs, err := researchWrite(root, "fever", "# Results\n\nAmong {{patients}}, fever fell by {{fever_drop}} degrees, "+
		"and 2 people felt better.", dana)
	if err != nil {
		t.Fatal(err)
	}
	if research.Problems(fs) != 1 || !strings.Contains(fs[len(fs)-1].What, "2 is a number nobody can trace") {
		t.Fatalf("%+v", fs)
	}
	md, _ := researchReport(root, "fever", dana)
	if !strings.Contains(md, "Among 4 patients, fever fell by 0.9 degrees") || !strings.Contains(md, "2 (untraced)") ||
		!strings.Contains(md, "| fever_drop | 0.9 | "+r.ID+" | analysis.py") {
		t.Errorf("%s", md)
	}

	// From the store's own folder, as the command line runs it, the root
	// is relative, and the box is still given where to work.
	t.Chdir(filepath.Dir(root))
	again, err := researchRerun(context.Background(), filepath.Base(root), "fever", r.ID, dana)
	if err != nil || again.Reproduced == nil || !*again.Reproduced {
		t.Fatalf("%+v %v", again, err)
	}
	t.Chdir(t.TempDir())

	// After the data is seen, the plan changes only by amendment, made by a
	// person, and the amendment says the data had been seen.
	a, err := researchSetPlan(root, "fever", "Compare medians.", "outliers", dana)
	if err != nil || !a.AfterData {
		t.Fatalf("%+v %v", a, err)
	}
	model := asAdmin("helper")
	model.Kind = audit.KindAI
	if _, err := researchSetPlan(root, "fever", "Compare modes.", "because", model); err == nil {
		t.Error("a model amended a registered plan")
	}
}

// A computation that gives different numbers each time does not reproduce,
// and the claim resting on it is a problem in the report.
func TestARerunThatDiffersIsAProblem(t *testing.T) {
	root, dana := researchStoreWithBox(t)
	dir := t.TempDir()
	noisy := filepath.Join(dir, "noisy.py")
	os.WriteFile(noisy, []byte("import json, os\njson.dump({\"draw\": int.from_bytes(os.urandom(4), 'big')}, open('values.json', 'w'))\n"), 0o600)
	if _, err := researchAdd(root, "fever", []string{noisy}, "", dana); err != nil {
		t.Fatal(err)
	}
	r, err := researchRunScript(context.Background(), root, "fever", "noisy.py", nil, "", dana)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := researchClaim(root, "fever", r.ID, []string{"draw"}, dana); err != nil {
		t.Fatal(err)
	}
	again, err := researchRerun(context.Background(), root, "fever", r.ID, dana)
	if err != nil || again.Reproduced == nil || *again.Reproduced || len(again.Differs) != 1 {
		t.Fatalf("%+v %v", again, err)
	}
	fs, _ := researchWrite(root, "fever", "We drew {{draw}}.", dana)
	if research.Problems(fs) != 1 || !strings.Contains(fs[len(fs)-1].What, "did not reproduce") {
		t.Errorf("%+v", fs)
	}
	// Changing the data under a computation stops its re-run.
	os.WriteFile(filepath.Join(researchStore(root).Work("fever"), "data", "trial.csv"), []byte("arm,fever\n"), 0o600)
	first, err := researchRunScript(context.Background(), root, "fever", "analysis.py", []string{"data/trial.csv"}, "", dana)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(researchStore(root).Work("fever"), "data", "trial.csv"), []byte("arm,fever\naspirin,37\n"), 0o600)
	if _, err := researchRerun(context.Background(), root, "fever", first.ID, dana); err == nil ||
		!strings.Contains(err.Error(), "changed since") {
		t.Errorf("a re-run on changed data: %v", err)
	}
}

// standInIndex answers as OpenAlex does for one DOI, and has nothing else.
func standInIndex(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Get("filter") == "doi:10.1000/aspirin":
			w.Write([]byte(`{"results":[{"id":"https://openalex.org/W9","doi":"https://doi.org/10.1000/aspirin",
				"display_name":"Aspirin and fever in adults","publication_year":2021,
				"authorships":[{"author":{"display_name":"Ann Smith"}}],
				"abstract_inverted_index":{"Aspirin":[0],"lowered":[1],"fever":[2],"in":[3],"adults":[4]}}]}`))
		case r.URL.Query().Get("search") != "":
			w.Write([]byte(`{"results":[{"id":"https://openalex.org/W9","doi":"https://doi.org/10.1000/aspirin","display_name":"Aspirin and fever in adults","publication_year":2021}]}`))
		case r.URL.Path == "/works":
			w.Write([]byte(`{"results":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	researchIndex = func(string) research.Index {
		return research.Index{OpenAlex: srv.URL, Crossref: srv.URL + "/cr", Get: func(ctx context.Context, u string) ([]byte, int, error) {
			res, err := http.Get(u)
			if err != nil {
				return nil, 0, err
			}
			defer res.Body.Close()
			var b strings.Builder
			buf := make([]byte, 4096)
			for {
				n, err := res.Body.Read(buf)
				b.Write(buf[:n])
				if err != nil {
					break
				}
			}
			return []byte(b.String()), res.StatusCode, nil
		}}
	}
	orig := researchIndex
	t.Cleanup(func() { researchIndex = orig })
}

// A citation is a work an index returned; an agent can find and cite one,
// and cannot invent one.
func TestAnAgentCitesOnlyWorksThatExist(t *testing.T) {
	root, _ := identityStore(t)
	standInIndex(t)
	dana := asAdmin("dana")
	if err := researchNew(root, "fever", "Does aspirin lower fever?", dana); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	agentCaller := remoteCaller(auth.Token{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"})
	srv := buildMCP(root, s, agentCaller, "templates")
	call := func(op string, args map[string]any) string {
		tool := "quilzo_write"
		if op == "research_search" || op == "research_project" {
			tool = "quilzo_read"
		}
		params, _ := json.Marshal(map[string]any{"name": tool, "arguments": map[string]any{"operation": op, "arguments": args}})
		resp := srv.Handle(mcp.Request{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: params})
		b, _ := json.Marshal(resp)
		var r struct {
			Result struct {
				Content []struct{ Text string } `json:"content"`
			} `json:"result"`
			Error *struct{ Message string } `json:"error"`
		}
		_ = json.Unmarshal(b, &r)
		switch {
		case r.Error != nil:
			return "ERROR " + r.Error.Message
		case len(r.Result.Content) > 0:
			return r.Result.Content[0].Text
		}
		return string(b)
	}
	text := func(s string) string { return s }
	if got := text(call("research_search", map[string]any{"query": "aspirin fever"})); !strings.Contains(got, "doi:10.1000/aspirin") {
		t.Fatalf("search: %s", got)
	}
	if got := text(call("research_cite", map[string]any{"name": "fever", "id": "doi:10.1000/aspirin"})); !strings.Contains(got, `"key":"smith2021"`) {
		t.Fatalf("cite: %s", got)
	}
	if got := text(call("research_cite", map[string]any{"name": "fever", "id": "doi:10.1000/invented"})); !strings.Contains(got, "did not resolve") {
		t.Errorf("an invented work: %s", got)
	}
	cited := 0
	events, _ := audit.Read(auditPath(root))
	for _, e := range events {
		if e.Action == "research.cited" && e.Detail["cited_as"] == "smith2021" {
			cited++
		}
	}
	if cited != 1 {
		t.Errorf("%d records of the citation", cited)
	}
	got := text(call("research_write", map[string]any{"name": "fever",
		"report": "Aspirin lowered fever in adults [@smith2021]. It cured 90 percent of colds [@smith2021]."}))
	if !strings.Contains(got, "90 is a number nobody can trace") || !strings.Contains(got, "It cured") ||
		strings.Contains(got, "Aspirin lowered fever in adults.\"") {
		t.Errorf("write: %s", got)
	}
	_, err = researchRegister(root, "fever", agentCaller)
	if err == nil || !strings.Contains(err.Error(), "not a model") {
		t.Errorf("a model registered a plan: %v", err)
	}
	reader := human("rae")
	reader.Role = "reader"
	if _, err := researchCite(context.Background(), root, "fever", "doi:10.1000/aspirin", "", reader); err == nil {
		t.Error("a reader cited a work")
	}
}
