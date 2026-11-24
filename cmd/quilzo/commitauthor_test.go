// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// authorshipRig is a store two administrators share, dana and lee, with one
// approval asked of every change, and dana signed in with her own token.
func authorshipRig(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if w == nil {
		w = out.New(false)
	}
	old := flagToken
	flagToken = ""
	t.Cleanup(func() { flagToken = old })
	root := t.TempDir() + "/st"
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	for _, who := range []string{"dana", "lee"} {
		if err := pol.Grant(auth.Binding{Principal: who, Role: auth.RoleAdmin, Resource: "/"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(approvalPolicyPath(root), collab.Policy{Required: 1, RequireHumanForAI: true}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("QUILZO_TOKEN", personToken(t, root, "dana", auth.RoleAdmin))
	return root
}

// fileOf writes body to a file of its own and gives its path.
func fileOf(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// draftCommit is the commit the draft points at.
func draftCommit(t *testing.T, root string) store.Commit {
	t.Helper()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.GetCommit(s.GetRef(site.RefDraft))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// approvalAs is somebody approving the draft on the command line with their
// own token: what refused them, if anything, and whether publishing would
// then be let through.
func approvalAs(t *testing.T, root, who string) (refusal string, d collab.Decision) {
	t.Helper()
	t.Setenv("QUILZO_TOKEN", personToken(t, root, who, auth.RoleAdmin))
	if err := cmdReview(root, []string{"approve", "--note", "read it"}); err != nil {
		refusal = err.Error()
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	prop, _, err := currentProposal(root, s)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := loadApprovalPolicy(root)
	if err != nil {
		t.Fatal(err)
	}
	return refusal, pol.Evaluate(*prop, kindOfPrincipal(root), time.Now())
}

// A change is recorded as written by whoever made it, on every command that
// writes one and takes a name, and a name other than theirs is a credit.
//
// `quilzo add --author lee`, run by dana, recorded the commit as lee's, and
// every authorship rule reads the commit: with one approval asked, dana
// approved her own change because the proposal believed lee wrote it, and
// it went live with nobody else having read it. The audit record named dana
// all along. `quilzo import --author` did the same for pages and records,
// with "import" by default, which nobody is, and `quilzo assist --author`
// recorded what dana's writing assistant wrote as written for lee, so dana
// was not who asked for it.
func TestACommitIsRecordedUnderWhoeverMadeIt(t *testing.T) {
	page := `{"title":"Prices","body":"cheap"}`
	for _, surface := range []struct {
		name  string
		write func(t *testing.T, root string) error
		// machine is a writer that commits for the person it acts for
		// (collab.WrittenFor), so the person is who it is written for.
		machine bool
	}{
		{name: "quilzo add", write: func(t *testing.T, root string) error {
			return cmdAdd(root, []string{"pricing=" + fileOf(t, "p.json", page), "--author", "lee", "-m", "edit pricing"})
		}},
		{name: "quilzo add --merge", write: func(t *testing.T, root string) error {
			if err := cmdAdd(root, []string{"about=" + fileOf(t, "a.json", page), "-m", "about"}); err != nil {
				return err
			}
			base := draftCommitID(t, root)
			return cmdAdd(root, []string{"pricing=" + fileOf(t, "p.json", page), "--author", "lee",
				"--based-on", base, "--merge", "-m", "edit pricing"})
		}},
		{name: "quilzo import", write: func(t *testing.T, root string) error {
			return cmdImport(root, []string{fileOf(t, "export.md", "---\ntitle: Prices\nslug: pricing\n---\ncheap\n"),
				"--author", "lee", "--redirects-out", filepath.Join(t.TempDir(), "r.json")})
		}},
		{name: "quilzo import records", write: func(t *testing.T, root string) error {
			return cmdImport(root, []string{fileOf(t, "prices.json",
				`{"collection":"prices","records":[{"id":"0123456789abcdef0123456789abcdef","fields":{"name":"tea"}}]}`), "--author", "lee"})
		}},
		{name: "quilzo assist", machine: true, write: func(t *testing.T, root string) error {
			standInWritingAssistant(t, `{"pages":{"pricing":`+page+`}}`)
			return cmdAssist(root, []string{"write the prices", "--author", "lee",
				"--templates", filepath.Join(t.TempDir(), "tpl")})
		}},
	} {
		t.Run(surface.name, func(t *testing.T) {
			root := authorshipRig(t)
			if err := surface.write(t, root); err != nil {
				t.Fatal(err)
			}
			c := draftCommit(t, root)
			if writer, person := collab.WrittenFor(c.Message, c.Author); surface.machine {
				if person != "dana" {
					t.Errorf("%q by %s is written for %q, not dana, who ran it", c.Message, c.Author, person)
				}
			} else if writer != "dana" {
				t.Errorf("%q is recorded as written by %s, not dana, who wrote it", c.Message, c.Author)
			}
			if !strings.Contains(c.Message, "lee") {
				t.Errorf("the credit to lee is not kept: %q", c.Message)
			}
			// And for every rule that reads who answers for a page.
			if idx, err := loadProvenance(root); err == nil {
				for name, rec := range idx.Records {
					if rec.Author == "lee" {
						t.Errorf("%s's provenance names lee as answering for it: %+v", name, rec)
					}
				}
			}

			refusal, d := approvalAs(t, root, "dana")
			if refusal == "" && d.Allowed {
				t.Fatalf("dana approved her own change, recorded as lee's, and it would publish: %s", d.Reason)
			}
			if refusal, d = approvalAs(t, root, "lee"); refusal != "" || !d.Allowed {
				t.Errorf("lee's approval of dana's change did not let it through: %q %s", refusal, d.Reason)
			}
		})
	}
}

// draftCommitID is the id the draft points at.
func draftCommitID(t *testing.T, root string) string {
	t.Helper()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return s.GetRef(site.RefDraft)
}

// standInWritingAssistant answers every completion with reply, as the model
// `quilzo assist` asks.
func standInWritingAssistant(t *testing.T, reply string) {
	t.Helper()
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": reply}}}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(model.Close)
	t.Setenv("QUILZO_MODEL_URL", model.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")
}

// Naming yourself is what it always was: the commit is yours, with nothing
// added to its message.
func TestNamingYourselfAsTheAuthorIsUnchanged(t *testing.T) {
	root := authorshipRig(t)
	if err := cmdAdd(root, []string{"pricing=" + fileOf(t, "p.json", `{"title":"T"}`), "--author", "dana",
		"-m", "edit pricing"}); err != nil {
		t.Fatal(err)
	}
	if c := draftCommit(t, root); c.Author != "dana" || c.Message != "edit pricing" {
		t.Errorf("naming yourself recorded %q by %s", c.Message, c.Author)
	}
}

// A person's own write cannot say a machine wrote it.
//
// The approval gate reads who wrote a commit from its message
// (collab.MachineWrote, collab.WrittenFor), and `quilzo add -m` took any
// message: "agent: tidy wrote pricing for lee" with --author agent/tidy was
// read as the agent's change made for lee, so dana, who wrote it, approved
// it as somebody else's work. Only the writers that are machines write
// those prefixes, and they write them themselves.
func TestAPersonsWriteCannotSayAMachineWroteIt(t *testing.T) {
	for _, forged := range [][]string{
		{"-m", "agent: tidy wrote pricing for lee", "--author", "agent/tidy"},
		{"-m", "mcp: write pricing"},
		{"-m", "assist: write the prices"},
	} {
		t.Run(forged[1], func(t *testing.T) {
			root := authorshipRig(t)
			before := draftCommitID(t, root)
			err := cmdAdd(root, append([]string{"pricing=" + fileOf(t, "p.json", `{"title":"T"}`)}, forged...))
			if err == nil {
				c := draftCommit(t, root)
				writer, person := collab.WrittenFor(c.Message, c.Author)
				t.Fatalf("a person's write was taken as a machine's: %q by %s, read as %s's for %q",
					c.Message, c.Author, writer, person)
			}
			if after := draftCommitID(t, root); after != before {
				t.Errorf("the refused write moved the draft from %q to %q", before, after)
			}
		})
	}
}

// What a person records about where a page came from names them as
// answering for it, and a name other than theirs is a credit.
//
// `quilzo provenance set --author lee`, run by dana, recorded lee as the
// person who answers for a model's page, and the rule that a person whose
// run wrote a draft approves it only when nobody else may publish reads
// those names (draftStarters) and does not ask any of them to be the
// second person. Naming lee on the page dana's run wrote took lee out of
// the people who could read it, and dana approved her own run's change
// alone with lee there. The provenance screen already records whoever is
// signed in.
func TestProvenanceIsRecordedUnderWhoeverRecordsIt(t *testing.T) {
	root := authorshipRig(t)
	if err := saveJSON(approvalPolicyPath(root), collab.Policy{RequireHumanForAI: true}); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	// dana's run wrote the prices, and its commit says so.
	if _, err := site.SaveDraft(s, map[string]any{"pricing": map[string]any{"title": "Prices"}},
		collab.AgentMessage("tidy", "pricing", "dana"), "agent/tidy"); err != nil {
		t.Fatal(err)
	}
	if err := cmdProvenance(root, []string{"set", "pricing", "--source", string(provenance.TrainedAlgorithmicMedia),
		"--author", "lee"}); err != nil {
		t.Fatal(err)
	}
	idx, err := loadProvenance(root)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := idx.Get("pricing")
	if rec.Author != "dana" {
		t.Errorf("the provenance dana recorded names %q as answering for the page", rec.Author)
	}
	if !strings.Contains(rec.Note, "lee") {
		t.Errorf("the credit to lee is not kept: %+v", rec)
	}
	refusal, d := approvalAs(t, root, "dana")
	if refusal == "" && d.Allowed {
		t.Fatalf("dana approved her own run's change alone, with lee there to read it: %s", d.Reason)
	}
	if !strings.Contains(refusal, "lee") {
		t.Errorf("dana was not told lee is the one to read it: %q", refusal)
	}
}
