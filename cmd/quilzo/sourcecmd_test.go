// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Sources on the command line: a pipeline's and a connector's source are
// added, listed with how fresh each is, shown and named stale; a
// connector's run with nothing in the vault writes nothing and says so; and
// the upkeep job tells the owner of a stale source with no mail relay that
// it could not, without failing the loop silently.
func TestSourcesOnTheCommandLine(t *testing.T) {
	root, token := accessStore(t)
	if _, e, code := cliRun(t, root, token, "source", "add-pipeline", "docs-ci", "--repository", "octo/docs",
		"--workflow", ".github/workflows/evidence.yml", "--every", "1h", "--owner", "priya@example.org"); code != 0 {
		t.Fatalf("add-pipeline exited %d: %s", code, e)
	}
	if _, e, code := cliRun(t, root, token, "source", "add", "entra-prod", "--recipe", "entra",
		"--param", "tenant=72f988bf-86f1-41af-91ab-2d7cd011db47"); code != 0 {
		t.Fatalf("add exited %d: %s", code, e)
	}
	o, e, code := cliRun(t, root, token, "--json", "source", "list")
	var list struct {
		Sources []struct {
			Source struct {
				Name  string   `json:"name"`
				Hosts []string `json:"hosts"`
			} `json:"source"`
			Stale bool   `json:"stale"`
			Said  string `json:"said"`
		} `json:"sources"`
	}
	if code != 0 || json.Unmarshal([]byte(o), &list) != nil || len(list.Sources) != 2 {
		t.Fatalf("source list exited %d: %s %s", code, e, o)
	}
	for _, st := range list.Sources {
		if st.Source.Name == "entra-prod" && strings.Join(st.Source.Hosts, " ") != "graph.microsoft.com login.microsoftonline.com" {
			t.Errorf("the connector reaches %v", st.Source.Hosts)
		}
	}
	if o, _, code := cliRun(t, root, token, "source", "show", "entra-prod"); code != 0 || !strings.Contains(o, "User.Read.All") ||
		!strings.Contains(o, "verified against recorded responses") {
		t.Errorf("source show: %d %s", code, o)
	}
	if _, _, code := cliRun(t, root, token, "source", "show", "nobody"); code != 4 {
		t.Errorf("an unknown source exited %d", code)
	}
	if _, _, code := cliRun(t, root, token, "source", "add", "bad", "--recipe", "nothing"); code != 2 {
		t.Errorf("an unknown recipe exited %d", code)
	}
	o, e, code = cliRun(t, root, token, "--json", "source", "run", "entra-prod")
	if code == 0 || !strings.Contains(o+e, "vault") {
		t.Errorf("a run with no credential exited %d: %s %s", code, o, e)
	}

	// An hour and more later the pipeline, which never pushed, is stale.
	later := time.Now().Add(2 * time.Hour)
	src, err := timedSources(root, later)
	if err != nil || src == nil {
		t.Fatal(err)
	}
	stale, err := src.Stale(later)
	if err != nil || len(stale) == 0 || stale[0].Source.Name != "docs-ci" {
		t.Fatalf("stale at %s: %+v %v", later, stale, err)
	}
	var tick func(time.Time) (int, error)
	for _, j := range sourceJobs(root) {
		if j.Name == "stale sources" {
			tick = j.Do
		}
	}
	if n, err := tick(later); n != 0 || err == nil || !strings.Contains(err.Error(), "mail relay") {
		t.Errorf("with no relay, the tick told %d and said %v", n, err)
	}
	if n, err := tick(later.Add(15 * time.Minute)); n != 0 || err != nil {
		t.Errorf("the next tick tried again: %d %v", n, err)
	}
}
