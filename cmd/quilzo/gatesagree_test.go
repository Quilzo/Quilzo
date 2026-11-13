// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/site"
)

// Every way to publish runs the same checks about the content.
//
// There are four — the command line, the browser, the agent interface, and a
// message in a chat room — and they ran four different sets. The demo ships a
// shop whose own instructions say "take guarantee_terms off the brass pen and
// publishing stops". It stopped on the command line and the browser published
// the same draft, claim and all.
//
// A source walk for the call, and a behavioural test below for the answer.
// The call is what a refactor removes; the answer is what a wrong gate gives.
func TestEveryPublishSurfaceRunsTheContentGates(t *testing.T) {
	// Where the set is built, and what each one is.
	surfaces := map[string]string{
		"main.go":  "quilzo publish",
		"serve.go": "the browser, through srv.ContentGates",
		"mcp.go":   "the agent interface",
	}
	var missing []string
	for file, what := range surfaces {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "contentGates(") {
			missing = append(missing, file+" — "+what)
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("%s no longer runs the shared content gates. A publish path "+
			"with its own idea of which checks apply is how this interface "+
			"came to publish a draft `quilzo publish` refuses", m)
	}
}

// And the browser's hook is wired, not merely declared.
//
// admin.Server.ContentGates is nil in a build that forgets it, and
// handlePublish refuses on nil rather than publishing — but a refusal in
// production is a worse way to find this out than a failing test.
func TestTheBrowserIsHandedTheGates(t *testing.T) {
	body, err := os.ReadFile("serve.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "srv.ContentGates = ") {
		t.Error("cmd/quilzo no longer hands the admin server its content " +
			"gates, so every publish through the browser refuses")
	}
}

// The gates refuse a claim nothing substantiates, which is the demo's own
// example of a gate that works.
func TestTheClaimsGateRefusesAnUnsubstantiatedClaim(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"kettle": map[string]any{
			"title": "A kettle",
			"body":  "Guaranteed for five years against the element.",
		},
	}, "first", "test"); err != nil {
		t.Fatal(err)
	}
	rules := `{"terms":[{"match":"guaranteed",` +
		`"why":"a guarantee is a promise somebody has to honour",` +
		`"needs":"guarantee_terms"}]}`
	if err := os.WriteFile(filepath.Join(root, "brand.json"),
		[]byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}

	refused, _, gerr := contentGates(root, s, "").Run()
	if gerr != nil {
		t.Fatalf("the gates could not run: %v", gerr)
	}
	if refused == nil {
		t.Fatal("a page claiming a guarantee with nothing to back it up " +
			"passed every gate. This is the demo's own example, and the " +
			"browser used to publish it")
	}
	if refused.Check.Name != "claims" {
		t.Errorf("refused by %q, want the claims gate", refused.Check.Name)
	}
}

// A gate that cannot run is a refusal, not a pass.
//
// The failure mode of every check that returns nil on error: "the claim check
// could not run" reaching somebody as "there are no claims to answer for".
// Corrupting the rules file would otherwise be the way to publish anything.
func TestAGateThatCannotRunRefuses(t *testing.T) {
	root := t.TempDir()
	if err := cmdInit(root); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home", "body": "Hello."},
	}, "first", "test"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "brand.json"),
		[]byte("this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	refused, _, gerr := contentGates(root, s, "").Run()
	if gerr == nil {
		t.Fatalf("an unreadable claim rules file was treated as no rules "+
			"(refused=%v); corrupting it is then the way to publish anything",
			refused)
	}
	if !strings.Contains(gerr.Error(), "could not run") {
		t.Errorf("the error does not say the check could not run: %v", gerr)
	}
}

// A page that reaches its expires date while live, as it was told to, does
// not stop the next publish of something else.
//
// The expiry gate read every page in the draft, so once an offer's date had
// passed every later publish, of a blog post or a price, was refused with
// "oldoffer expired ..., so publishing it would put up a page nobody can
// see", until somebody edited or removed a page that was doing exactly what
// it was set to. A page the publish puts up or changes is still refused.
func TestAPageThatExpiresWhileLiveDoesNotStopTheNextPublish(t *testing.T) {
	root := newStoreWithDraft(t)
	dir := t.TempDir()
	put := func(name, body string) {
		t.Helper()
		file := filepath.Join(dir, name+".json")
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := runCmd(t, root, "add", name+"="+file, "-m", name); err != nil {
			t.Fatal(err)
		}
		if err := runCmd(t, root, "provenance", "set", name, "--source", "humanEdits", "--author", "someone"); err != nil {
			t.Fatal(err)
		}
	}
	if err := runCmd(t, root, "provenance", "set", "index", "--source", "humanEdits", "--author", "someone"); err != nil {
		t.Fatal(err)
	}
	// Live while its window was open, which a test cannot wait for: put
	// live as it stood then, and its date is now in the past.
	put("oldoffer", `{"title":"Old offer","body":"Ten per cent off.","expires":"2026-01-01T00:00:00Z"}`)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}

	put("post", `{"title":"A new post","body":"Something unrelated."}`)
	if err := runPublish(t, root, "--no-a11y-check"); err != nil {
		t.Fatalf("a page that expired on schedule stopped an unrelated publish: %v", err)
	}

	// Changed, and still past its date: that would put up a page nobody
	// can see, and is refused, naming it.
	refused := func() string {
		t.Helper()
		old := w
		defer func() { w = old }()
		var buf bytes.Buffer
		w = out.New(false)
		w.Out = &buf
		if err := runPublish(t, root, "--no-a11y-check"); err == nil || !strings.Contains(err.Error(), "already past the date") {
			t.Fatalf("published a page already past its date: %v\n%s", err, buf.String())
		}
		return buf.String()
	}
	put("oldoffer", `{"title":"Old offer","body":"Fifteen per cent off.","expires":"2026-01-01T00:00:00Z"}`)
	if said := refused(); !strings.Contains(said, "oldoffer expired") {
		t.Fatalf("the refusal does not name the changed page:\n%s", said)
	}
	// And so is a new one, and only it.
	put("oldoffer", `{"title":"Old offer","body":"Ten per cent off.","expires":"2026-01-01T00:00:00Z"}`)
	put("lateoffer", `{"title":"Late offer","body":"Gone already.","expires":"2026-02-01T00:00:00Z"}`)
	if said := refused(); !strings.Contains(said, "lateoffer expired") || strings.Contains(said, "oldoffer expired") {
		t.Fatalf("the refusal of a new page already past its date says:\n%s", said)
	}
}
