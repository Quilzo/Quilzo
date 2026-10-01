// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/render"
)

var staticBot = assistant.Assistant{Name: "help", Title: "Ask the shop", Public: true,
	Static: true, Exclude: []string{"drafts"}}

// The corpus the browser and the server are both asked about. Long enough to
// exercise the parts that only run on a real site: more than six passages,
// so the common-word rule applies; a passage over ninety words, so answers
// are cut to their best sentences; plurals, -ing and -ed, an apostrophe and
// a word that is not ASCII.
func parityPages() map[string]any {
	long := "The workshop is in Leeds, above the bakery on Mill Street. " +
		"It opens at nine on weekdays and at ten on Saturdays. " +
		"Parking is on the street, and the nearest station is twelve minutes away on foot. " +
		"We run binding classes on the first Saturday of each month. " +
		"Classes are small, six people at most, and every material is included. " +
		"Booking closes two days before a class, because the paper is cut for each person. " +
		"If a class is cancelled, we refund the booking in full within five working days. " +
		"Gift vouchers can be used for classes and for anything in the shop. " +
		"The café next door does the coffee, and we would rather you did not bring it near the paper."
	return map[string]any{
		"index":         map[string]any{"title": "Marginalia", "intro": "Paper, made in small runs, and the tools for writing on it."},
		"returns":       map[string]any{"title": "Returns", "body": "Opened ink bottles cannot be returned. Unopened items can be returned within 30 days."},
		"delivery":      map[string]any{"title": "Delivery", "body": "UK delivery is £4 and takes two working days. We ship to the EU for £12."},
		"workshop":      map[string]any{"title": "The workshop", "body": long},
		"pens":          map[string]any{"title": "Pens", "body": "Brass and copper fountain pens, filled from a bottle or a cartridge. Copper darkens as it's handled."},
		"paper":         map[string]any{"title": "Paper", "body": "Cotton rag paper, pressed by hand in Zürich. Sheets are sold in packs of twenty-five."},
		"cleaning":      map[string]any{"title": "Cleaning a pen", "body": "Flush the nib with cool water when changing inks. Cleaning takes five minutes and stops a pen from drying out."},
		"drafts/secret": map[string]any{"title": "Pricing plan", "body": "Next year the copper pen goes up to £60."},
		// Section-shaped, so passages carry headings and the third ranker
		// has something to rank.
		"help": map[string]any{"title": "Help", "sections": []any{
			map[string]any{"faq": map[string]any{"title": "Questions", "items": []any{
				map[string]any{"q": "Can I return opened ink?", "a": "No. Opened bottles cannot go back, because we cannot sell them again."},
				map[string]any{"q": "Do you ship to France?", "a": "Yes. Anywhere in the EU, for twelve pounds, in about five days."},
				map[string]any{"q": "Can I visit the workshop?", "a": "Yes, on Saturdays. Booking is not needed for a visit, only for a class."},
			}}},
			map[string]any{"steps": map[string]any{"title": "Ordering", "items": []any{
				map[string]any{"title": "Choose", "body": "Pick the paper, the pen and the ink."},
				map[string]any{"title": "Pay", "body": "Card or bank transfer; nothing is taken until it ships."},
			}}},
		}},
	}
}

type parityCase struct {
	Q    string `json:"q"`
	Prev string `json:"prev"`
}

type parityResult struct {
	Problem   bool     `json:"problem"`
	Refused   bool     `json:"refused"`
	Hits      []string `json:"hits"`
	Sentences []string `json:"sentences"`
}

var parityCases = []parityCase{
	{Q: "can I return opened ink?"},
	{Q: "how much is delivery to the EU"},
	{Q: "What about returns?", Prev: "how much is delivery"},
	{Q: "and to France?", Prev: "how much is delivery"},
	{Q: "when does the workshop open on saturdays"},
	{Q: "is parking available near the workshop"},
	{Q: "what happens if my class is cancelled"},
	{Q: "cleaning pens"},
	{Q: "changing inks"},
	{Q: "Where is the paper pressed? Zürich?"},
	{Q: "does copper darken"},
	{Q: "it's handled"},
	{Q: "what is the meaning of life"},
	{Q: "what is the weather in Leeds tomorrow"},
	{Q: "the copper pen price next year"},
	{Q: "   "},
	{Q: "booking classes gift vouchers"},
	{Q: "PAPER packs"},
	{Q: "Do you ship to France?"},
	{Q: "can i visit the workshop"},
	{Q: "Can I return opened ink?"},
	{Q: "how do I pay"},
}

// The browser answers every question exactly as the server does.
//
// The browser's engine is a port, and a port drifts: somebody tunes the
// floor or the stop list in Go, and a static copy goes on answering with the
// old rules, plausibly, with nothing to say it differs. So this runs the
// shipped script — the same bytes the page carries — under Node, against the
// same passages, and compares which passages each answer came from and what
// it quoted.
func TestTheBrowserAnswersAsTheServerDoes(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is not installed, and CI must run this test")
		}
		t.Skip("node is not installed; CI runs this")
	}

	a := staticBot
	ps := assistant.Chunk(parityPages(), a.Reads)
	idx := assistant.BrowserIndex(ps)

	var want []parityResult
	for _, c := range parityCases {
		ans, err := assistant.RespondTo(context.Background(), a, idx, nil, c.Q, c.Prev)
		r := parityResult{Problem: err != nil, Refused: ans.Refused,
			Hits: []string{}, Sentences: []string{}}
		if err == nil {
			for _, h := range ans.Sources {
				r.Hits = append(r.Hits, h.ID)
			}
			if !ans.Refused {
				for _, s := range ans.Kept {
					r.Sentences = append(r.Sentences, s.Text)
				}
			}
		}
		want = append(want, r)
	}

	dir := t.TempDir()
	k := assistant.Browser(a, ps, func(p assistant.Passage) string { return p.Link() })
	writeParityJSON(t, filepath.Join(dir, "k.json"), k)
	writeParityJSON(t, filepath.Join(dir, "cases.json"), parityCases)
	if err := os.WriteFile(filepath.Join(dir, "engine.js"), []byte(askStaticJS), 0o600); err != nil {
		t.Fatal(err)
	}
	harness := `const fs = require("fs"), vm = require("vm"), path = require("path");
const dir = process.argv[2];
globalThis.__quilzoAskHarness = function (engine) {
  const k = JSON.parse(fs.readFileSync(path.join(dir, "k.json"), "utf8"));
  const cases = JSON.parse(fs.readFileSync(path.join(dir, "cases.json"), "utf8"));
  const e = new engine.Engine(k);
  const out = cases.map(function (c) {
    const a = e.respond(c.q, c.prev);
    if (a.problem) return { problem: true, refused: false, hits: [], sentences: [] };
    return { problem: false, refused: !!a.refused,
      hits: a.hits.map(function (h) { return k.passages[h.i].id; }),
      sentences: a.refused ? [] : a.sentences };
  });
  process.stdout.write(JSON.stringify(out));
};
vm.runInThisContext(fs.readFileSync(path.join(dir, "engine.js"), "utf8"));
`
	if err := os.WriteFile(filepath.Join(dir, "harness.js"), []byte(harness), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, filepath.Join(dir, "harness.js"), dir).Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	var got []parityResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("the harness printed %q: %v", out, err)
	}
	if len(got) != len(want) {
		t.Fatalf("%d answers for %d questions", len(got), len(want))
	}
	answered := 0
	for i, c := range parityCases {
		g, w := got[i], want[i]
		if g.Problem != w.Problem || g.Refused != w.Refused ||
			strings.Join(g.Hits, "|") != strings.Join(w.Hits, "|") ||
			strings.Join(g.Sentences, "|") != strings.Join(w.Sentences, "|") {
			t.Errorf("%q (after %q):\n  browser %+v\n  server  %+v", c.Q, c.Prev, g, w)
		}
		if !w.Refused && !w.Problem {
			answered++
		}
	}
	// A corpus nothing answers would agree trivially.
	if answered < 10 {
		t.Errorf("only %d of the questions were answered; the corpus is not "+
			"exercising the engine", answered)
	}
}

func writeParityJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A static copy carries the conversation page, its script, and what it
// answers from — and the policy permits that script and nothing else.
func TestAStaticCopyCarriesTheChatbot(t *testing.T) {
	st, _ := askSite(t, staticBot)
	files, err := st.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	page, ok := files["ask/help/index.html"]
	if !ok {
		t.Fatal("the static copy has no conversation page")
	}
	if _, ok := files["ask/help/knowledge.json"]; !ok {
		t.Fatal("the static copy has nothing to answer from")
	}
	if _, ok := files["ask.css"]; !ok {
		t.Fatal("the conversation page's stylesheet is missing")
	}
	checkScriptHash(t, string(page))

	// And moved into a subdirectory, the script is untouched, so the hash
	// still names it.
	moved := render.Rebase(files, "/demo")
	checkScriptHash(t, string(moved["ask/help/index.html"]))
	if !strings.Contains(string(moved["ask/help/index.html"]), `action="/demo/ask/help/"`) {
		t.Error("the form's action was not moved, and the script finds " +
			"everything else from it")
	}
}

var (
	reInline = regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	reMeta   = regexp.MustCompile(`http-equiv="Content-Security-Policy" content="([^"]*)"`)
)

func checkScriptHash(t *testing.T, page string) {
	t.Helper()
	scripts := reInline.FindAllStringSubmatch(page, -1)
	if len(scripts) != 1 {
		t.Fatalf("%d inline scripts on the page, want 1", len(scripts))
	}
	sum := sha256.Sum256([]byte(scripts[0][1]))
	hash := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	m := reMeta.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("the static page carries no policy")
	}
	policy := strings.ReplaceAll(m[1], "&#39;", "'")
	if !strings.Contains(policy, "script-src "+hash) {
		t.Errorf("the policy does not name the script it carries:\n  %s\n  want %s",
			policy, hash)
	}
	script := reScriptSrc.FindString(policy)
	if script != "script-src "+hash {
		t.Errorf("script-src allows more than the one script:\n  %s", script)
	}
	if !strings.Contains(policy, "connect-src 'self'") {
		t.Errorf("the script cannot fetch what it answers from:\n  %s", policy)
	}
}

// What ships is only what the live site would serve anyway.
func TestTheStaticKnowledgeHoldsOnlyPublishedPages(t *testing.T) {
	bot := staticBot
	bot.Documents = []string{strings.Repeat("a", 64)}
	st, _ := askSite(t, bot)
	st.Assistants.Document = func(string) (string, string, []byte, error) {
		return "contract.md", "markdown", []byte("# Terms\n\nThe supplier discount is forty per cent."), nil
	}
	w := get(st, "/ask/help/knowledge.json", nil)
	if w.Code != 200 {
		t.Fatalf("knowledge.json: %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "forty per cent") || strings.Contains(body, "contract.md") {
		t.Error("a document the assistant reads was published whole in a static copy")
	}
	if strings.Contains(body, "copper pen goes up") {
		t.Error("an excluded page reached the static knowledge")
	}
	if !strings.Contains(body, "cannot be returned") {
		t.Error("a published page is missing from the static knowledge")
	}
	if w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("served as %q", w.Header().Get("Content-Type"))
	}
}

// An assistant that did not declare static has neither address, on the live
// site or in a copy.
func TestOnlyAStaticAssistantHasAStaticCopy(t *testing.T) {
	st, _ := askSite(t, shopBot)
	if w := get(st, "/ask/help/knowledge.json", nil); w.Code != 404 {
		t.Errorf("knowledge.json for a server-only assistant: %d", w.Code)
	}
	if w := get(st, "/ask/help?copy=static", nil); strings.Contains(w.Body.String(), "<script>") {
		t.Error("a server-only assistant served the static page")
	}
	files, err := st.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	for name := range files {
		if strings.HasPrefix(name, "ask/") {
			t.Errorf("the copy carries %s for an assistant that did not ask to be static", name)
		}
	}
}

// A static assistant has to be public: a copy carries only what is served.
func TestAStaticAssistantMustBePublic(t *testing.T) {
	a := staticBot
	a.Public = false
	if err := a.Validate(); err == nil {
		t.Error("a private assistant was allowed on static copies")
	}
}

// The question box is a GET form, so the live site answers a question in
// the address.
func TestAQuestionInTheAddressIsAnswered(t *testing.T) {
	st, audited := askSite(t, shopBot)
	w := get(st, "/ask/help?q=can+I+return+opened+ink", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "cannot be returned") {
		t.Fatalf("%d\n%s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("an answer in reply to a GET is cacheable")
	}
	if len(*audited) != 1 {
		t.Errorf("the question was not recorded: %v", *audited)
	}
	// HEAD answers nothing and spends nothing.
	if w := head(st, "/ask/help?q=returns"); w.Code != 200 || len(*audited) != 1 {
		t.Errorf("HEAD: %d, audited %v", w.Code, *audited)
	}
}

func head(st *Site, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodHead, path, nil)
	w := httptest.NewRecorder()
	st.Handler().ServeHTTP(w, req)
	return w
}

// The conversation answers at its address with a trailing slash, which is
// where a static host serves the directory it is in.
func TestTheAskAddressTakesATrailingSlash(t *testing.T) {
	st, _ := askSite(t, shopBot)
	w := get(st, "/ask/help/?q=can+I+return+opened+ink", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "cannot be returned") {
		t.Fatalf("%d", w.Code)
	}
}
