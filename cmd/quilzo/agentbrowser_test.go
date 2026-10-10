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
	"github.com/quilzo/quilzo/internal/cdp"
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
		case strings.Contains(last, "Paid") || strings.Contains(last, "declined"):
			choice = `{"op":"done","say":"finished"}`
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
