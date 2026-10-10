// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

// A run whose browser is asking a person shows the page with what it would
// press outlined; the picture is served to the studio, and kept by nothing
// on the way.
func TestABrowserRunShowsWhatItWouldPress(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	const id = "run-20261010-000000aa"
	why := `it presses button "Pay now" on shop.example.com, and it is called "Pay now"`
	tr := agent.Trace{Agent: "buyer", Goal: "pay the invoice", Tainted: true,
		Steps: []agent.Step{{N: 1, At: time.Now().Add(-time.Minute), Action: agent.Action{Op: "browser_open"}, Allowed: true, Result: "opened"}},
		Waiting: &agent.Pending{N: 2, Since: time.Now(), Live: true, Why: why,
			Action: agent.Action{Op: "browser_click", Input: map[string]any{"ref": "e1"}}}}
	rec := agent.Keep(id, "dana", "a-model", time.Now(), tr, agent.Receipt{Did: 1})
	rec.State = agent.Running
	st.runs[id] = rec
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 'x'}
	at := rec.Trace.Steps[0].At
	frames := []RunFrame{{N: 1, Op: "browser_open", When: at.Add(time.Second)},
		{N: 3, Op: "browser_click", When: at.Add(2 * time.Second), Asking: why}}
	srv.Agents.Frames = func(run string) ([]RunFrame, bool) { return frames, true }
	srv.Agents.Frame = func(run string, n int) ([]byte, error) {
		if run != id || (n != 3 && n != 1 && n != 0) {
			return nil, fmt.Errorf("no picture %d", n)
		}
		return jpeg, nil
	}
	var stopped []string
	srv.Agents.Stop = func(run, by string) error {
		stopped = append(stopped, run+" "+by)
		return nil
	}

	body := get(t, srv, "/agents/run/"+id, token).Body.String()
	for _, want := range []string{`src="/agents/frame/` + id + `/3"`, "outlined in red", "The run is waiting on this now", "Pay now",
		`src="/agents/frame/` + id + `/1"`, "The page after step 1", "Stop the run"} {
		if !strings.Contains(body, want) {
			t.Errorf("the run's page is missing %q", want)
		}
	}
	if strings.Contains(body, `http-equiv="refresh"`) {
		t.Error("a page asking a person refreshes under them")
	}
	w := get(t, srv, "/agents/frame/"+id+"/3", token)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/jpeg" ||
		!strings.Contains(w.Header().Get("Cache-Control"), "no-store") || w.Body.String() != string(jpeg) {
		t.Errorf("the picture: %d %v", w.Code, w.Header())
	}
	for _, bad := range []string{"/agents/frame/" + id + "/4", "/agents/frame/" + id + "/x", "/agents/frame/" + id, "/agents/frame/run-x/3"} {
		if w := get(t, srv, bad, token); w.Code != 404 {
			t.Errorf("%s answered %d", bad, w.Code)
		}
	}
	if w := get(t, srv, "/agents/frame/"+id+"/3", ""); w.Code == 200 {
		t.Error("the picture was served to nobody in particular")
	}

	// Still working, the page looks again until it finishes or asks, and
	// shows what the browser shows now.
	rec.Trace.Waiting = nil
	rec.Beat = time.Now()
	st.runs[id] = rec
	body = get(t, srv, "/agents/run/"+id, token).Body.String()
	for _, want := range []string{`http-equiv="refresh" content="2"`, `src="/agents/frame/` + id + `/live"`, "Stop the run"} {
		if !strings.Contains(body, want) {
			t.Errorf("a running run's page is missing %q", want)
		}
	}
	if w := get(t, srv, "/agents/frame/"+id+"/live", token); w.Code != 200 {
		t.Errorf("the picture of now answered %d", w.Code)
	}
	w = postForm(t, srv, "/agents/act", token, url.Values{"do": {"stop"}, "run": {id}}.Encode())
	if w.Code != 303 || len(stopped) != 1 || !strings.HasPrefix(stopped[0], id+" ") {
		t.Errorf("stopping answered %d; asked %v", w.Code, stopped)
	}

	// Finished, there is nothing to stop and nothing to look at again.
	rec.Trace.Complete, rec.State = true, ""
	st.runs[id] = rec
	body = get(t, srv, "/agents/run/"+id, token).Body.String()
	if strings.Contains(body, "Stop the run") || strings.Contains(body, `http-equiv="refresh"`) {
		t.Error("a finished run offers to stop or keeps refreshing")
	}
}
