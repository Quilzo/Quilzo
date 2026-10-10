// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
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
		Steps: []agent.Step{{N: 1, Action: agent.Action{Op: "browser_open"}, Allowed: true, Result: "opened"}},
		Waiting: &agent.Pending{N: 2, Since: time.Now(), Live: true, Why: why,
			Action: agent.Action{Op: "browser_click", Input: map[string]any{"ref": "e1"}}}}
	rec := agent.Keep(id, "dana", "a-model", time.Now(), tr, agent.Receipt{Did: 1})
	rec.State = agent.Running
	st.runs[id] = rec
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 'x'}
	srv.Agents.Asking = func(run, w string) (int, bool) { return 3, run == id && w == why }
	srv.Agents.Frame = func(run string, n int) ([]byte, error) {
		if run != id || n != 3 {
			return nil, fmt.Errorf("no picture %d", n)
		}
		return jpeg, nil
	}

	body := get(t, srv, "/agents/run/"+id, token).Body.String()
	for _, want := range []string{`src="/agents/frame/` + id + `/3"`, "outlined in red", "The run is waiting on this now", "Pay now"} {
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

	// Still working, the page looks again until it finishes or asks.
	rec.Trace.Waiting = nil
	rec.Beat = time.Now()
	st.runs[id] = rec
	if body := get(t, srv, "/agents/run/"+id, token).Body.String(); !strings.Contains(body, `http-equiv="refresh" content="2"`) {
		t.Error("a running run's page does not refresh")
	}
}
