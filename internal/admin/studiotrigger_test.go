// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

// An agent is given a trigger on its page, shown in a person's words with
// what it did today, and taken off again; a trigger the form gets wrong
// says why and changes nothing.
func TestAnAgentIsStartedOnItsOwnFromItsPage(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	if code, _ := studioAct(t, srv, token, declareForm("answers")); code != http.StatusSeeOther {
		t.Fatal(code)
	}
	body := get(t, srv, "/agents/edit/answers", token).Body.String()
	whole(t, body)
	for _, want := range []string{`id="triggers"`, "It runs only when somebody runs it.",
		`<option value="page.published">When pages go live</option>`, `<option value="schedule">On a schedule</option>`} {
		if !strings.Contains(body, want) {
			t.Errorf("the agent's page is missing %q", want)
		}
	}

	code, loc := studioAct(t, srv, token, url.Values{"do": {"trigger-add"}, "name": {"answers"},
		"on": {"page.published"}, "where": {"/blog"}, "goal": {"Summarise the new post"}, "per_day": {"5"}})
	if code != http.StatusSeeOther || !strings.HasSuffix(loc, "#triggers") || !strings.Contains(loc, "starts+on+its+own") {
		t.Fatalf("%d %s", code, loc)
	}
	ts := st.declared["answers"].Triggers
	if len(ts) != 1 || ts[0].On != "page.published" || ts[0].Where != "/blog" || ts[0].PerDay != 5 {
		t.Fatalf("%+v", ts)
	}

	// A schedule: every day at a time, in a zone.
	studioAct(t, srv, token, url.Values{"do": {"trigger-add"}, "name": {"answers"},
		"on": {"schedule"}, "every": {"24h"}, "at": {"07:30"}, "zone": {"Europe/London"},
		"where": {"/ignored"}, "goal": {"Check the docs for broken links"}})
	ts = st.declared["answers"].Triggers
	if len(ts) != 2 || ts[1].Every != agent.Duration(24*time.Hour) || ts[1].At != "07:30" || ts[1].Where != "" {
		t.Fatalf("%+v", ts)
	}

	srv.Agents.Triggered = func(string) map[string]TriggerStatus {
		return map[string]TriggerStatus{ts[0].Key(): {Today: 3, Last: time.Date(2026, 11, 2, 9, 5, 0, 0, time.UTC)}}
	}
	body = get(t, srv, "/agents/edit/answers", token).Body.String()
	whole(t, body)
	for _, want := range []string{"when pages go live (/blog)", "3 of 5 runs", "last at 09:05 on 2 Nov UTC",
		"every day at 07:30 Europe/London"} {
		if !strings.Contains(body, want) {
			t.Errorf("the triggers do not say %q", want)
		}
	}

	// Wrong: every 6 hours at a time of day. Refused, said, and nothing changes.
	code, loc = studioAct(t, srv, token, url.Values{"do": {"trigger-add"}, "name": {"answers"},
		"on": {"schedule"}, "every": {"6h"}, "at": {"07:30"}, "goal": {"x"}})
	if code != http.StatusSeeOther || !strings.Contains(loc, "e=") || len(st.declared["answers"].Triggers) != 2 {
		t.Fatalf("%d %s %+v", code, loc, st.declared["answers"].Triggers)
	}

	studioAct(t, srv, token, url.Values{"do": {"trigger-remove"}, "name": {"answers"}, "n": {"1"}})
	if ts := st.declared["answers"].Triggers; len(ts) != 1 || ts[0].On != agent.OnSchedule {
		t.Fatalf("%+v", ts)
	}
	if code, loc := studioAct(t, srv, token, url.Values{"do": {"trigger-remove"}, "name": {"answers"}, "n": {"7"}}); code != http.StatusSeeOther || !strings.Contains(loc, "e=") {
		t.Fatalf("removing a trigger that is not there: %d %s", code, loc)
	}
}
