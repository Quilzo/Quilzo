// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/lessons"
)

// The Learning screen shows an agent's weeks and its lessons, and adopting
// or retiring one goes to the person's decision, by id.
func TestTheLearningScreenShowsTheWeeksAndTheLessons(t *testing.T) {
	srv, token := setup(t)
	st := wireStudio(srv)
	now := time.Now()
	st.runs["run-20261014-00000001"] = agent.Keep("run-20261014-00000001", "dana", "m", now, agent.Trace{Agent: "helper",
		Goal: "answer", Complete: true, Lessons: []string{"ls_0123456789ab"}}, agent.Receipt{})
	st.runs["run-20261014-00000002"] = agent.Keep("run-20261014-00000002", "dana", "m", now, agent.Trace{Agent: "helper",
		Goal: "answer", Stopped: "a person declined it", Lessons: []string{"ls_0123456789ab"}}, agent.Receipt{})
	var adopted, retired []string
	srv.Agents.Lessons = func(string) ([]lessons.Lesson, error) {
		return []lessons.Lesson{
			{ID: "ls_0123456789ab", Agent: "helper", When: "a change waits for a person", Do: "say what will change", Kind: "task",
				State: lessons.Adopted, AdoptedFor: []string{"m"}, FromRun: "run-20261014-00000002", FromSignal: "a person declined it",
				Trials: []lessons.Trial{{Model: "m", Better: true, Why: "with it, 4 of 4 cases passed every time, against 2 without"}}},
			{ID: "ls_ba9876543210", Agent: "helper", When: "a page is a draft", Do: "check it is published", Kind: "check",
				State: lessons.Candidate, Tainted: true, FromRun: "run-20261014-00000002",
				Trials: []lessons.Trial{{Model: "m", Better: true, Why: "helped"}}},
		}, nil
	}
	srv.Agents.AdoptLesson = func(name, id string, taintedOK bool, act Actor) error {
		by := act.Name
		adopted = append(adopted, name+" "+id+" "+map[bool]string{true: "read", false: "unread"}[taintedOK]+" "+by)
		return nil
	}
	srv.Agents.RetireLesson = func(name, id, why string, _ Actor) error {
		retired = append(retired, name+" "+id+" "+why)
		return nil
	}
	body := get(t, srv, "/agents/learning?agent=helper", token).Body.String()
	whole(t, body)
	for _, want := range []string{"What helper is learning", "say what will change", "adopted for m",
		"from a run that read somebody else", "Read by 2 kept runs, 1 of which went wrong", "Adopt for m", "I have read it"} {
		if !strings.Contains(body, want) {
			t.Errorf("the screen does not say %q", want)
		}
	}
	postFormLoc(t, srv, token, "/agents/learning/act", url.Values{"do": {"adopt"}, "agent": {"helper"}, "id": {"ls_ba9876543210"}, "tainted_ok": {"yes"}})
	postFormLoc(t, srv, token, "/agents/learning/act", url.Values{"do": {"retire"}, "agent": {"helper"}, "id": {"ls_0123456789ab"}, "why": {"longer answers"}})
	postFormLoc(t, srv, token, "/agents/learning/act", url.Values{"do": {"adopt"}, "agent": {"../x"}, "id": {"ls_ba9876543210"}})
	postFormLoc(t, srv, token, "/agents/learning/act", url.Values{"do": {"adopt"}, "agent": {"helper"}, "id": {"../../etc"}})
	if len(adopted) != 1 || adopted[0] != "helper ls_ba9876543210 read editor" {
		t.Errorf("adopted %v", adopted)
	}
	if len(retired) != 1 || retired[0] != "helper ls_0123456789ab longer answers" {
		t.Errorf("retired %v", retired)
	}
}
