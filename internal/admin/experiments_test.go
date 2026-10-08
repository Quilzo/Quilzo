// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/analytics"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/experiment"
)

func experimentsRig() (*Experiments, *experiment.Set) {
	set := &experiment.Set{}
	return &Experiments{
		Load: func() (*experiment.Set, error) {
			cp := &experiment.Set{Experiments: append([]experiment.Experiment(nil), set.Experiments...)}
			return cp, nil
		},
		Save: func(s *experiment.Set, _, _, _ string) error { *set = *s; return nil },
		Days: func(int) ([]analytics.Day, error) {
			return []analytics.Day{{Goals: map[string]int{
				experiment.SeenKey("price", "control"): 1000, experiment.WonKey("price", "control"): 100,
				experiment.SeenKey("price", "variant"): 1000, experiment.WonKey("price", "variant"): 150}}}, nil
		},
	}, set
}

func TestAnExperimentIsSetUpStartedAndReported(t *testing.T) {
	srv, token := setup(t)
	x, set := experimentsRig()
	srv.Experiments = x
	decideForm(t, srv, "/experiments/change", token, url.Values{"op": {"add"}, "name": {"price"},
		"page": {"pricing"}, "variant": {"pricing-b"}, "weight": {"50"}, "goal": {"form:contact"}})
	if e, ok := set.Get("price"); !ok || e.Running {
		t.Fatalf("not created stopped: %+v", set)
	}
	decideForm(t, srv, "/experiments/change", token, url.Values{"op": {"start"}, "name": {"price"}})
	if e, _ := set.Get("price"); !e.Running {
		t.Fatal("not started")
	}
	body := get(t, srv, "/experiments", token).Body.String()
	for _, want := range []string{"running", "15.0%", "variant converts better than control", "p = 0.00"} {
		if !strings.Contains(body, want) {
			t.Errorf("the report does not show %q", want)
		}
	}
}

// TestAGrantOnOnePageCoversATestOnIt, and not on another.
func TestAGrantOnOnePageCoversATestOnIt(t *testing.T) {
	x, set := experimentsRig()
	srv, _ := setup(t)
	pol := &auth.Policy{}
	pol.Grant(auth.Binding{Principal: "pat", Role: auth.RolePublisher, Resource: "/pricing"})
	pol.Grant(auth.Binding{Principal: "pat", Role: auth.RolePublisher, Resource: "/pricing-b"})
	pol.Grant(auth.Binding{Principal: "pat", Role: auth.RoleAuthor, Resource: "/"})
	ts := &auth.TokenStore{}
	token, _, err := ts.Issue("t", "pat", auth.RolePublisher, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	srv.Policy, srv.Tokens, srv.Experiments = pol, ts, x
	decideForm(t, srv, "/experiments/change", token, url.Values{"op": {"add"}, "name": {"price"},
		"page": {"pricing"}, "variant": {"pricing-b"}, "goal": {"form:contact"}})
	if _, ok := set.Get("price"); !ok {
		t.Fatal("a publisher of both pages could not test them")
	}
	decideForm(t, srv, "/experiments/change", token, url.Values{"op": {"add"}, "name": {"home"},
		"page": {"index"}, "variant": {"index-b"}, "goal": {"form:contact"}})
	if _, ok := set.Get("home"); ok {
		t.Fatal("a publisher of other pages started a test on the home page")
	}
}
