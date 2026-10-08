// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/fleet"
)

func TestTheFleetIsAnAdministratorsMapOfWhoCalledWhat(t *testing.T) {
	srv, token := setup(t)
	now := time.Now()
	var registered []string
	srv.Fleet = &Fleet{
		View: func(days int) (fleet.View, error) {
			return fleet.View{Days: days, Nodes: []fleet.Node{
				{ID: "agent:tidy", Kind: fleet.KindAgent, Name: "tidy", Owner: "dana", Standing: "until 5 Jan 2027", Autonomy: "draft"},
				{ID: "person:dana", Kind: fleet.KindPerson, Name: "dana", Last: now},
				{ID: "tool:tracker", Kind: fleet.KindTool, Name: "tracker", Flags: []string{"1 tool nobody pinned"}},
				{ID: "external:help-desk", Kind: fleet.KindExternal, Name: "help-desk", Owner: "dana"},
			}, Edges: []fleet.Edge{{From: "person:dana", To: "agent:tidy", Calls: 3, Last: now},
				{From: "agent:tidy", To: "tool:tracker", Calls: 1, Last: now}},
				Shadow: []fleet.Sighting{{Service: "OpenAI", Where: "api.openai.com", Who: "okta:rae", Source: "zscaler/web", Count: 4, Last: now}}}, nil
		},
		Register: func(cardURL, name, by string) error { registered = append(registered, cardURL+"|"+by); return nil },
		Remove:   func(name, by string) error { return nil },
		Check:    func() ([]string, error) { return []string{"help-desk"}, nil },
	}
	body := get(t, srv, "/fleet", token).Body.String()
	for _, want := range []string{"Who called what", `class="agmap fleetmap"`, "dana → tidy: 3 calls", "1 tool nobody pinned",
		"Other vendors&#39; agents", "api.openai.com", "okta:rae", `name="card"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the screen lacks %q", want)
		}
	}
	w := postForm(t, srv, "/fleet/act", token, url.Values{"op": {"register"}, "card": {"https://agents.example.com/card"}}.Encode())
	if w.Code != http.StatusSeeOther || len(registered) != 1 || registered[0] != "https://agents.example.com/card|editor" {
		t.Fatalf("%d %v", w.Code, registered)
	}
	if w := postForm(t, srv, "/fleet/act", token, url.Values{"op": {"check"}}.Encode()); !strings.Contains(w.Header().Get("Location"), "help-desk") {
		t.Fatalf("a changed card is not said: %s", w.Header().Get("Location"))
	}
	// An author sees none of it.
	if err := srv.Policy.Grant(auth.Binding{Principal: "rae", Role: auth.RoleAuthor, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	rae, _, _ := srv.Tokens.Issue("rae", "rae", auth.RoleAuthor, "/", time.Hour, auth.RoleAdmin)
	if w := get(t, srv, "/fleet", rae); w.Code != http.StatusForbidden {
		t.Fatalf("an author saw the fleet: %d", w.Code)
	}
	if w := postForm(t, srv, "/fleet/act", rae, url.Values{"op": {"register"}, "card": {"https://x.example/c"}}.Encode()); w.Code != http.StatusForbidden || len(registered) != 1 {
		t.Fatalf("an author registered an agent: %d", w.Code)
	}
}
