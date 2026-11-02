// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agentexec"
	"github.com/quilzo/quilzo/internal/auth"
)

// The Integrations screen lists writes that did not get through, and an
// administrator takes one off once it is settled; nobody else can.
func TestUndeliveredWritesAreShownAndSettled(t *testing.T) {
	srv, token := setup(t)
	list := []agentexec.Undelivered{{At: time.Now(), Agent: "errands", Run: "run-1", Step: 3, Integration: "crm",
		Tool: "createContact", Key: "qz-abc", Error: "crm answered 503"}}
	var dismissed []int
	srv.Integrations = &Integrations{
		Undelivered: func() ([]agentexec.Undelivered, error) { return list, nil },
		Dismiss:     func(n int, by string) error { dismissed = append(dismissed, n); return nil },
	}
	body := get(t, srv, "/integrations", token).Body.String()
	for _, want := range []string{"Writes that did not get through", "createContact", "qz-abc", "crm answered 503", "run run-1, step 3"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if _, loc := postFormLoc(t, srv, token, "/integrations/undelivered", url.Values{"n": {"1"}}); refused(loc) || len(dismissed) != 1 || dismissed[0] != 1 {
		t.Fatalf("%s %v", loc, dismissed)
	}
	editor, etoken := asRole(t, auth.RolePublisher)
	editor.Integrations = srv.Integrations
	postFormLoc(t, editor, etoken, "/integrations/undelivered", url.Values{"n": {"1"}})
	if len(dismissed) != 1 {
		t.Fatal("a publisher took one off the list")
	}
}
