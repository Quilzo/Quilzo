// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// withRecords puts two controls in the register of the server's store and
// proposes a third, as a crew would.
func withRecords(t *testing.T, srv *Server) (put, proposed register.ID) {
	t.Helper()
	r := register.Open(srv.Store)
	r.Audit = func(audit.Record) error { return nil }
	r.Now = func() time.Time { return time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC) }
	allow := func(auth.Action, string) error { return nil }
	owner := register.ID("0123456789abcdef0123456789abcdef")
	person := register.Actor{Name: "editor", Subject: "d0000000000000000000000000000001", Kind: audit.KindHuman, May: allow}
	rc, err := r.Put(person, "two controls",
		register.Control{Ref: "AC-01", Title: "Second factor for every account", Domain: "identity", Owner: owner},
		register.Control{Ref: "AC-02", Title: "Encrypted disks", Domain: "endpoints", Owner: owner})
	if err != nil {
		t.Fatal(err)
	}
	crew := register.Actor{Name: "control-tester", Kind: audit.KindAI, May: allow}
	pc, err := r.Propose(crew, "drafted from the access review",
		register.Control{Ref: "AC-03", Title: "Quarterly access review", Domain: "identity", Owner: owner})
	if err != nil {
		t.Fatal(err)
	}
	return rc.Written[0].ID, pc.Written[0].ID
}

// The register's screens read the register, and only the register: its
// kinds with how many of each, a kind's records, one record with the hash
// it is stored under, and what waits on the proposals ref, kept apart and
// counted in no figure.
func TestTheRegisterScreensReadTheRegister(t *testing.T) {
	srv, token := setup(t)
	put, proposed := withRecords(t, srv)
	head := register.Open(srv.Store).Head()

	page := get(t, srv, "/register", token)
	if page.Code != http.StatusOK {
		t.Fatalf("/register answered %d", page.Code)
	}
	body := page.Body.String()
	for _, want := range []string{"<h1>Register</h1>", "<caption>", `<th scope="row"><a href="/register/kind/control">Control</a></th>`,
		`<span class="kit-n">2</span>`, head, `href="/register/proposals"`} {
		if !strings.Contains(body, want) {
			t.Errorf("/register does not show %q", want)
		}
	}
	if strings.Contains(body, `<span class="kit-n">3</span>`) {
		t.Error("the proposal is counted with the register's controls")
	}

	kind := get(t, srv, "/register/kind/control", token).Body.String()
	if !strings.Contains(kind, "AC-01") || !strings.Contains(kind, "AC-02") || strings.Contains(kind, "AC-03") ||
		!strings.Contains(kind, `href="/register/record/`+string(put)+`"`) {
		t.Errorf("the controls are listed as\n%s", firstLines(kind, 80))
	}
	if w := get(t, srv, "/register/kind/nonsense", token); w.Code != http.StatusNotFound {
		t.Errorf("a kind that does not exist answered %d", w.Code)
	}

	rec := get(t, srv, "/register/record/"+string(put), token)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Second factor for every account") &&
		!strings.Contains(rec.Body.String(), "Encrypted disks") {
		t.Fatalf("the record answered %d\n%s", rec.Code, firstLines(rec.Body.String(), 40))
	}
	e, _ := register.Open(srv.Store).Get(put)
	if !strings.Contains(rec.Body.String(), e.Object) {
		t.Error("the record is shown without the hash it is stored under")
	}
	if w := get(t, srv, "/register/record/"+string(proposed), token); w.Code != http.StatusNotFound {
		t.Errorf("a proposal is shown as a record of the register: %d", w.Code)
	}

	props := get(t, srv, "/register/proposals", token).Body.String()
	if !strings.Contains(props, `id="p-`+string(proposed)+`"`) || !strings.Contains(props, "control-tester") ||
		strings.Contains(props, "Quarterly access review") {
		t.Errorf("the proposal is listed as\n%s", firstLines(props, 80))
	}

	for _, path := range []string{"/register", "/register/kind/control", "/register/record/" + string(put), "/register/proposals"} {
		for _, f := range a11y.Check(path, get(t, srv, path, token).Body.String()).Findings {
			if f.Severity == a11y.Blocking {
				t.Errorf("%s: %s (%s): %s", path, f.Rule, f.Criterion, f.Detail)
			}
		}
	}
}

// The register is the compliance area's: somebody who may read the site's
// pages is not shown it in the menu and is refused it at the door.
func TestTheRegisterIsTheComplianceAreas(t *testing.T) {
	srv, _ := setup(t)
	if err := srv.Policy.Grant(auth.Binding{Principal: "rita", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	secret, _, err := srv.Tokens.IssueSession("rita", "rita", auth.RoleReader, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if w := get(t, srv, "/register", secret); w.Code != http.StatusForbidden {
		t.Errorf("a reader of the site opened the register: %d", w.Code)
	}
	if body := get(t, srv, "/", secret).Body.String(); strings.Contains(body, `href="/register"`) {
		t.Error("a reader of the site is offered the register in the menu")
	}
}

// What registerScreens refuses, it refuses before anything is changed: a
// menu entry with no page of the manual, an icon nobody has, a section that
// is none, or a route another module serves.
func TestRegisteringAScreenIsHeldToTheTables(t *testing.T) {
	handle := func(*Server, http.ResponseWriter, *http.Request) {}
	good := screens{module: "example", routes: []screenRoute{{path: "/example", handle: handle}},
		nav: []navEntry{{destination: destination{Key: "example", Label: "Example", Path: "/example", Group: "Assurance",
			Doc: "compliance", Needs: auth.ActView}, icon: "verified", area: auth.AreaCompliance}}}
	if err := checkScreens(good); err != nil {
		t.Fatalf("a module declared rightly is refused: %v", err)
	}
	for what, change := range map[string]func(*screens){
		"no page of the manual":      func(m *screens) { m.nav[0].Doc = "nowhere" },
		"an icon nobody has":         func(m *screens) { m.nav[0].icon = "unicorn" },
		"a section that is none":     func(m *screens) { m.nav[0].Group = "Elsewhere" },
		"an entry it does not serve": func(m *screens) { m.nav[0].Path = "/elsewhere" },
		"a route a module serves":    func(m *screens) { m.routes[0].path = "/register" },
		"an entry the menu has":      func(m *screens) { m.nav[0].Key = "security" },
		"an area that is none":       func(m *screens) { m.nav[0].area = "/blog" },
		"a route with no handler":    func(m *screens) { m.routes[0].handle = nil },
		"no name":                    func(m *screens) { m.module = "" },
	} {
		m := good
		m.routes = append([]screenRoute(nil), good.routes...)
		m.nav = append([]navEntry(nil), good.nav...)
		change(&m)
		if err := checkScreens(m); err == nil {
			t.Errorf("a module with %s is registered", what)
		}
	}
}
