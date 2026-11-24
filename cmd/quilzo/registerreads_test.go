// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/api"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/site"
)

// No generic surface reads the register (STRATEGY 7.1).
//
// The register's own surfaces ask about its area, which a role over the site
// reaches only as administrator, so a reader of the site's pages does not
// read its risks. The surfaces that read whatever ref they are told to read,
// the site's export on the command line and the agent interface, the
// history, and the ref a replica asks for, asked about the site and the
// data area: told "register", or the commit the register stands at, they
// read every record of it to a reader of the site.
func TestGenericReadSurfacesDoNotReadTheRegister(t *testing.T) {
	root, token := accessStore(t)
	r := registerOn(t, root)
	secret := register.Control{Ref: "AC-77", Title: "A control only compliance reads", Domain: "identity", Owner: testOwner}
	if _, err := r.Put(testPerson, "a control", secret); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Propose(testCrew, "a proposed control", register.Control{Ref: "AC-78",
		Title: "A proposal only compliance reads", Domain: "identity", Owner: testOwner}); err != nil {
		t.Fatal(err)
	}
	head := r.Head()

	// A reader of the whole site, with no role on the compliance area.
	if _, e, code := cliRun(t, root, token, "auth", "grant", "rita", "reader"); code != 0 {
		t.Fatalf("auth grant: %s", e)
	}
	o, e, code := cliRun(t, root, token, "token", "issue", "rita", "--principal", "rita", "--role", "reader", "--json")
	if code != 0 {
		t.Fatalf("token issue: %s", e)
	}
	var issued struct{ Token string }
	if err := json.Unmarshal([]byte(o), &issued); err != nil || issued.Token == "" {
		t.Fatalf("token issue answered no token: %v", err)
	}
	rita := issued.Token
	leaked := func(s string) bool {
		return strings.Contains(s, secret.Title) || strings.Contains(s, "only compliance reads") ||
			strings.Contains(s, head) || strings.Contains(s, "a control")
	}

	// The command line.
	for _, ref := range []string{register.Ref, register.ProposalsRef, head} {
		dir := filepath.Join(t.TempDir(), "out")
		o, e, code := cliRun(t, root, rita, "export", "json", "--ref", ref, "--to", dir)
		files := ""
		_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				b, _ := os.ReadFile(p)
				files += string(b)
			}
			return nil
		})
		if code != 3 || leaked(o+files) {
			t.Errorf("`quilzo export --ref %s` by a reader of the site exited %d and wrote %q: %s", ref, code,
				firstLines(files, 3), firstLines(e, 2))
		}
		// The history takes a ref and not a commit, and is not there for one.
		o, e, code = cliRun(t, root, rita, "log", "--ref", ref)
		if code != 3 && (ref != head || code != 4) || leaked(o) {
			t.Errorf("`quilzo log --ref %s` by a reader of the site exited %d: %s%s", ref, code, firstLines(o, 3), firstLines(e, 2))
		}
	}

	// The agent interface, as the same reader.
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	reader := &Caller{Name: "rita", Role: auth.RoleReader, Scope: "/", Kind: audit.KindHuman, Verified: true}
	m := buildMCP(root, s, reader, "templates")
	for _, ref := range []string{register.Ref, head} {
		text, merr := callTool(t, m, "quilzo_read", "export_site", map[string]any{"format": "json", "ref": ref})
		said := text
		if merr != nil {
			said = merr.Message
		}
		// What was asked for may be said back; nothing else of the register.
		if leaked(strings.ReplaceAll(said, ref, "")) || !strings.Contains(said, "register") {
			t.Errorf("export_site of %s for a reader of the site answered %q", ref, firstLines(said, 3))
		}
	}

	// A replica, with a reader's credential for the whole site.
	srv := &api.Server{Store: s, Policy: &auth.Policy{}, Tokens: &auth.TokenStore{}, Ref: site.RefLive}
	if err := srv.Policy.Grant(auth.Binding{Principal: "rita", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	tok, _, err := srv.Tokens.Issue("replica", "rita", auth.RoleReader, "/", time.Hour, auth.RoleReader)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	for _, ref := range []string{register.Ref, register.ProposalsRef} {
		req := httptest.NewRequest("GET", "/api/v1/replica/ref/"+ref, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 403 || leaked(w.Body.String()) || strings.Contains(w.Body.String(), s.GetRef(ref)) {
			t.Errorf("a replica's credential for the site asked for the %s ref and was answered %d: %s", ref, w.Code, w.Body)
		}
	}

	// And somebody who may read the register reads its history.
	if o, e, code := cliRun(t, root, token, "log", "--ref", register.Ref); code != 0 || !strings.Contains(o, "a control") {
		t.Errorf("`quilzo log --ref register` by the owner exited %d: %s%s", code, firstLines(o, 3), firstLines(e, 2))
	}
}
