// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/api"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
)

// Every generic write surface refuses the register's collections (PLAN
// theme 6, decision D7).
//
// A record put into sec_control by `quilzo records add`, the content API or
// the agent interface would have passed none of register.Put's checks and
// would look, in a tree, like one that had. collection.Reserved refuses the
// name in every write of the collection package, and this walks the
// surfaces that write through it, as a person, a script and an agent reach
// them, to see each refuse and the draft not move: the command line's add,
// import and delete; the content API's POST, PUT and DELETE; and every
// operation of the agent interface that writes and takes a collection,
// write_record among them, found by walking the operations rather than
// named, so one added later is walked too.
func TestGenericWriteSurfacesRefuseSec(t *testing.T) {
	root, token := accessStore(t)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	draft := func() string { return s.GetRef(site.RefDraft) }
	before := draft()
	const reserved = "sec_control"

	// The command line.
	csv := filepath.Join(t.TempDir(), "controls.csv")
	if err := os.WriteFile(csv, []byte("ref,title\nAC-01,Second factor\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, line := range [][]string{
		{"records", "add", reserved, "ref=AC-01", "title=Second factor"},
		{"records", "import", reserved, csv},
		{"records", "delete", reserved, "0123456789abcdef0123456789abcdef"},
	} {
		_, e, code := cliRun(t, root, token, line...)
		if code == 0 || !strings.Contains(e, "reserved") {
			t.Errorf("`quilzo %s` exited %d: %s", strings.Join(line, " "), code, firstLines(e, 3))
		}
	}

	// The content API, as the admin mounts it: writable.
	srv := &api.Server{Store: s, Policy: &auth.Policy{}, Tokens: &auth.TokenStore{}, Ref: site.RefDraft, Writable: true,
		Types: func() (*schema.Store, error) { return schema.Load(root) },
		Records: &api.Records{Writable: true, Tree: func() (string, error) { return draftTree(s) },
			Commit: func(tree, message, author string) error { return commitTreeNoLock(s, tree, message, author) }}}
	if err := srv.Policy.Grant(auth.Binding{Principal: "owner", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	tok, _, err := srv.Tokens.Issue("api", "owner", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/v1/records/" + reserved, `{"ref":"AC-01"}`},
		{"PUT", "/api/v1/records/" + reserved + "/0123456789abcdef0123456789abcdef", `{"ref":"AC-01"}`},
		{"DELETE", "/api/v1/records/" + reserved + "/0123456789abcdef0123456789abcdef", ""},
	} {
		r := httptest.NewRequest(c.method, c.path, bytes.NewBufferString(c.body))
		r.Header.Set("Authorization", "Bearer "+tok)
		r.Header.Set("If-None-Match", "*")
		if c.method == "DELETE" {
			r.Header.Set("If-Match", "*")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 400 || w.Code >= 500 {
			t.Errorf("%s %s answered %d: %s", c.method, c.path, w.Code, w.Body)
		}
	}

	// The agent interface: every operation that writes and takes a
	// collection.
	m := buildMCP(root, s, asAdmin("owner"), "templates")
	walked := 0
	for _, op := range m.Operations() {
		if _, takes := op.Args["collection"]; !takes || !op.Writes {
			continue
		}
		walked++
		args := map[string]any{"collection": reserved, "fields": map[string]any{"ref": "AC-01"},
			"id": "0123456789abcdef0123456789abcdef"}
		for k := range args {
			if _, ok := op.Args[k]; !ok {
				delete(args, k)
			}
		}
		text, e := callTool(t, m, "quilzo_write", op.Name, args)
		said := text
		if e != nil {
			said = e.Message
		}
		if !strings.Contains(said, "reserved") {
			t.Errorf("%s with the collection %s answered %q", op.Name, reserved, firstLines(said, 2))
		}
	}
	if walked == 0 {
		t.Fatal("no operation of the agent interface writes a collection; write_record has gone, or the walk is wrong")
	}

	if after := draft(); after != before {
		t.Errorf("the draft moved from %s to %s while every write was refused", before, after)
	}
	tree, err := draftTree(s)
	if err != nil {
		t.Fatal(err)
	}
	names, err := collection.Names(s, tree)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if strings.HasPrefix(n, collection.ReservedPrefix) {
			t.Errorf("the draft holds a collection called %s", n)
		}
	}
}
