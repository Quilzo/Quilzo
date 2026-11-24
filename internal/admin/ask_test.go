// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// labData gives a server two typed collections in its draft: samples, two
// of three checked out, and payroll.
func labData(t *testing.T, srv *Server) {
	t.Helper()
	reg := schema.NewRegistry()
	for _, typ := range []schema.Type{
		{Name: "sample", Fields: []schema.Field{{Name: "code", Kind: schema.Text}, {Name: "status", Kind: schema.Choice,
			Choices: []string{"available", "checked-out"}}, {Name: "weight", Kind: schema.Number}}},
		{Name: "salary", Fields: []schema.Field{{Name: "person", Kind: schema.Text}, {Name: "amount", Kind: schema.Number}}},
	} {
		if err := reg.Add(typ); err != nil {
			t.Fatal(err)
		}
	}
	st := &schema.Store{Registry: reg, Collections: map[string]string{"samples": "sample", "payroll": "salary"}}
	srv.Types = &Types{Load: func() (*schema.Store, error) { return st, nil }}

	tree, err := draftTreeOf(srv)
	if err != nil {
		t.Fatal(err)
	}
	put := func(c string, n int, fields map[string]any) {
		next, _, err := collection.Put(srv.Store, tree, c, collection.Record{ID: fmt.Sprintf("%032x", n), Fields: fields}, time.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		tree = next
	}
	put("samples", 1, map[string]any{"code": "S-1", "status": "checked-out", "weight": 2.0})
	put("samples", 2, map[string]any{"code": "S-2", "status": "checked-out", "weight": 3.0})
	put("samples", 3, map[string]any{"code": "S-3", "status": "available", "weight": 5.0})
	put("payroll", 4, map[string]any{"person": "dana", "amount": 100.0})
	parent := srv.Store.GetRef(site.RefDraft)
	commit, err := srv.Store.PutCommit(store.Commit{Tree: tree, Parents: []string{parent}, Message: "records", Author: "test", At: time.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Store.SetRef(site.RefDraft, commit); err != nil {
		t.Fatal(err)
	}
}

// withAsk gives a server a model answering with what it is told to, and a
// place to keep views.
func withAsk(srv *Server, answer string) (*briefModel, map[string][]SavedView) {
	m := &briefModel{answer: answer}
	kept := map[string][]SavedView{}
	srv.Ask = &Ask{
		Model: func(string) assist.Model { return m },
		Load:  func(p string) ([]SavedView, error) { return kept[p], nil },
		Save:  func(p string, v []SavedView) error { kept[p] = v; return nil },
	}
	return m, kept
}

// The model's view is held to the catalogue and to what the person may
// read: an unknown card, a collection they may not read, a field the type
// does not have and markup in a title are all left out.
func TestAnAnswerIsHeldToTheCardsAndWhatThePersonMayRead(t *testing.T) {
	src := askSources{Types: map[string]schema.Type{"samples": {Name: "sample", Fields: []schema.Field{
		{Name: "code", Kind: schema.Text}, {Name: "status", Kind: schema.Choice}, {Name: "weight", Kind: schema.Number}}}}}
	title, cards, notes := readAsk("```json\n"+`{"title":"<script>x</script>","cards":[
		{"kind":"figure","collection":"samples","where":[{"field":"status","match":"is","value":"checked-out"}],"op":"count"},
		{"kind":"table","collection":"payroll","fields":["amount"]},
		{"kind":"table","collection":"samples","fields":["code","secret","code"],"rows":900},
		{"kind":"figure","collection":"samples","op":"sum","field":"code"},
		{"kind":"html","collection":"samples"},
		{"kind":"runs","days":3},
		{"kind":"waiting","commits":"pays"}]}`+"\n```", src)
	if title != "" {
		t.Errorf("a title with markup was kept: %q", title)
	}
	if len(cards) != 3 || cards[0].Kind != "figure" || cards[1].Kind != "table" || cards[2].Kind != "waiting" {
		t.Fatalf("kept %+v", cards)
	}
	if got := cards[1]; strings.Join(got.Fields, ",") != "code" || got.Rows != 10 {
		t.Errorf("the table was not trimmed to its own fields and bounds: %+v", got)
	}
	if len(notes) != 4 {
		t.Errorf("left out without saying: %v", notes)
	}
	if !strings.Contains(strings.Join(notes, "\n"), `"payroll" is not a collection you may read`) {
		t.Errorf("%v", notes)
	}
}

// The question box takes 300 characters, and so does the server. It cut at
// 300 bytes: a question of 200 characters in Japanese reached the model as
// its first 100, and one cut inside a character as text that is not text.
func TestAQuestionIsBoundedInCharactersAsItsBoxIs(t *testing.T) {
	srv, token := setup(t)
	labData(t, srv)
	m, _ := withAsk(srv, `{"title":"Samples","cards":[{"kind":"figure","collection":"samples","op":"count"}]}`)
	long := strings.Repeat("\u691c\u4f53", 100)
	mixed := "a" + strings.Repeat("\u00e9", 250)
	for _, q := range []string{long, mixed} {
		if w := postForm(t, srv, "/today/ask", token, url.Values{"question": {q}}.Encode()); w.Code != http.StatusSeeOther {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		m.mu.Lock()
		told := m.asked[len(m.asked)-1]
		m.mu.Unlock()
		if !strings.Contains(told, q) || !utf8.ValidString(told) {
			t.Errorf("a question of %d characters did not reach the model whole", utf8.RuneCountInString(q))
		}
	}
	over := strings.Repeat("\u691c", 400)
	postForm(t, srv, "/today/ask", token, url.Values{"question": {over}}.Encode())
	m.mu.Lock()
	told := m.asked[len(m.asked)-1]
	m.mu.Unlock()
	if strings.Contains(told, over) || !strings.Contains(told, over[:3*maxQuestion]) || !utf8.ValidString(told) {
		t.Errorf("a question of 400 characters was not cut to %d", maxQuestion)
	}
}

// What the model is told is the collections the person may read, by their
// fields, and never a record.
func TestAQuestionIsAnsweredFromFieldsNotFromRecords(t *testing.T) {
	srv, _ := setup(t)
	labData(t, srv)
	srv.Policy.Grant(auth.Binding{Principal: "tess", Role: auth.RoleAuthor, Resource: auth.DataResource("samples")})
	prompt := askPrompt(srv.sourcesFor(principal{Name: "tess", Role: auth.RoleAuthor}), "what is checked out?")
	if !strings.Contains(prompt, "samples: code (text); status (choice: available, checked-out); weight (number)") ||
		strings.Contains(prompt, "payroll") || strings.Contains(prompt, "S-1") {
		t.Errorf("the model was told:\n%s", prompt)
	}
}

// Asking draws the answer from the records, says what each card counted,
// and keeps it on Today until it is taken off.
func TestAnAnswerIsDrawnFromTheRecordsAndCanBeKept(t *testing.T) {
	srv, token := setup(t)
	labData(t, srv)
	_, kept := withAsk(srv, `{"title":"Samples out","cards":[
		{"kind":"figure","collection":"samples","where":[{"field":"status","match":"is","value":"checked-out"}],"op":"count"},
		{"kind":"figure","collection":"samples","op":"sum","field":"weight"},
		{"kind":"bars","collection":"samples","by":"status"},
		{"kind":"table","collection":"samples","fields":["code","status"],"sort":"code"}]}`)

	if w := postForm(t, srv, "/today/ask", token, url.Values{"question": {"What is checked out?"}}.Encode()); w.Code != http.StatusSeeOther {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	body := get(t, srv, "/today", token).Body.String()
	whole(t, body)
	for _, want := range []string{
		`<h2 id="answer">Samples out</h2>`,
		`How many records in samples where status is &#34;checked-out&#34;`,
		`<p class="view-figure"><a href="/records?c=samples">2</a></p>`,
		`<p class="view-figure"><a href="/records?c=samples">10</a></p>`,
		`<th scope="row">checked-out</th><td>2</td>`,
		`<td>S-3</td>`,
		`Keep on Today`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the answer does not show %s", want)
		}
	}
	postForm(t, srv, "/today/pin", token, "do=pin")
	if len(kept["editor"]) != 1 || kept["editor"][0].Question != "What is checked out?" {
		t.Fatalf("kept %+v", kept)
	}
	body = get(t, srv, "/today", token).Body.String()
	if !strings.Contains(body, `<h2 id="views">Your views</h2>`) || strings.Contains(body, `id="answer"`) {
		t.Error("the kept view is not on Today, or the answer is still shown as new")
	}
	postForm(t, srv, "/today/pin", token, url.Values{"do": {"unpin"}, "id": {kept["editor"][0].ID}}.Encode())
	if len(kept["editor"]) != 0 {
		t.Error("the view was not taken off")
	}
}

// A kept view is drawn with what the person may read now, and somebody who
// may not use the models is not offered asking at all.
func TestAKeptViewFollowsAccessAndAReaderIsNotOfferedAsking(t *testing.T) {
	srv, _ := setup(t)
	labData(t, srv)
	srv.Policy.Grant(auth.Binding{Principal: "ria", Role: auth.RoleReader, Resource: "/"})
	tok, _, err := srv.Tokens.IssueSession("ria", "ria", auth.RoleReader, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	_, kept := withAsk(srv, `{"title":"x","cards":[]}`)
	kept["ria"] = []SavedView{{ID: "abc", Title: "Pay", Cards: []AskCard{{Kind: "figure", Collection: "payroll", Op: "count"}}}}
	srv.Policy.Grant(auth.Binding{Principal: "ria", Role: auth.RoleReader, Resource: auth.AreaData, Deny: true})
	body := get(t, srv, "/today", tok).Body.String()
	if strings.Contains(body, `id="ask"`) {
		t.Error("a reader is offered asking")
	}
	if !strings.Contains(body, "you may no longer read payroll") {
		t.Error("a kept view was drawn with access the person no longer has")
	}
	if w := postForm(t, srv, "/today/ask", tok, "question=pay"); w.Code != http.StatusForbidden {
		t.Errorf("a reader asked: %d", w.Code)
	}
}

// The question box spends the store's models, so it is offered to whoever
// may use them on the site's content, and to nobody whose work is an area.
//
// It asked whether somebody held use-models anywhere under "/", and an area
// is under "/": the analyst, compliance and support jobs, administrators or
// authors of their areas, hold every action of their rung there, use-models
// among them, though it means nothing in an area. So each was offered the
// box and spent the models from it, while the writing assistant and `quilzo
// assist`, which ask about the site, refused them.
func TestOnlyThoseWhoMayUseTheModelsOnContentAreOfferedAsking(t *testing.T) {
	srv, _ := setup(t)
	labData(t, srv)
	m, _ := withAsk(srv, `{"title":"x","cards":[]}`)
	for _, j := range []string{"analyst", "compliance", "support"} {
		job, _ := auth.JobNamed(j)
		for _, b := range job.Bindings {
			b.Principal = j
			if err := srv.Policy.Grant(b); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := srv.Policy.Grant(auth.Binding{Principal: "bea", Role: auth.RoleAuthor, Resource: "/blog"}); err != nil {
		t.Fatal(err)
	}
	session := func(who string) string {
		tok, _, err := srv.Tokens.IssueSession(who, who, auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	for _, who := range []string{"analyst", "compliance", "support"} {
		tok := session(who)
		if strings.Contains(get(t, srv, "/today", tok).Body.String(), `id="ask"`) {
			t.Errorf("the %s job is offered asking", who)
		}
		if w := postForm(t, srv, "/today/ask", tok, "question=how+many"); w.Code != http.StatusForbidden {
			t.Errorf("the %s job asked: %d", who, w.Code)
		}
	}
	if len(m.asked) != 0 {
		t.Errorf("the model was asked %d time(s) for somebody whose job holds no use-models", len(m.asked))
	}
	// An author of part of the site may use the models there, and asks.
	if w := postForm(t, srv, "/today/ask", session("bea"), "question=how+many"); w.Code != http.StatusSeeOther {
		t.Errorf("an author of /blog may not ask: %d", w.Code)
	}
	// And a credential that may not use the models does not ask through
	// its person's grant.
	capped, _, err := srv.Tokens.IssueSession("editor-r", "editor", auth.RoleReader, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	if w := postForm(t, srv, "/today/ask", capped, "question=how+many"); w.Code != http.StatusForbidden {
		t.Errorf("an administrator's session capped at reader asked: %d", w.Code)
	}
}

// Somebody granted use-models on its own asks through their own session,
// whose role is the rung they hold, as they use the writing assistant.
//
// A permission granted on its own is capped by the credential's path and
// limits and not by its role (auth.CheckGranted), and the question box
// asked the credential's role instead: a reader given use-models, signed in
// with a reader's session, was offered the writing assistant and not the
// box, though the permission is granted for both.
func TestUseModelsGrantedOnItsOwnAsks(t *testing.T) {
	srv, _ := setup(t)
	labData(t, srv)
	withAsk(srv, `{"title":"x","cards":[]}`)
	for _, b := range []auth.Binding{
		{Principal: "rae", Role: auth.RoleReader, Resource: "/"},
		{Principal: "rae", Permission: auth.ActUseModels, Resource: "/"},
		{Principal: "pat", Role: auth.RoleReader, Resource: "/blog"},
		{Principal: "pat", Permission: auth.ActUseModels, Resource: "/blog"},
	} {
		if err := srv.Policy.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	for _, who := range []string{"rae", "pat"} {
		tok, _, err := srv.Tokens.IssueSession(who, who, auth.RoleReader, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(get(t, srv, "/today", tok).Body.String(), `id="ask"`) {
			t.Errorf("%s, granted use-models, is not offered asking", who)
		}
		if w := postForm(t, srv, "/today/ask", tok, "question=how+many"); w.Code != http.StatusSeeOther {
			t.Errorf("%s, granted use-models, may not ask: %d", who, w.Code)
		}
	}
}
