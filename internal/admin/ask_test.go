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
	tok, _, err := srv.Tokens.Issue("ria", "ria", auth.RoleReader, "/", time.Hour, auth.RoleAdmin)
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
