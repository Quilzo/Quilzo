// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/handoff"
)

func wireInbox(t *testing.T, srv *Server) (*handoff.Store, string, *[]string) {
	t.Helper()
	store := &handoff.Store{Dir: t.TempDir()}
	_, id, _ := handoff.NewSecret()
	if _, err := store.Open("help", id, "can I return an opened bottle?",
		`I'd like to return order 1182 <script>alert(1)</script>`, time.Now()); err != nil {
		t.Fatal(err)
	}
	asked := &[]string{}
	srv.Inbox = &Inbox{
		List: store.List,
		Get:  store.Get,
		Reply: func(a, id, by, text string) error {
			_, err := store.Say(a, id, handoff.Person, by, text, time.Now())
			return err
		},
		Close: func(a, id, by string) error { return store.Close(a, id, by, time.Now()) },
		Suggest: func(a, q string) (string, []string, error) {
			*asked = append(*asked, a+"|"+q)
			return "Unopened items can be returned within 30 days.",
				[]string{"Returns"}, nil
		},
		Titles: func() map[string]string { return map[string]string{"help": "Ask the shop"} },
	}
	return store, id, asked
}

func inboxAct(t *testing.T, srv *Server, token string, v url.Values) (int, string, string) {
	t.Helper()
	w := postForm(t, srv, "/inbox/act", token, v.Encode())
	return w.Code, w.Header().Get("Location"), w.Body.String()
}

func TestAHandedOverConversationIsReadAndAnsweredFromTheInbox(t *testing.T) {
	srv, token := setup(t)
	store, id, _ := wireInbox(t, srv)

	list := get(t, srv, "/inbox", token).Body.String()
	whole(t, list)
	for _, want := range []string{"1</strong> waiting", "waiting for you",
		"Ask the shop", "/inbox/help/" + id} {
		if !strings.Contains(list, want) {
			t.Errorf("the inbox is missing %q", want)
		}
	}
	page := get(t, srv, "/inbox/help/"+id, token)
	body := page.Body.String()
	whole(t, body)
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("what the visitor wrote is on the page as markup")
	}
	if !strings.Contains(body, "can I return an opened bottle?") ||
		page.Header().Get("Cache-Control") != "no-store" {
		t.Error("the page lacks what they had asked, or may be cached")
	}

	code, loc, _ := inboxAct(t, srv, token, url.Values{"do": {"reply"},
		"assistant": {"help"}, "id": {id}, "text": {"Of course — which order?"},
		"by": {"somebody-else"}})
	if code != http.StatusSeeOther || !strings.Contains(loc, "m=Sent") ||
		strings.Contains(loc, "which+order") {
		t.Fatalf("replying answered %d to %s", code, loc)
	}
	c, _ := store.Get("help", id)
	last := c.Messages[len(c.Messages)-1]
	// Signed by whoever is signed in, whatever the form says.
	if last.From != handoff.Person || last.By != "editor" || last.Text != "Of course — which order?" {
		t.Fatalf("the reply is stored as %+v", last)
	}
	if !strings.Contains(get(t, srv, "/inbox", token).Body.String(), "Nobody is waiting") {
		t.Error("an answered conversation is still waiting")
	}

	if code, _, _ = inboxAct(t, srv, token, url.Values{"do": {"close"},
		"assistant": {"help"}, "id": {id}}); code != http.StatusSeeOther {
		t.Fatalf("ending answered %d", code)
	}
	if c, _ := store.Get("help", id); !c.Closed || c.ClosedBy != "editor" {
		t.Errorf("the conversation is %+v", c)
	}
	body = get(t, srv, "/inbox/help/"+id, token).Body.String()
	if strings.Contains(body, `name="text"`) {
		t.Error("an ended conversation still offers a reply box")
	}
}

// A suggestion goes in the box and nowhere else, and does not travel in an
// address.
func TestASuggestedReplyIsOnlyEverADraft(t *testing.T) {
	srv, token := setup(t)
	store, id, asked := wireInbox(t, srv)
	before, _ := store.Get("help", id)

	code, loc, body := inboxAct(t, srv, token, url.Values{"do": {"suggest"},
		"assistant": {"help"}, "id": {id}})
	if code != http.StatusOK || loc != "" {
		t.Fatalf("a suggestion answered %d to %q", code, loc)
	}
	if !strings.Contains(body, ">Unopened items can be returned within 30 days.</textarea>") ||
		!strings.Contains(body, "<li>Returns</li>") {
		t.Error("the suggestion is not in the reply box with its source")
	}
	if len(*asked) != 1 || !strings.HasPrefix((*asked)[0], "help|I'd like to return order 1182") {
		t.Errorf("the chatbot was asked %v", *asked)
	}
	after, _ := store.Get("help", id)
	if len(after.Messages) != len(before.Messages) {
		t.Fatal("a suggestion was sent")
	}
}

func TestARefusedReplyIsGivenBackNotLost(t *testing.T) {
	srv, token := setup(t)
	_, id, _ := wireInbox(t, srv)
	long := strings.Repeat("x", handoff.MaxText+5)
	code, loc, body := inboxAct(t, srv, token, url.Values{"do": {"reply"},
		"assistant": {"help"}, "id": {id}, "text": {long}})
	if code != http.StatusUnprocessableEntity || loc != "" ||
		!strings.Contains(body, long[:200]) || !strings.Contains(body, "at most") {
		t.Errorf("a refused reply answered %d, location %q", code, loc)
	}
}

func TestConversationsAreForWhoeverMayEditTheSite(t *testing.T) {
	srv, token := setup(t)
	store, id, _ := wireInbox(t, srv)
	if err := srv.Policy.Grant(auth.Binding{Principal: "looker",
		Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	reader, _, err := srv.Tokens.Issue("r", "looker", auth.RoleReader, "/",
		time.Hour, auth.RoleReader)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/inbox", "/inbox/help/" + id} {
		w := get(t, srv, path, reader)
		if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "order 1182") {
			t.Errorf("%s answered %d to a reader", path, w.Code)
		}
	}
	if code, _, _ := inboxAct(t, srv, reader, url.Values{"do": {"reply"},
		"assistant": {"help"}, "id": {id}, "text": {"hi"}}); code == http.StatusSeeOther {
		t.Error("a reader replied")
	}
	for _, bad := range []string{"/inbox/help/" + id + "0", "/inbox/other/" + id,
		"/inbox/help/" + id + "/x", "/inbox/help/" + strings.ToUpper(id)} {
		if w := get(t, srv, bad, token); w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d", bad, w.Code)
		}
	}
	if code, _, _ := inboxAct(t, srv, token, url.Values{"do": {"reply"},
		"assistant": {"other"}, "id": {id}, "text": {"hi"}}); code != http.StatusNotFound {
		t.Errorf("a reply to another assistant's conversation answered %d", code)
	}
	if c, _ := store.Get("help", id); len(c.Messages) != 1 {
		t.Fatal("something was sent")
	}
}

func TestEverySignOfAConversationIsInTheLogAndNothingSaid(t *testing.T) {
	srv, token := setup(t)
	_, id, _ := wireInbox(t, srv)
	var logged []string
	srv.Audit = func(action, resource string, detail map[string]string) {
		logged = append(logged, fmt.Sprintf("%s %s %v", action, resource, detail))
	}
	inboxAct(t, srv, token, url.Values{"do": {"reply"}, "assistant": {"help"},
		"id": {id}, "text": {"a private reply"}})
	if len(logged) == 0 || !strings.HasPrefix(logged[0], "handoff.reply /ask/help") {
		t.Fatalf("the log has %v", logged)
	}
	for _, l := range logged {
		if strings.Contains(l, "private reply") || strings.Contains(l, "1182") {
			t.Errorf("the log carries what was said: %s", l)
		}
	}
}
