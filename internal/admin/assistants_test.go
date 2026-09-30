// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/auth"
)

type fakeAssistants struct {
	warnings []string
	set      *assistant.Set
	changes  []string
	model    assistant.Model
}

func (f *fakeAssistants) wire() *Assistants {
	return &Assistants{
		Load: func() (*assistant.Set, error) {
			// A copy, as a file would be.
			cp := &assistant.Set{Assistants: append([]assistant.Assistant(nil), f.set.Assistants...)}
			return cp, nil
		},
		Save: func(s *assistant.Set, by, change, name string) error {
			f.set = s
			f.changes = append(f.changes, by+" "+change+" "+name)
			return nil
		},
		Index: func(a assistant.Assistant) (*assistant.Index, []string, error) {
			return assistant.NewIndex(assistant.Chunk(map[string]any{
				"returns": map[string]any{"title": "Returns",
					"body": "Opened ink bottles cannot be returned. <b>bold</b>"},
			}, a.Reads)), f.warnings, nil
		},
		Documents: func() ([]DocumentChoice, error) {
			return []DocumentChoice{{ID: strings.Repeat("a", 64), Name: "care.pdf", Format: "pdf"}}, nil
		},
		Model: func(assistant.Assistant) (assistant.Model, string) { return f.model, "" },
		Forms: func() ([]string, error) { return []string{"returns_form"}, nil },
	}
}

func chatbots(t *testing.T) (*Server, string, *fakeAssistants) {
	t.Helper()
	srv, token := setup(t)
	fa := &fakeAssistants{set: &assistant.Set{}}
	srv.Assistants = fa.wire()
	return srv, token, fa
}

func TestAChatbotIsCreatedConfiguredAndRemoved(t *testing.T) {
	srv, token, fa := chatbots(t)
	w := decideForm(t, srv, "/assistants/save", token, url.Values{"name": {"help"}, "title": {"Ask the shop"}})
	if w.Code != http.StatusSeeOther || len(fa.set.Assistants) != 1 {
		t.Fatalf("create: %d %+v", w.Code, fa.set)
	}
	decideForm(t, srv, "/assistants/save", token, url.Values{"name": {"help"}, "full": {"1"},
		"title": {"Ask the shop"}, "exclude": {"internal, drafts"}, "public": {"1"}})
	a, _ := fa.set.Get("help")
	if !a.Public || len(a.Exclude) != 2 {
		t.Fatalf("settings were not saved: %+v", a)
	}
	decideForm(t, srv, "/assistants/action", token, url.Values{"assistant": {"help"},
		"action": {"start-return"}, "kind": {"form"}, "target": {"returns_form"},
		"description": {"start a return"}, "fields": {"order"}})
	if a, _ = fa.set.Get("help"); len(a.Actions) != 1 {
		t.Fatalf("the action was not added: %+v", a)
	}
	decideForm(t, srv, "/assistants/action", token, url.Values{"assistant": {"help"},
		"action": {"start-return"}, "remove": {"1"}})
	if a, _ = fa.set.Get("help"); len(a.Actions) != 0 {
		t.Fatal("the action was not removed")
	}
	decideForm(t, srv, "/assistants/remove", token, url.Values{"name": {"help"}})
	if len(fa.set.Assistants) != 0 {
		t.Fatal("the chatbot was not removed")
	}
	// Every change is attributed.
	for _, c := range fa.changes {
		if !strings.HasPrefix(c, "editor ") {
			t.Errorf("a change was not attributed: %q", c)
		}
	}
}

func TestAnInvalidChatbotIsRefusedWithTheReason(t *testing.T) {
	srv, token, fa := chatbots(t)
	w := decideForm(t, srv, "/assistants/save", token, url.Values{"name": {"Help Desk"}, "title": {"x"}})
	if len(fa.set.Assistants) != 0 || !strings.Contains(w.Header().Get("Location"), "e=") {
		t.Fatalf("an invalid name was stored: %+v", fa.set)
	}
	decideForm(t, srv, "/assistants/save", token, url.Values{"name": {"help"}, "title": {"Help"}})
	w = decideForm(t, srv, "/assistants/action", token, url.Values{"assistant": {"help"},
		"action": {"go"}, "kind": {"link"}, "target": {"javascript:alert(1)"}, "description": {"x"}})
	if a, _ := fa.set.Get("help"); len(a.Actions) != 0 {
		t.Fatal("an action pointing off the site was stored")
	}
}

// unfaithful writes one supported sentence and one invented one.
type unfaithful struct{}

func (unfaithful) Name() string { return "u" }
func (unfaithful) Complete(context.Context, string, string) (string, error) {
	return `{"answer": "Opened ink bottles cannot be returned [1]. Refunds take 3 days [1].", "action": null}`, nil
}

// TestTheConsoleShowsWhatWasRemovedAndWhy.
func TestTheConsoleShowsWhatWasRemovedAndWhy(t *testing.T) {
	srv, token, fa := chatbots(t)
	fa.set.Put(assistant.Assistant{Name: "help", Title: "Help", UseModel: true})
	fa.model = unfaithful{}
	body := get(t, srv, "/assistants/help?q="+url.QueryEscape("can I return opened ink"), token).Body.String()
	for _, want := range []string{"cannot be returned", "Removed before a visitor would see it",
		"Refunds take 3 days", "says 3", "Keyword rank"} {
		if !strings.Contains(body, want) {
			t.Errorf("the console does not show %q", want)
		}
	}
	// Page text is shown as text.
	if strings.Contains(body, "<b>bold</b>") {
		t.Fatal("passage text reached the page unescaped")
	}
}

func TestOnlyAPublisherChangesAChatbot(t *testing.T) {
	fa := &fakeAssistants{set: &assistant.Set{}}
	fa.set.Put(assistant.Assistant{Name: "help", Title: "Help"})
	author, atoken := asRole(t, auth.RoleAuthor)
	author.Assistants = fa.wire()
	if w := get(t, author, "/assistants/help", atoken); w.Code != http.StatusOK {
		t.Fatalf("an author could not try a chatbot: %d", w.Code)
	}
	decideForm(t, author, "/assistants/save", atoken, url.Values{"name": {"help"}, "full": {"1"},
		"title": {"Help"}, "public": {"1"}})
	if a, _ := fa.set.Get("help"); a.Public {
		t.Fatal("an author made a chatbot public")
	}
	reader, rtoken := asRole(t, auth.RoleReader)
	reader.Assistants = fa.wire()
	if w := get(t, reader, "/assistants", rtoken); w.Code == http.StatusOK {
		t.Fatal("a reader opened the chatbots screen")
	}
}

func TestDocumentsAndEmbeddingAreConfigured(t *testing.T) {
	srv, token, fa := chatbots(t)
	fa.set.Put(assistant.Assistant{Name: "help", Title: "Help"})
	doc := strings.Repeat("a", 64)
	decideForm(t, srv, "/assistants/save", token, url.Values{"name": {"help"}, "full": {"1"},
		"title": {"Help"}, "public": {"1"}, "documents": {doc},
		"embed": {"https://Shop.Example\nhttp://localhost:8080"}})
	a, _ := fa.set.Get("help")
	if len(a.Documents) != 1 || len(a.Embed) != 2 || a.Embed[0] != "https://shop.example" {
		t.Fatalf("%+v", a)
	}
	body := get(t, srv, "/assistants/help", token).Body.String()
	if !strings.Contains(body, "?embed=1") || !strings.Contains(body, `value="`+doc+`" checked`) {
		t.Fatal("the embed snippet or the document choice is not shown")
	}
	// A wildcard is refused with the reason, and nothing is saved.
	w := decideForm(t, srv, "/assistants/save", token, url.Values{"name": {"help"}, "full": {"1"},
		"title": {"Help"}, "embed": {"*"}})
	if !strings.Contains(w.Header().Get("Location"), "e=") {
		t.Fatal("a wildcard embed was not refused")
	}
	if a, _ := fa.set.Get("help"); len(a.Embed) != 2 {
		t.Fatal("a refused change was partly saved")
	}
}

func TestTheConsoleSaysWhichDocumentsCouldNotBeRead(t *testing.T) {
	srv, token, fa := chatbots(t)
	fa.set.Put(assistant.Assistant{Name: "help", Title: "Help"})
	fa.warnings = []string{"scan.pdf: no readable text: this PDF holds no text a program can read — it is probably scanned"}
	body := get(t, srv, "/assistants/help?q=returns", token).Body.String()
	if !strings.Contains(body, "probably scanned") {
		t.Fatal("a document that could not be read is not reported")
	}
}
