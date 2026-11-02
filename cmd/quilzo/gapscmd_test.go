// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// The loop: an unanswered question is kept only when the owner turned that
// on, with nobody's details in it; it stays open while nothing published
// answers it; and once a page that does is published, asking it again
// closes it, naming the page.
func TestAnUnansweredQuestionIsClosedByThePageThatAnswersIt(t *testing.T) {
	root := publishedShop(t)
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help"}); err != nil {
		t.Fatal(err)
	}
	keep := gapKeeper(root)
	keep("help", "Do you sell gift vouchers? email me at ana.lopez@gmail.com")
	if entries, _ := gapLedger(root).Read("help", time.Time{}); len(entries) != 0 {
		t.Fatal("a question was kept with chatbot.gaps off")
	}
	keepGaps(t, root)
	keep("help", "Do you sell gift vouchers? email me at ana.lopez@gmail.com")
	keep("help", "gift vouchers for christmas?")
	groups, err := gapGroups(root, "help", time.Now())
	if err != nil || len(groups) != 1 || groups[0].Count != 2 || !groups[0].Open() {
		t.Fatalf("%+v %v", groups, err)
	}
	if strings.Contains(groups[0].Questions[0]+groups[0].Questions[1], "ana.lopez") {
		t.Fatal("a visitor's address was kept")
	}

	ctx := context.Background()
	r, err := checkGaps(ctx, root, "help", "dana", time.Now())
	if err != nil || r.Asked == 0 || r.Closed != 0 {
		t.Fatalf("closed with no page that answers it: %+v %v", r, err)
	}

	// The page that answers it, published.
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := site.PagesAt(s, site.RefLive)
	if err != nil {
		t.Fatal(err)
	}
	pages["vouchers"] = map[string]any{"title": "Gift vouchers",
		"body": "We sell gift vouchers from £10, by post or by email, and they last two years."}
	if _, err := site.SaveDraft(s, pages, "vouchers", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
	r, err = checkGaps(ctx, root, "help", "dana", time.Now())
	if err != nil || r.Closed != 1 || len(r.Pages) != 1 || r.Pages[0] != "vouchers" {
		t.Fatalf("%+v %v", r, err)
	}
	groups, _ = gapGroups(root, "help", time.Now())
	if groups[0].Open() || groups[0].Closed.Page != "vouchers" || groups[0].Closed.How != "answered" {
		t.Fatalf("%+v", groups[0])
	}
	// The record says it was checked and how many; never a question.
	body, _ := os.ReadFile(auditPath(root))
	if !strings.Contains(string(body), "assistant.gaps.checked") || strings.Contains(string(body), "voucher") {
		t.Fatal("the audit log does not say it was checked, or says what was asked")
	}
	evs, _ := audit.Read(auditPath(root))
	if len(evs) == 0 {
		t.Fatal("nothing recorded")
	}
	// Somebody asks again: open again, saying so. (A question is kept to
	// the second, so the next one is.)
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(1100 * time.Millisecond)))
	keep("help", "do you sell gift vouchers online?")
	groups, _ = gapGroups(root, "help", time.Now().Add(time.Second))
	if !groups[0].Open() || groups[0].Since != 1 {
		t.Fatalf("asked again after it was answered: %+v", groups[0])
	}
}

// The command line lists what was not answered and closes a group a
// person says needs no page; reading them needs what reading the Inbox
// does.
func TestTheGapsAreListedAndClosedFromTheCommandLine(t *testing.T) {
	root := publishedShop(t)
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help"}); err != nil {
		t.Fatal(err)
	}
	keepGaps(t, root)
	gapKeeper(root)("help", "Are you open on Christmas Day?")
	if err := cmdAssistant(root, []string{"gaps", "help"}); err != nil {
		t.Fatal(err)
	}
	groups, _ := gapGroups(root, "help", time.Now())
	if err := cmdAssistant(root, []string{"gaps", "help", "--close", groups[0].Key}); err != nil {
		t.Fatal(err)
	}
	groups, _ = gapGroups(root, "help", time.Now())
	if groups[0].Open() || groups[0].Closed.How != "dismissed" {
		t.Fatalf("%+v", groups[0])
	}
	if err := cmdAssistant(root, []string{"gaps", "nobody"}); err == nil {
		t.Error("the gaps of a chatbot that is not there")
	}
}

// keepGaps turns chatbot.gaps on, with the reason a weaker setting asks
// for.
func keepGaps(t *testing.T, root string) {
	t.Helper()
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("chatbot.gaps", "true", "to find what the site does not say", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
}

// An agent reads the groups only when the owner keeps them and lets agents
// read them, and only as an author; what it reads is the open groups.
func TestAnAgentReadsTheGapsOnlyWhenLetTo(t *testing.T) {
	root := publishedShop(t)
	if err := cmdAssistant(root, []string{"add", "help", "--title", "Help"}); err != nil {
		t.Fatal(err)
	}
	keepGaps(t, root)
	gapKeeper(root)("help", "Do you engrave pens?")
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	srv := buildMCP(root, s, asAdmin("dana"), t.TempDir())
	if _, mcpErr := callTool(t, srv, "quilzo_read", "list_chatbot_gaps", map[string]any{"name": "help"}); mcpErr == nil {
		t.Fatal("an agent read visitors' questions without being let to")
	}
	cfg, _ := loadConfig(root)
	if err := cfg.Set("chatbot.gaps_agents", "true", "a gardener drafts the missing pages", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	out, mcpErr := callTool(t, srv, "quilzo_read", "list_chatbot_gaps", map[string]any{"name": "help"})
	if mcpErr != nil || !strings.Contains(out, "Do you engrave pens?") || !strings.Contains(out, `"asked":1`) {
		t.Fatalf("%s %v", out, mcpErr)
	}
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		if err := p.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
			return err
		}
		return p.Grant(auth.Binding{Principal: "rhea", Role: auth.RoleReader, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	reader := buildMCP(root, s, human("rhea"), t.TempDir())
	if _, mcpErr := callTool(t, reader, "quilzo_read", "list_chatbot_gaps", map[string]any{"name": "help"}); mcpErr == nil {
		t.Fatal("a reader read visitors' questions")
	}
}
