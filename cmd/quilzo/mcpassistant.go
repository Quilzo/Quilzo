// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mcp"
)

// Chatbots, for an agent building a site.
//
// An agent can do most of the work of making a chatbot: declare it, write its
// tone, choose what it reads, and ask it the questions visitors will ask
// until the answers are right. What it cannot do is the part that reaches
// the public. A declaration made here is never public, an assistant that is
// already public cannot be changed from here, and actions are not on this
// surface at all — what a public chatbot may offer to do is decided by a
// person on the Chatbots screen. Least agency: the agent gets the building,
// not the launching.

func registerAssistantOps(srv *mcp.Server, root string, caller *Caller) {
	// What a chatbot could not answer, grouped and masked, for an agent
	// that drafts the pages that would: only when the owner keeps them and
	// lets agents read them, and for an author, as the Inbox is.
	srv.Register(mcp.Operation{
		Name: "list_chatbot_gaps", NeedsRole: "author",
		Summary: "what visitors asked a chatbot that it could not answer, grouped by subject, to write the pages that answer them",
		Detail: "Visitors' questions with their details masked, most asked first, each group with a key. " +
			"Write the page that answers a group as a draft for a person to review; once the site is " +
			"published the chatbot is asked again and a group it answers is closed. Only when the owner " +
			"keeps unanswered questions (chatbot.gaps) and lets agents read them (chatbot.gaps_agents).",
		Args:     map[string]string{"name": "the chatbot"},
		Keywords: []string{"chatbot", "gaps", "unanswered", "questions", "missing", "content"},
	}, func(a map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		cfg := mustConfig(root)
		if !cfg.Bool("chatbot.gaps") || !cfg.Bool("chatbot.gaps_agents") {
			return nil, &mcp.Refusal{Reason: "unanswered questions are visitors' words, and the owner has not " +
				"let agents read them (chatbot.gaps and chatbot.gaps_agents)"}
		}
		name, _ := a["name"].(string)
		if _, err := loadAssistant(root, name); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		groups, err := gapGroups(root, name, time.Now())
		if err != nil {
			return nil, err
		}
		type row struct {
			Key       string   `json:"key"`
			Asked     int      `json:"asked"`
			Questions []string `json:"questions"`
			Last      string   `json:"last"`
		}
		var out []row
		for _, g := range groups {
			if g.Open() {
				out = append(out, row{Key: g.Key, Asked: g.Count, Questions: g.Questions, Last: g.Last.Format("2006-01-02")})
			}
		}
		record(root, caller.auditRecord("assistant.gaps.read", "/ask/"+name, audit.Success,
			map[string]string{"assistant": name, "groups": fmt.Sprint(len(out)), "via": "mcp"}))
		b, err := json.Marshal(out)
		return string(b), err
	})

	srv.Register(mcp.Operation{
		Name: "list_assistants", NeedsRole: "reader",
		Summary:  "the site's chatbots, whether each is public, and what it may offer",
		Keywords: []string{"chatbot", "assistant", "ask", "rag", "bot"},
	}, func(map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActView, "/"); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		set, err := assistant.Load(assistantsPath(root))
		if err != nil {
			return nil, err
		}
		b, err := json.Marshal(set.Assistants)
		return string(b), err
	})

	srv.Register(mcp.Operation{
		Name: "ask_assistant", NeedsRole: "reader",
		Summary: "ask a chatbot a question and see its answer, sources and removals",
		Detail: "Works on private chatbots too, so you can test one before a " +
			"person makes it public. The answer is from published pages only; " +
			"removed sentences are ones the pages did not support.",
		Args: map[string]string{
			"name":     "the chatbot",
			"question": "what a visitor would ask",
		},
		Keywords: []string{"chatbot", "ask", "test", "rag", "answer"},
	}, func(a map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActView, "/"); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		name, _ := a["name"].(string)
		q, _ := a["question"].(string)
		bot, err := loadAssistant(root, name)
		if err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		idx, err := assistantIndex(root, bot)
		if err != nil {
			return nil, err
		}
		// Inside an agent's run, the run's spending and its person's.
		m, _ := assistantModelAt(root, bot, caller.runPayers()...)
		m = caller.chargedToRun(m)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		ans, err := assistant.Respond(ctx, bot, idx, m, q)
		if err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		type src struct {
			N            int
			Page, Header string
		}
		out := map[string]any{"answer": ans.Text, "refused": ans.Refused,
			"mode": ans.Mode, "note": ans.Note, "removed": ans.Dropped}
		var srcs []src
		for i, h := range ans.Sources {
			srcs = append(srcs, src{i + 1, h.Page, h.Header()})
		}
		out["sources"] = srcs
		b, err := json.Marshal(out)
		return string(b), err
	})

	srv.Register(mcp.Operation{
		Name: "declare_assistant", NeedsRole: "author", Writes: true,
		Summary: "create or change a private chatbot: its title, tone and what it reads",
		Detail: "Never public from here. A person makes a chatbot public, " +
			"decides whether static copies of the site carry it, and decides " +
			"what it may offer to do, on the Chatbots screen. A chatbot that " +
			"is already public cannot be changed from here.",
		Args: map[string]string{
			"name": "lower-case, digits and hyphens", "title": "what visitors see",
			"greeting": "optional", "instructions": "optional tone and focus",
			"pages":   "optional comma-separated prefixes it may read",
			"exclude": "optional comma-separated prefixes it may not",
			"refusal": "optional: what it says when it does not know",
		},
		Keywords: []string{"chatbot", "create", "assistant", "build", "rag"},
	}, func(a map[string]any) (any, error) {
		if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		str := func(k string) string { v, _ := a[k].(string); return strings.TrimSpace(v) }
		name := str("name")
		path := assistantsPath(root)
		set, err := assistant.Load(path)
		if err != nil {
			return nil, err
		}
		bot, existed := set.Get(name)
		if existed && bot.Public {
			return nil, &mcp.Refusal{Reason: name + " is public; a person " +
				"changes a public chatbot on the Chatbots screen"}
		}
		bot.Name, bot.Title = name, str("title")
		bot.Greeting, bot.Instructions = str("greeting"), str("instructions")
		bot.Pages, bot.Exclude = splitList(str("pages")), splitList(str("exclude"))
		bot.Refusal = str("refusal")
		bot.Public = false
		if err := set.Put(bot); err != nil {
			return nil, &mcp.Refusal{Reason: err.Error()}
		}
		if err := assistant.Save(path, set); err != nil {
			return nil, err
		}
		if err := recordE(root, audit.Record{
			Action: "assistant.declare", Resource: "/ask/" + name,
			Outcome: audit.Success, Principal: "mcp-client", Kind: audit.KindAI,
			Model: "mcp-client", Detail: map[string]string{
				"assistant": name, "on_behalf_of": caller.Name},
		}); err != nil {
			return nil, err
		}
		return fmt.Sprintf("declared %s, private. Try it with ask_assistant; "+
			"a person makes it public at /assistants/%s", name, name), nil
	})
}
