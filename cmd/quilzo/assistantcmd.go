// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/admin"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// Chatbots a site owner declares, from the command line.
//
// The same declarations the admin's Assistants screen edits and the public
// site serves at /ask/NAME. See internal/assistant for what an answer has to
// survive before a visitor sees it.

func assistantsPath(root string) string { return filepath.Join(root, "assistants.json") }

func cmdAssistant(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return assistantList(root)
	case "add":
		return assistantAdd(root, args[1:])
	case "action":
		return assistantAction(root, args[1:])
	case "remove":
		return assistantRemove(root, args[1:])
	case "ask":
		return assistantAsk(root, args[1:])
	case "eval":
		return assistantEval(root, args[1:])
	default:
		return fmt.Errorf("unknown assistant command %q; try list, add, "+
			"action, remove, ask or eval", args[0])
	}
}

func assistantList(root string) error {
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	set, err := assistant.Load(assistantsPath(root))
	if err != nil {
		return err
	}
	if w.JSON(set.Assistants) {
		return nil
	}
	if len(set.Assistants) == 0 {
		w.Human("no assistants; declare one with quilzo assistant add NAME --title T\n")
		return nil
	}
	for _, a := range set.Assistants {
		where := "admin only"
		if a.Public {
			where = "/ask/" + a.Name
		}
		w.Human("%s%s%s  %s  %s(%s, %d action(s))%s\n", bold, a.Name, reset,
			a.Title, dim, where, len(a.Actions), reset)
	}
	return nil
}

// saveAssistant changes the declarations under the audit log.
func saveAssistant(root string, caller *Caller, action, name string,
	change func(*assistant.Set) error) error {

	// Publish, not edit: a public assistant is a new way for anybody on the
	// internet to reach what this site says, and what it may offer to do.
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	path := assistantsPath(root)
	set, err := assistant.Load(path)
	if err != nil {
		return err
	}
	if err := change(set); err != nil {
		return err
	}
	if err := assistant.Save(path, set); err != nil {
		return err
	}
	record(root, audit.Record{
		Action: "assistant." + action, Resource: "/ask/" + name,
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified, Detail: map[string]string{"assistant": name},
	})
	return nil
}

func assistantAdd(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	title := fs.String("title", "", "what visitors see it called")
	greeting := fs.String("greeting", "", "the first thing it says")
	instructions := fs.String("instructions", "", "tone and focus, or @FILE")
	pages := fs.String("pages", "", "comma-separated page prefixes it may read (default: all published)")
	exclude := fs.String("exclude", "", "comma-separated page prefixes it may not read")
	refusal := fs.String("refusal", "", "what it says when it does not know")
	public := fs.Bool("public", false, "serve it on the site at /ask/NAME")
	model := fs.Bool("model", false, "answer with the configured model (default: extractive only)")
	passages := fs.Int("passages", 0, "passages retrieved per question (default 5)")
	documents := fs.String("documents", "", "comma-separated media library ids it may read")
	embed := fs.String("embed", "", "comma-separated sites that may embed it, like https://shop.example")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo assistant add NAME --title TITLE [...]")
	}
	instr := *instructions
	if strings.HasPrefix(instr, "@") {
		b, err := os.ReadFile(strings.TrimPrefix(instr, "@"))
		if err != nil {
			return err
		}
		instr = string(b)
	}
	a := assistant.Assistant{
		Name: pos[0], Title: *title, Greeting: *greeting, Instructions: instr,
		Pages: splitList(*pages), Exclude: splitList(*exclude),
		Refusal: *refusal, Public: *public, UseModel: *model, Passages: *passages,
		Documents: splitList(*documents), Embed: splitList(*embed),
	}
	caller := resolveCaller(root, flagToken)
	err := saveAssistant(root, caller, "declare", a.Name, func(s *assistant.Set) error {
		if old, ok := s.Get(a.Name); ok {
			a.Actions = old.Actions
		}
		return s.Put(a)
	})
	if err != nil {
		return err
	}
	if w.JSON(a) {
		return nil
	}
	w.Human("%s%s%s declared\n", bold, a.Name, reset)
	if a.Public {
		w.Human("  %sserved at /ask/%s once the site is running%s\n", dim, a.Name, reset)
	} else {
		w.Human("  %snot public; try it with quilzo assistant ask %s \"...\"%s\n",
			dim, a.Name, reset)
	}
	return nil
}

func assistantAction(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("action", flag.ContinueOnError)
	kind := fs.String("kind", "link", "link or form")
	target := fs.String("target", "", "the page for a link, the form for a form")
	description := fs.String("description", "", "what it does, for the model and the visitor")
	fields := fs.String("fields", "", "comma-separated form fields it may pre-fill")
	remove := fs.Bool("remove", false, "remove this action instead")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo assistant action ASSISTANT ACTION --kind link|form --target T --description D [--fields a,b]")
	}
	caller := resolveCaller(root, flagToken)
	return saveAssistant(root, caller, "action", pos[0], func(s *assistant.Set) error {
		a, ok := s.Get(pos[0])
		if !ok {
			return fmt.Errorf("no assistant called %s", pos[0])
		}
		kept := a.Actions[:0:0]
		for _, ac := range a.Actions {
			if ac.Name != pos[1] {
				kept = append(kept, ac)
			}
		}
		if !*remove {
			kept = append(kept, assistant.Action{
				Name: pos[1], Kind: assistant.ActionKind(*kind),
				Target: *target, Description: *description,
				Fields: splitList(*fields),
			})
		}
		a.Actions = kept
		return s.Put(a)
	})
}

func assistantRemove(root string, args []string) error {
	pos, _ := leadingArgs(args, 1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo assistant remove NAME")
	}
	caller := resolveCaller(root, flagToken)
	return saveAssistant(root, caller, "remove", pos[0], func(s *assistant.Set) error {
		if !s.Remove(pos[0]) {
			return fmt.Errorf("no assistant called %s", pos[0])
		}
		return nil
	})
}

// assistantIndex builds what an assistant may read: the published site,
// through its page filter, and the documents it was given.
//
// Published, never the draft. A visitor's assistant answering from a page
// nobody has approved would be publishing it by another route.
func assistantIndex(root string, a assistant.Assistant) (*assistant.Index, error) {
	idx, _, err := assistantKnowledge(root, a)
	return idx, err
}

// assistantKnowledge is assistantIndex with the reasons any document could
// not be used, for the owner's console.
func assistantKnowledge(root string, a assistant.Assistant) (*assistant.Index, []string, error) {
	s, err := store.Open(root)
	if err != nil {
		return nil, nil, err
	}
	pages, err := site.PagesAt(s, site.RefLive)
	if err != nil {
		return nil, nil, fmt.Errorf("nothing is published yet, so there is "+
			"nothing to answer from: %w", err)
	}
	passages := assistant.Chunk(pages, a.Reads)
	var warnings []string
	for _, id := range a.Documents {
		name, format, body, derr := assistantDocument(root, id)
		if derr != nil {
			warnings = append(warnings, id[:12]+": "+derr.Error())
			continue
		}
		ps, cerr := assistant.ChunkDocument(id, name, format, body)
		if cerr != nil {
			warnings = append(warnings, cerr.Error())
			continue
		}
		passages = append(passages, ps...)
	}
	return assistant.NewIndex(passages), warnings, nil
}

// assistantDocument reads one media library file for an assistant.
func assistantDocument(root, id string) (name, format string, body []byte, err error) {
	lib, err := openMedia(root)
	if err != nil {
		return "", "", nil, err
	}
	f, b, err := lib.Get(id)
	if err != nil {
		return "", "", nil, fmt.Errorf("not in the media library")
	}
	return f.Name, f.Format, b, nil
}

// assistantModel is the configured model when the assistant uses one, and
// nil — extractive — otherwise or when none is configured.
func assistantModel(a assistant.Assistant) (assistant.Model, string) {
	return assistantModelAt("", a)
}

// assistantModelAt routes a chatbot through the model gateway when one is
// declared, as the caller "chatbot:NAME", so its routes, fallbacks and budget
// apply. Over budget, the gateway refuses the call and the chatbot answers
// from its pages instead.
func assistantModelAt(root string, a assistant.Assistant) (assistant.Model, string) {
	if !a.UseModel {
		return nil, "extractive by declaration"
	}
	if root != "" {
		gw, _, err := modelGateway(root)
		if err != nil {
			return nil, "the model gateway could not be read: " + err.Error()
		}
		if gw != nil {
			return gw.For("chatbot:" + a.Name), ""
		}
	}
	m, err := assist.NewHTTPModel()
	if err != nil {
		return nil, "no model configured: " + err.Error()
	}
	return m, ""
}

func loadAssistant(root, name string) (assistant.Assistant, error) {
	set, err := assistant.Load(assistantsPath(root))
	if err != nil {
		return assistant.Assistant{}, err
	}
	a, ok := set.Get(name)
	if !ok {
		return a, fmt.Errorf("no assistant called %s", name)
	}
	return a, nil
}

func assistantAsk(root string, args []string) error {
	pos, _ := leadingArgs(args, 2)
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo assistant ask NAME \"question\"")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	a, err := loadAssistant(root, pos[0])
	if err != nil {
		return err
	}
	idx, err := assistantIndex(root, a)
	if err != nil {
		return err
	}
	m, why := assistantModelAt(root, a)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	ans, err := assistant.Respond(ctx, a, idx, m, pos[1])
	if err != nil {
		return err
	}
	if w.JSON(ans) {
		return nil
	}
	w.Human("%s\n", ans.Text)
	for i, h := range ans.Sources {
		w.Human("  %s[%d] %s (%s)%s\n", dim, i+1, h.Header(), h.Page, reset)
	}
	for _, d := range ans.Dropped {
		w.Human("  %sremoved: %q — %s%s\n", yellow, d.Text, d.Why, reset)
	}
	if ans.Proposed != nil {
		w.Human("  %soffers: %s (%s)%s\n", green, ans.Proposed.Action.Name,
			ans.Proposed.Action.Description, reset)
	}
	note := ans.Note
	if why != "" && note == "" {
		note = why
	}
	if note != "" {
		w.Human("  %s%s mode — %s%s\n", dim, ans.Mode, note, reset)
	}
	return nil
}

func assistantEval(root string, args []string) error {
	pos, _ := leadingArgs(args, 2)
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo assistant eval NAME CASES.jsonl\n" +
			"  one case per line: {\"question\": \"...\", \"page\": \"returns\"}\n" +
			"  a case with no page is a question the site does not answer")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	a, err := loadAssistant(root, pos[0])
	if err != nil {
		return err
	}
	var cases []assistant.Case
	if err := loadJSONL(pos[1], func(b []byte) error {
		var c assistant.Case
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		cases = append(cases, c)
		return nil
	}); err != nil {
		return err
	}
	if len(cases) == 0 {
		return fmt.Errorf("%s holds no cases", pos[1])
	}
	idx, err := assistantIndex(root, a)
	if err != nil {
		return err
	}
	m, _ := assistantModelAt(root, a)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	r, err := assistant.Evaluate(ctx, a, idx, m, cases)
	if err != nil {
		return err
	}
	if w.JSON(r) {
		if r.Hallucinated > 0 {
			return fmt.Errorf("%d unanswerable question(s) answered", r.Hallucinated)
		}
		return nil
	}
	w.Human("%s%d case(s): %d answerable, %d not%s\n", bold, r.Cases,
		r.Answerable, r.Unanswerable, reset)
	w.Human("  right page first      %d/%d\n", r.HitAt1, r.Answerable)
	w.Human("  right page retrieved  %d/%d  (MRR %.2f)\n", r.HitAtK, r.Answerable, r.MRR)
	w.Human("  answered              %d/%d\n", r.Answered, r.Answerable)
	w.Human("  refused correctly     %d/%d\n", r.Refused, r.Unanswerable)
	w.Human("  sentences removed     %d\n", r.Dropped)
	for _, f := range r.Failures {
		w.Human("  %s%s%s\n", yellow, f, reset)
	}
	// The one number that fails the run. An assistant that answers a
	// question the site does not answer is saying something the site never
	// said, and that is the result a CI job should stop on.
	if r.Hallucinated > 0 {
		return fmt.Errorf("%d unanswerable question(s) were answered", r.Hallucinated)
	}
	return nil
}

// assistantsCapability is the declarations for the admin's Chatbots screen,
// saved the way the command line saves them.
func assistantsCapability(root string) *admin.Assistants {
	return &admin.Assistants{
		Load: func() (*assistant.Set, error) { return assistant.Load(assistantsPath(root)) },
		Save: func(set *assistant.Set, by, change, name string) error {
			if err := assistant.Save(assistantsPath(root), set); err != nil {
				return err
			}
			record(root, audit.Record{
				Action: "assistant." + change, Resource: "/ask/" + name,
				Outcome: audit.Success, Principal: by, Kind: audit.KindHuman,
				Verified: true, Detail: map[string]string{"assistant": name},
			})
			return nil
		},
		Index: func(a assistant.Assistant) (*assistant.Index, []string, error) {
			return assistantKnowledge(root, a)
		},
		Documents: func() ([]admin.DocumentChoice, error) {
			lib, err := openMedia(root)
			if err != nil {
				return nil, err
			}
			files, err := lib.List()
			if err != nil {
				return nil, err
			}
			var out []admin.DocumentChoice
			for _, f := range files {
				switch f.Format {
				case "pdf", "md", "txt", "csv":
					out = append(out, admin.DocumentChoice{ID: f.ID, Name: f.Name,
						Format: f.Format})
				}
			}
			return out, nil
		},
		Model: func(a assistant.Assistant) (assistant.Model, string) {
			return assistantModelAt(root, a)
		},
		Forms: func() ([]string, error) {
			set, err := loadForms(root)
			if err != nil {
				return nil, err
			}
			return set.Names(), nil
		},
	}
}
