// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/admin"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/gaps"
	"github.com/quilzo/quilzo/internal/listing"
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
		if err := noArguments(args[1:]); err != nil {
			return err
		}
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
	case "gaps":
		return assistantGaps(root, args[1:])
	case "embed":
		return assistantEmbed(root, args[1:])
	default:
		return fmt.Errorf("unknown assistant command %q; try list, add, "+
			"action, remove, ask, eval, gaps or embed", args[0])
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
		if a.Static {
			where += ", and on static copies"
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
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind, Model: caller.Model,
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
	collections := fs.String("collections", "", "comma-separated record collections it may answer from too, published records only")
	exclude := fs.String("exclude", "", "comma-separated page prefixes it may not read")
	refusal := fs.String("refusal", "", "what it says when it does not know")
	public := fs.Bool("public", false, "serve it on the site at /ask/NAME")
	static := fs.Bool("static", false, "answer on static copies too, in the visitor's browser, from published pages only (needs --public)")
	model := fs.Bool("model", false, "answer with the configured model (default: extractive only)")
	passages := fs.Int("passages", 0, "passages retrieved per question (default 5)")
	documents := fs.String("documents", "", "comma-separated media library ids it may read")
	embed := fs.String("embed", "", "comma-separated sites that may embed it, like https://shop.example")
	handoffOn := fs.Bool("handoff", false, "let a visitor ask for a person; the conversation goes to the inbox")
	voice := fs.Bool("voice", false, "let visitors speak and listen, recognised and read on their own device")
	translate := fs.Bool("translate", false, "answer in the visitor's language, translated on their own device")
	handoffDays := fs.Int("handoff-days", 0, "days a handed-over conversation is kept after it last moves (default 30, at most 90)")
	launcher := fs.Bool("launcher", false, "put it on the site's pages: a button in a corner that opens it beside the page (needs --public)")
	lStyle := fs.String("launcher-style", "", "bubble, pill or tab (default bubble)")
	lSide := fs.String("launcher-side", "", "right or left (default right)")
	lLabel := fs.String("launcher-label", "", "what a pill or tab says (default Ask)")
	lPanel := fs.String("panel", "", "float, over the corner, or side, docked beside the page (default float)")
	lPages := fs.String("launcher-pages", "", "comma-separated page prefixes it appears on (default: every page)")
	suggest := fs.String("suggest", "", "questions offered before the first, separated by |")
	nudge := fs.String("nudge", "", "a short line shown beside the button once a visit (default: none)")
	nudgeAfter := fs.Int("nudge-after", 0, "seconds on a page before the nudge (default 20)")
	nudgePages := fs.String("nudge-pages", "", "comma-separated page prefixes the nudge may show on")
	route := fs.String("route", "", "the gateway route, or the model a route serves, that answers first")
	routeOnly := fs.Bool("route-only", false, "keep it to that route alone: no other route answers for it")
	if err := parseFlags(fs, flags, &pos, 1); err != nil {
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
		Pages: splitList(*pages), Exclude: splitList(*exclude), Collections: splitList(*collections),
		Refusal: *refusal, Public: *public, Static: *static, UseModel: *model, Passages: *passages,
		Route: strings.TrimSpace(*route), RouteOnly: *routeOnly,
		Handoff: *handoffOn, HandoffDays: *handoffDays, Voice: *voice, Translate: *translate,
		Documents: splitList(*documents), Embed: splitList(*embed),
	}
	if *launcher {
		var qs []string
		for _, q := range strings.Split(*suggest, "|") {
			if q = strings.TrimSpace(q); q != "" {
				qs = append(qs, q)
			}
		}
		a.Launcher = &assistant.Launcher{Style: *lStyle, Side: *lSide, Label: *lLabel, Panel: *lPanel,
			Pages: splitList(*lPages), Suggestions: qs, Nudge: *nudge, NudgeAfter: *nudgeAfter,
			NudgePages: splitList(*nudgePages)}
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
		if a.Static {
			w.Human("  %sstatic copies carry it, with the passages it answers from%s\n", dim, reset)
		}
		if a.Launcher != nil {
			w.Human("  %sits button is on the site's pages%s\n", dim, reset)
		}
	} else {
		w.Human("  %snot public; try it with quilzo assistant ask %s \"...\"%s\n",
			dim, a.Name, reset)
	}
	return nil
}

func assistantAction(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("action", flag.ContinueOnError)
	kind := fs.String("kind", "link", "link, form or agent")
	target := fs.String("target", "", "the page for a link, the form for a form, the agent for an agent")
	description := fs.String("description", "", "what it does, for the model and the visitor")
	fields := fs.String("fields", "", "comma-separated fields it may pre-fill, or an agent asks for")
	writes := fs.Bool("writes", false, "an agent action may change something once the visitor confirms")
	identity := fs.Bool("identity", false, "an agent action only for a visitor the site vouches for")
	signer := fs.String("identity-secret", "", "the sealed credential the site signs visitors with (the assistant's)")
	remove := fs.Bool("remove", false, "remove this action instead")
	if err := parseFlags(fs, flags, &pos, 2); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo assistant action ASSISTANT ACTION --kind link|form|agent --target T --description D " +
			"[--fields a,b] [--writes] [--identity --identity-secret NAME]")
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
				Fields: splitList(*fields), Writes: *writes, Identity: *identity,
			})
		}
		if *signer != "" {
			a.IdentitySecret = *signer
		}
		a.Actions = kept
		return s.Put(a)
	})
}

func assistantRemove(root string, args []string) error {
	pos, err := positionals(args, 1)
	if err != nil {
		return err
	}
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
	return assistantIndexAs(root, a, nil)
}

// assistantIndexAs is assistantIndex for a caller who may be acting in an
// agent's run (agentplatform.go). The question the index embeds to rank its
// passages by meaning is a model call, and in a run it is charged to the run
// and its person, as the chatbot's answer is.
func assistantIndexAs(root string, a assistant.Assistant, c *Caller) (*assistant.Index, error) {
	idx, _, err := assistantKnowledge(root, a, c)
	return idx, err
}

// assistantKnowledge is assistantIndex with the reasons any document could
// not be used, for the owner's console. c is as in assistantIndexAs, and nil
// when the index is asked in no run.
func assistantKnowledge(root string, a assistant.Assistant, c *Caller) (*assistant.Index, []string, error) {
	s, err := store.Open(root)
	if err != nil {
		return nil, nil, err
	}
	pages, err := site.PagesAt(s, site.RefLive)
	if err != nil {
		return nil, nil, fmt.Errorf("nothing is published yet, so there is "+
			"nothing to answer from: %w", err)
	}
	passages := assistant.Chunk(site.WithBlocks(pages), a.Reads)
	var warnings []string
	recs, rerr := assistantRecords(s, a)
	if rerr != nil {
		warnings = append(warnings, rerr.Error())
	}
	passages = append(passages, recs...)
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
	passages, held := screenKnowledge(a, passages)
	warnings = append(warnings, held...)
	return withMeaning(root, a, assistant.NewIndex(passages), c), warnings, nil
}

// assistantRecords are the published records of the collections an
// assistant reads, as passages.
func assistantRecords(s *store.Store, a assistant.Assistant) ([]assistant.Passage, error) {
	if len(a.Collections) == 0 {
		return nil, nil
	}
	commit := s.GetRef(site.RefLive)
	if commit == "" {
		return nil, nil
	}
	c, err := s.GetCommit(commit)
	if err != nil {
		return nil, err
	}
	return recordPassages(s, c.Tree, a.Collections)
}

// recordPassages are a tree's records of some collections, as passages.
func recordPassages(s *store.Store, tree string, collections []string) ([]assistant.Passage, error) {
	var out []assistant.Passage
	var missing []string
	for _, name := range collections {
		recs, _, err := collection.List(s, tree, name, collection.Query{Limit: collection.MaxLimit})
		if err != nil {
			missing = append(missing, name)
			continue
		}
		texts := make([]assistant.RecordText, len(recs))
		for i, r := range recs {
			fields := r.Fields
			// The price a record shows a person is the price it charges,
			// as on its page (listing.WrittenPrice). The chatbot read the
			// copy kept by hand, which said £12.00 for a product the Buy
			// button sold at £13.00 once its price had changed.
			if _, shown := fields[listing.PriceDisplay]; shown {
				if text, ok := listing.WrittenPrice(fields); ok {
					fields = maps.Clone(fields)
					fields[listing.PriceDisplay] = text
				}
			}
			texts[i] = assistant.RecordText{ID: r.ID, Fields: fields}
		}
		out = append(out, assistant.ChunkRecords(name, texts)...)
	}
	if len(missing) > 0 {
		return out, fmt.Errorf("no published records in %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// screenKnowledge leaves out of what an assistant reads the passages that
// address an AI, unless it keeps them on purpose, and says which pages and
// why, for the owner. See internal/assistant/screen.go.
func screenKnowledge(a assistant.Assistant, passages []assistant.Passage) ([]assistant.Passage, []string) {
	if a.KeepInstructions {
		return passages, nil
	}
	kept, held := assistant.Hold(passages)
	byPage := assistant.HeldPages(held)
	names := make([]string, 0, len(byPage))
	for p := range byPage {
		names = append(names, p)
	}
	sort.Strings(names)
	var out []string
	for _, p := range names {
		out = append(out, fmt.Sprintf("%s: left out of what it reads, because it %s", p, strings.Join(byPage[p], ", and ")))
	}
	return kept, out
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
// from its pages instead. Each of payers is charged as well, each against
// its own budget: the person whose agent run asked the chatbot.
func assistantModelAt(root string, a assistant.Assistant, payers ...string) (assistant.Model, string) {
	if !a.UseModel {
		return nil, "extractive by declaration"
	}
	if root != "" {
		gw, _, err := modelGateway(root)
		if err != nil {
			return nil, "the model gateway could not be read: " + err.Error()
		}
		if gw != nil {
			switch {
			case a.Route != "" && a.RouteOnly:
				// Kept to one route: when none serves it, the chatbot
				// answers from its pages rather than through another.
				r := gw.RouteServing(a.Route)
				if r == "" {
					return nil, "kept to " + a.Route + ", which no route serves"
				}
				return gw.ForRoute(r, "chatbot:"+a.Name, payers...), ""
			case a.Route != "":
				return gw.ForModel(a.Route, "chatbot:"+a.Name, payers...), ""
			}
			return gw.For("chatbot:"+a.Name, payers...), ""
		}
	}
	if a.RouteOnly {
		return nil, "kept to " + a.Route + ", and no model gateway is declared"
	}
	m, err := directModel(root)
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
	pos, err := positionals(args, 2)
	if err != nil {
		return err
	}
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
	pos, err := positionals(args, 2)
	if err != nil {
		return err
	}
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
	// Named before it is measured, and measured through that route alone
	// (onlyThrough). Named after, the route a failed call had left resting
	// was passed over and the next one named instead.
	served := servedBy(m)
	if only := onlyThrough(root, served.Route, "chatbot:"+a.Name); only != nil {
		m = only
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	r, err := assistant.Evaluate(ctx, a, idx, m, cases)
	if err != nil {
		return err
	}
	// Recorded, so "when was this chatbot last measured, and on which
	// model" has an answer the posture checks can read. The counts, never
	// the questions. The model is the one served, by its provider's name
	// and the gateway's route: the record named none, so a chatbot measured
	// on one model counted as measured after it was moved to another.
	outcome := audit.Success
	if r.Hallucinated > 0 {
		outcome = audit.Failure
	}
	evalBy := resolveCaller(root, "")
	record(root, audit.Record{Action: "assistant.evaluated",
		Resource: "/ask/" + a.Name, Outcome: outcome, Principal: evalBy.Name,
		Kind: evalBy.Kind, Verified: evalBy.Verified,
		Detail: map[string]string{"assistant": a.Name,
			"cases":        fmt.Sprint(r.Cases),
			"hallucinated": fmt.Sprint(r.Hallucinated),
			"model":        served.Model, "route": served.Route}})
	// Kept whole for the Chatbots screen, which says when it was last
	// measured and on which model without reading the whole log.
	at := time.Now().UTC()
	if err := keepMeasurement(root, "chatbot", a.Name, evalBy.Name, served, at, r); err != nil {
		fmt.Fprintf(os.Stderr, "  the evaluation of %s could not be kept: %v\n", a.Name, err)
	}
	if w.JSON(r) {
		if r.Hallucinated > 0 {
			return fmt.Errorf("%d unanswerable question(s) answered", r.Hallucinated)
		}
		return nil
	}
	w.Human("%s%d case(s): %d answerable, %d not%s\n", bold, r.Cases,
		r.Answerable, r.Unanswerable, reset)
	w.Human("  %s\n", measurement{At: at, Model: served.Model, Route: served.Route})
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
			return assistantKnowledge(root, a, nil)
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
		Gaps: func(name string) ([]gaps.Group, bool, error) {
			groups, err := gapGroups(root, name, time.Now())
			return groups, mustConfig(root).Bool("chatbot.gaps"), err
		},
		Ratings: func(name string) (int, int) { return gapRatings(root, name, time.Now()) },
		Measured: func(name string) string {
			if m, ok := lastMeasurement(root, "chatbot", name); ok {
				return m.String()
			}
			return ""
		},
		CheckGaps: func(ctx context.Context, name, by string) (int, int, error) {
			r, err := checkGaps(ctx, root, name, by, time.Now())
			return r.Asked, r.Closed, err
		},
		CloseGap: func(name, key, by string) error {
			if err := gapLedger(root).Close(name, key, gaps.Closure{At: time.Now().UTC(), By: by, How: "dismissed"}); err != nil {
				return err
			}
			record(root, audit.Record{Action: "assistant.gaps.closed", Resource: "/ask/" + name,
				Outcome: audit.Success, Principal: by, Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{"assistant": name, "group": key}})
			return nil
		},
	}
}
