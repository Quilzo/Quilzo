// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/handoff"
)

// The inbox: conversations a site's chatbots handed to a person.
//
// The public site writes them, because that is where a visitor is; the admin
// and this command read and answer them. Both processes append to the same
// files, which internal/handoff arranges so that neither needs a lock.

func handoffDir(root string) string { return filepath.Join(root, "handoff") }

func handoffStore(root string) *handoff.Store {
	return &handoff.Store{Dir: handoffDir(root)}
}

// handoffKeep is how long each assistant keeps its conversations.
func handoffKeep(root string) func(string) time.Duration {
	set, err := assistant.Load(assistantsPath(root))
	return func(name string) time.Duration {
		if err != nil || set == nil {
			return 0
		}
		a, ok := set.Get(name)
		if !ok {
			return 0
		}
		return time.Duration(a.Keep()) * 24 * time.Hour
	}
}

// recordHandoff writes that something happened in a conversation, and never
// what was said. The visitor is recorded by where they came from, as every
// other visitor action is.
func recordHandoff(root, action, name, id, who string, kind audit.Kind) {
	record(root, audit.Record{Action: action, Resource: "/ask/" + name,
		Outcome: audit.Success, Principal: who, Kind: kind,
		Detail: map[string]string{"conversation": id}})
}

// suggestReply asks an assistant the visitor's last message, from the same
// knowledge it answers visitors with, and returns its answer as a draft.
func suggestReply(root, name, question string) (string, []string, error) {
	if strings.TrimSpace(question) == "" {
		return "", nil, fmt.Errorf("the visitor has not asked anything yet")
	}
	set, err := assistant.Load(assistantsPath(root))
	if err != nil {
		return "", nil, err
	}
	a, ok := set.Get(name)
	if !ok {
		return "", nil, fmt.Errorf("the chatbot %s no longer exists", name)
	}
	idx, _, err := assistantKnowledge(root, a)
	if err != nil {
		return "", nil, err
	}
	var m assistant.Model
	if a.UseModel {
		m, _ = assistantModelAt(root, a)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	ans, err := assistant.RespondTo(ctx, a, idx, m, question, "")
	if err != nil {
		return "", nil, err
	}
	if ans.Refused {
		return "", nil, fmt.Errorf("the site does not answer that; it needs " +
			"a person, which is why they asked for one")
	}
	// The sentences without their [n] markers. In the chatbot those point
	// at a list of sources under the answer; in a reply the visitor reads
	// they point at nothing. The sources are named to the person instead,
	// and only the ones the answer actually cites.
	var text []string
	var sources []string
	seen := map[string]bool{}
	for _, sen := range ans.Kept {
		text = append(text, sen.Text)
		for _, n := range sen.Cites {
			if n < 1 || n > len(ans.Sources) {
				continue
			}
			h := ans.Sources[n-1]
			title := h.Header()
			if title == "" {
				title = h.Page
			}
			if title != "" && !seen[title] {
				seen[title] = true
				sources = append(sources, title)
			}
		}
	}
	return strings.Join(text, " "), sources, nil
}

// inboxHooks is the admin's inbox, over the store.
func inboxHooks(root string) *admin.Inbox {
	st := handoffStore(root)
	return &admin.Inbox{
		List: st.List,
		Get:  st.Get,
		Reply: func(name, id, by, text string) error {
			_, err := st.Say(name, id, handoff.Person, by, text, time.Now())
			return err
		},
		Close: func(name, id, by string) error {
			return st.Close(name, id, by, time.Now())
		},
		Suggest: func(name, question string) (string, []string, error) {
			return suggestReply(root, name, question)
		},
		Titles: func() map[string]string {
			out := map[string]string{}
			if set, err := assistant.Load(assistantsPath(root)); err == nil && set != nil {
				for _, a := range set.Assistants {
					out[a.Name] = a.Title
				}
			}
			return out
		},
	}
}

func inboxUsage() error {
	return fmt.Errorf(`usage: quilzo inbox <command>

  list                        conversations, the ones waiting for a reply first
  show ASSISTANT/ID           one conversation
  reply ASSISTANT/ID "text"   answer it, as yourself
  close ASSISTANT/ID          end it`)
}

func splitConversation(arg string) (string, string, error) {
	name, id, ok := strings.Cut(arg, "/")
	if !ok || !handoff.ValidID(id) {
		return "", "", fmt.Errorf("%q is not a conversation; they are named "+
			"ASSISTANT/ID, as `quilzo inbox list` shows them", arg)
	}
	return name, id, nil
}

func cmdInbox(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	st := handoffStore(root)
	switch args[0] {
	case "list":
		all, err := st.List()
		if err != nil {
			return err
		}
		if len(all) == 0 {
			fmt.Println("  no conversations")
			return nil
		}
		for _, c := range all {
			state := "answered"
			switch {
			case c.Waiting():
				state = "waiting"
			case c.Closed:
				state = "ended"
			}
			last := ""
			if n := len(c.Messages); n > 0 {
				last = c.Messages[n-1].Text
			}
			fmt.Printf("  %s/%s  %-8s %s\n", c.Assistant, c.ID, state,
				onOneLine(truncate(last, 70)))
		}
		return nil
	case "show":
		if len(args) != 2 {
			return inboxUsage()
		}
		name, id, err := splitConversation(args[1])
		if err != nil {
			return err
		}
		c, err := st.Get(name, id)
		if err != nil {
			return err
		}
		fmt.Printf("%s%s/%s%s  opened %s\n", bold, name, id, reset,
			c.Opened.Format("2 Jan 2006 15:04 UTC"))
		if c.Question != "" {
			fmt.Printf("  %sthey had asked: %s%s\n", dim, onOneLine(c.Question), reset)
		}
		for _, m := range c.Messages {
			who := "visitor"
			if m.From == handoff.Person {
				who = m.By
			}
			fmt.Printf("  %s%s, %s%s\n    %s\n", dim, onOneLine(who),
				m.At.Format("2 Jan 15:04"), reset, forTerminal(m.Text))
		}
		if c.Closed {
			fmt.Printf("  %sended%s\n", dim, reset)
		}
		return nil
	case "reply", "close":
		fs := flag.NewFlagSet("inbox "+args[0], flag.ContinueOnError)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		rest := fs.Args()
		if (args[0] == "reply" && len(rest) != 2) || (args[0] == "close" && len(rest) != 1) {
			return inboxUsage()
		}
		text := ""
		if args[0] == "reply" {
			text = rest[1]
		}
		if err := inboxAnswer(root, args[0], rest[0], text,
			resolveCaller(root, "")); err != nil {
			return err
		}
		if args[0] == "reply" {
			fmt.Println("  sent")
		} else {
			fmt.Println("  ended")
		}
		return nil
	}
	return inboxUsage()
}

// inboxAnswer replies to or ends a conversation, as caller, and records it.
func inboxAnswer(root, act, ref, text string, caller *Caller) error {
	name, id, err := splitConversation(ref)
	if err != nil {
		return err
	}
	if caller.Kind == audit.KindAI {
		return fmt.Errorf("a person answers a visitor who asked for one. A " +
			"model's draft is a suggestion on the inbox screen, for a person " +
			"to send")
	}
	st := handoffStore(root)
	switch act {
	case "reply":
		_, err = st.Say(name, id, handoff.Person, caller.Name, text, time.Now())
	case "close":
		err = st.Close(name, id, caller.Name, time.Now())
	default:
		return inboxUsage()
	}
	if err != nil {
		return err
	}
	return recordE(root, caller.auditRecord("handoff."+act, "/ask/"+name,
		audit.Success, map[string]string{"conversation": id}))
}
