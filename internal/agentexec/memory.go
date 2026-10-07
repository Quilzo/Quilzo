// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentexec

import (
	"context"
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/memory"
)

// Memory performs remember and recall for a run. See internal/memory: what
// is kept is about the person who started the run, what was learnt after
// somebody else's words is held until a person confirms it, and what is
// recalled is private to that person.
type Memory struct {
	// Remember keeps an entry; the host knows whose run this is.
	Remember func(kind, text string, held bool, sources string) (memory.Entry, error)
	// Recall is what the run's person's memory holds for a query.
	Recall func(query string, kinds map[string]bool) ([]memory.Entry, error)
	// About names the person, for what the run now holds in private.
	About string
}

// MaxRecalled is how much one recall returns.
const MaxRecalled = 20

// WithMemory routes remember and recall to the run's memory and everything
// else to perform.
func WithMemory(m Memory, s *agent.Session,
	perform func(context.Context, agent.Action) (string, error)) func(context.Context, agent.Action) (string, error) {
	return func(ctx context.Context, a agent.Action) (string, error) {
		if a.Op != "remember" && a.Op != "recall" {
			return perform(ctx, a)
		}
		if err := s.Check(a.Op); err != nil {
			return "", err
		}
		if m.Remember == nil || m.Recall == nil {
			return "", fmt.Errorf("%s is permitted and this host keeps no memory", a.Op)
		}
		decl := s.Manifest().Memory
		kinds := map[string]bool{memory.Episodic: decl.Episodic, memory.Semantic: decl.Semantic,
			memory.Procedural: decl.Procedural}
		if a.Op == "recall" {
			query, _ := a.Input["query"].(string)
			found, err := m.Recall(query, kinds)
			if err != nil {
				return "", err
			}
			if len(found) == 0 {
				return "nothing is remembered that matches", nil
			}
			// What an agent remembers about somebody is theirs: the run now
			// holds it, and the exfiltration breaker knows.
			s.HoldsPrivate("what " + s.Manifest().Name + " remembers about " + m.About)
			var b strings.Builder
			for _, e := range found {
				fmt.Fprintf(&b, "- (%s, %s) %s\n", e.Kind, e.Created.Format("2 Jan 2006"), e.Text)
			}
			return b.String(), nil
		}
		kind, _ := a.Input["kind"].(string)
		if kind == "" {
			kind = memory.Semantic
		}
		if !kinds[kind] {
			return "", fmt.Errorf("%s does not keep %s memory", s.Manifest().Name, kind)
		}
		text, _ := a.Input["text"].(string)
		held := s.Tainted()
		sources := ""
		if held {
			sources = agent.Provenance(s.Sources(), s.Omitted())
		}
		e, err := m.Remember(kind, text, held, sources)
		if err != nil {
			return "", err
		}
		if e.Held {
			return fmt.Sprintf("remembered as %s, and held: it was learnt after reading content somebody "+
				"else may have written, so it is not recalled until a person confirms it", e.ID), nil
		}
		return "remembered as " + e.ID, nil
	}
}
