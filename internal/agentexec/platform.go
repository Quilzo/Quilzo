// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agentexec

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
)

// The rest of what the CMS offers, for an agent's own run.
//
// # The gap this closes
//
// A manifest may declare any operation the agent interface (MCP) offers:
// records, media, menus, newsletters, chatbots, research, the site crew.
// An outside agent calling them through MCP got them; the same agent run
// here got "permitted for this agent and not implemented here" for all but
// the nine this package performs itself. A gardener agent that should read
// a chatbot's gaps and draft the page could do the second half only.
//
// # Why through MCP, not a second implementation
//
// Every one of these already has one implementation, with its own checks:
// the read and write split, the role each needs, the handler's own
// refusals and records. A second copy for internal runs would be a second
// answer to "may this agent do this", and two answers drift. So a run
// calls them the way an outside agent does (Call, wired to the agent
// interface built for the run's caller), after the run's own gate.
//
// # What is and is not here
//
// Bridged is a list, not "everything MCP has": reads, and writes that make
// a draft or a proposal. Publishing has its own path in this package (it
// proposes), and an administrator's reports are not an agent's to run.
// A write waits for the agent's autonomy as write_page does, except a
// proposal, which is what proposing means.

// Bridged are the operations a run performs through the agent interface,
// and whether each writes.
var Bridged = map[string]bool{
	// Reads.
	"ask_assistant": false, "booking_times": false, "check_accessibility": false, "check_provenance": false,
	"check_translations": false, "content_id": false, "control_implementation": false,
	"experiment_report": false, "find": false, "list_assistants": false, "list_chatbot_gaps": false,
	"list_checked": false, "list_collections": false, "list_media": false, "list_menus": false,
	"list_notes": false, "list_records": false, "list_terms": false, "list_types": false,
	"newsletter_status": false, "pipeline_status": false, "research_ideas": false, "research_project": false,
	"research_projects": false, "research_search": false, "run_listing": false, "site_analytics": false,
	"site_blanks": false, "upcoming_events": false,
	// Writes that make a draft or a proposal.
	"write_record": true, "declare_assistant": true, "propose_feature": true, "propose_issue": true,
	"research_cite": true, "research_claim": true, "research_run": true, "research_write": true,
	"site_build": true, "site_fill": true,
}

// BridgedNames are the bridged operations, sorted.
func BridgedNames() []string {
	out := make([]string, 0, len(Bridged))
	for k := range Bridged {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Platform performs the bridged operations for a run.
type Platform struct {
	// Call performs one operation through the agent interface built for
	// the run's caller, as an outside agent would: its role, its handler's
	// own checks. writes says which of the interface's tools carries it.
	Call func(ctx context.Context, op string, writes bool, args map[string]any) (string, error)
}

// WithPlatform performs the bridged operations, and passes the rest on.
func WithPlatform(p Platform, s *agent.Session,
	next func(context.Context, agent.Action) (string, error)) func(context.Context, agent.Action) (string, error) {
	return func(ctx context.Context, a agent.Action) (string, error) {
		writes, bridged := Bridged[a.Op]
		if !bridged || a.Tool != "" || a.Delegate != "" {
			return next(ctx, a)
		}
		if err := s.Check(a.Op); err != nil {
			return "", err
		}
		m := s.Manifest()
		if writes && !strings.HasPrefix(a.Op, "propose_") && m.Autonomy == agent.AutonomyPropose {
			return "", fmt.Errorf("%s changes what is stored, and this agent proposes and does not write", a.Op)
		}
		if p.Call == nil {
			return "", fmt.Errorf("%q is permitted and this host does not reach the agent interface", a.Op)
		}
		out, err := p.Call(ctx, a.Op, writes, bounded(a.Input))
		if err != nil {
			return "", err
		}
		// What comes back is the store's words, some of them written by
		// people outside it (a record a form made, a note, a chatbot's
		// answer): the run is tainted by reading them.
		if !writes {
			s.ReadStore(a.Op)
		}
		return out, nil
	}
}

// bounded is an action's input as the agent interface takes it: the
// model's values, never a structure deeper than one level.
func bounded(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch t := v.(type) {
		case string, float64, bool, nil:
			out[k] = t
		case []any:
			if len(t) <= 64 {
				out[k] = slices.Clone(t)
			}
		case map[string]any:
			if len(t) <= 64 {
				inner := make(map[string]any, len(t))
				for ik, iv := range t {
					switch iv.(type) {
					case string, float64, bool, nil:
						inner[ik] = iv
					}
				}
				out[k] = inner
			}
		}
	}
	return out
}
