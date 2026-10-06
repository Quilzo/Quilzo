// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/auth"
)

// The agents screen: what a model in this store is allowed to do.
//
// Distinct from /security/agents, which reports what models have *been* doing.
// Watching and permitting are different questions, and the answer to the second
// is what makes the first worth reading — an activity log over agents whose
// permissions nobody declared is a list of things that happened.
//
// Declaring one is done in the studio (studio.go), from a form, a map drawn
// from the declaration, and the declaration's own text.

// Agents is what the host supplies so the admin can show declared agents.
//
// A function rather than a path, like the audit log: this process does not know
// where the manifests live, and the CLI is what owns that file.
type Agents struct {
	Load func() (map[string]agent.Manifest, error)
	// Identities is who answers for each agent, and until when; nil shows
	// nothing about it. SponsorActive says whether a sponsor can still act
	// here.
	Identities    func() (map[string]agent.Identity, error)
	SponsorActive func(sponsor string) bool
	// Known is every capability the machine interface offers, which is
	// what a declaration is validated against.
	Known func() []string
	// Save stores a declaration after validating it; Remove withdraws one.
	Save   func(m agent.Manifest, isNew bool, by string) error
	Remove func(name, by string) error
	// Run runs an agent once and keeps the run, returning its identifier.
	// A run that ended badly is still kept, and still returns one.
	Run func(name, goal string, model bool, by string) (string, error)
	// Runs lists kept runs, newest first, of one agent or all of them.
	Runs   func(name string) ([]agent.Record, error)
	RunGet func(id string) (agent.Record, error)
	// Answer decides the action a run is waiting on, Resume continues one
	// that was cut off, and Replay runs one again from after a step and
	// returns the new run.
	Answer func(id string, step int, approve bool, by string) error
	Resume func(id, by string) error
	Replay func(id string, step int, by string) (string, error)
}

// agentRow is one declared agent as the screen shows it.
type agentRow struct {
	Name         string
	Kind         string
	Purpose      string
	Autonomy     string
	Capabilities []string
	Writes       bool
	Memory       string
	Retain       string
	Tools        []agent.Tool
	Approval     bool
	// Sponsor is who answers for it, Ends when it stops, and Standing a
	// word for the screen: ok, ending, ended, orphaned or unsponsored.
	Sponsor  string
	Ends     time.Time
	Standing string
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// Reading which permissions were handed to models is an administrative
	// question, so it needs the permission that covers administration.
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}

	data := map[string]any{
		"Title": "Agents", "Principal": p, "Nav": "agents",
		"Templates": agent.Catalogue(),
	}

	if s.Agents == nil || s.Agents.Load == nil {
		data["Unavailable"] = "this server was started without access to the agent declarations"
		s.render(w, r, "agents.html", data)
		return
	}
	declared, err := s.Agents.Load()
	if err != nil {
		data["Unavailable"] = err.Error()
		s.render(w, r, "agents.html", data)
		return
	}

	var ids map[string]agent.Identity
	if s.Agents.Identities != nil {
		ids, _ = s.Agents.Identities()
	}
	now := time.Now()
	var rows []agentRow
	for name, m := range declared {
		row := agentRow{
			Name: name, Kind: string(m.Kind), Purpose: m.Purpose,
			Autonomy: string(m.Autonomy), Capabilities: m.Capabilities,
			Tools: m.Tools, Approval: m.HumanApproval,
		}
		for _, c := range m.Capabilities {
			if agent.IsWrite(c) {
				row.Writes = true
			}
		}
		if m.Memory.Any() {
			row.Memory = memoryTiers(m.Memory)
			row.Retain = m.Memory.Retain.String()
		}
		if s.Agents.Identities != nil {
			row.Standing = "unsponsored"
			if id, ok := ids[name]; ok && id.Sponsor != "" {
				row.Sponsor, row.Ends = id.Sponsor, id.Expires
				switch {
				case id.Expired(now):
					row.Standing = "ended"
				case s.Agents.SponsorActive != nil && !s.Agents.SponsorActive(id.Sponsor):
					row.Standing = "orphaned"
				case id.Expires.Before(now.Add(14 * 24 * time.Hour)):
					row.Standing = "ending"
				default:
					row.Standing = "ok"
				}
			}
		}
		rows = append(rows, row)
	}
	sortAgentRows(rows)
	data["Agents"] = rows
	s.render(w, r, "agents.html", data)
}

// memoryTiers names the tiers an agent keeps, for display.
func memoryTiers(m agent.Memory) string {
	out := ""
	add := func(s string) {
		if out != "" {
			out += " + "
		}
		out += s
	}
	if m.Episodic {
		add("episodic")
	}
	if m.Semantic {
		add("semantic")
	}
	if m.Procedural {
		add("procedural")
	}
	return out
}

// sortAgentRows puts the ones that can write first.
//
// Ordered by blast radius rather than alphabetically, because the question
// somebody opens this screen with is "what can act on its own", and an
// alphabetical list makes them read all of it to find out.
func sortAgentRows(rows []agentRow) {
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0; j-- {
			a, b := rows[j-1], rows[j]
			if rank(b) < rank(a) || (rank(b) == rank(a) && b.Name < a.Name) {
				rows[j-1], rows[j] = rows[j], rows[j-1]
				continue
			}
			break
		}
	}
}

func rank(r agentRow) int {
	switch r.Autonomy {
	case "publish":
		return 0
	case "draft":
		return 1
	}
	return 2
}
