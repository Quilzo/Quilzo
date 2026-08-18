package admin

import (
	"net/http"

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
// Read-only here on purpose, for now. Declaring an agent is an administrative
// act with a blast radius, and the command line is where it is done with a
// diff in front of you; a screen that writes manifests is worth building once
// the shape has settled rather than while it is still moving.

// Agents is what the host supplies so the admin can show declared agents.
//
// A function rather than a path, like the audit log: this process does not know
// where the manifests live, and the CLI is what owns that file.
type Agents struct {
	Load func() (map[string]agent.Manifest, error)
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
