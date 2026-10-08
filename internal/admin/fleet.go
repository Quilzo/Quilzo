// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/fleet"
)

// Fleet is every agent the organisation runs or uses, who called what, and
// the AI use nobody registered. See internal/fleet.
type Fleet struct {
	// View is the fleet with the last days of calls.
	View func(days int) (fleet.View, error)
	// Register adds another vendor's agent by its card; Remove takes one
	// away; Check reads every card again.
	Register func(cardURL, name, by string) error
	Remove   func(name, by string) error
	Check    func() ([]string, error)
}

// fleetGroup is one kind of thing, for a table.
type fleetGroup struct {
	Kind, Title string
	Nodes       []fleet.Node
}

// fleetMap is who called what, drawn in four columns: people, then apps,
// other vendors' agents and features, then Quilzo's agents, then what they
// reach.
type fleetMap struct {
	W, H  int
	Heads []fleetHead
	Boxes []fleetBox
	Lines []fleetLine
	Says  string
}

type fleetHead struct {
	X     int
	Label string
}

type fleetBox struct {
	X, Y, W, TX, TY int
	Label, Class    string
}

type fleetLine struct {
	X1, Y1, X2, Y2 int
	Width          float64
	Title          string
}

func fleetColumn(kind string) int {
	switch kind {
	case fleet.KindPerson:
		return 0
	case fleet.KindApp, fleet.KindExternal, "chatbot", "feature":
		return 1
	case fleet.KindAgent:
		return 2
	}
	return 3
}

// MaxMapRows bounds a column of the map; the tables hold the rest.
const MaxMapRows = 24

func drawFleet(v fleet.View) fleetMap {
	const colW, boxW, rowH, top = 230, 190, 34, 40
	byID := map[string]fleet.Node{}
	for _, n := range v.Nodes {
		byID[n.ID] = n
	}
	// Only what took part in a call is drawn; the tables list everything.
	inEdge := map[string]bool{}
	for _, e := range v.Edges {
		inEdge[e.From], inEdge[e.To] = true, true
	}
	cols := make([][]fleet.Node, 4)
	for _, n := range v.Nodes {
		if inEdge[n.ID] {
			c := fleetColumn(n.Kind)
			cols[c] = append(cols[c], n)
		}
	}
	m := fleetMap{W: 4 * colW}
	heads := []string{"People", "Apps and other agents", "Quilzo's agents", "What they reach"}
	pos := map[string][2]int{}
	rows := 0
	for c, nodes := range cols {
		sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
		if len(nodes) > MaxMapRows {
			nodes = nodes[:MaxMapRows]
		}
		m.Heads = append(m.Heads, fleetHead{X: c*colW + 8, Label: heads[c]})
		for i, n := range nodes {
			x, y := c*colW+8, top+i*rowH
			label := n.Name
			if r := []rune(label); len(r) > 26 {
				label = string(r[:25]) + "…"
			}
			m.Boxes = append(m.Boxes, fleetBox{X: x, Y: y, W: boxW, TX: x + 10, TY: y + 18, Label: label,
				Class: strings.ReplaceAll(n.Kind, " ", "-")})
			pos[n.ID] = [2]int{x, y + 13}
		}
		if len(nodes) > rows {
			rows = len(nodes)
		}
	}
	most := 1
	for _, e := range v.Edges {
		if e.Calls > most {
			most = e.Calls
		}
	}
	for _, e := range v.Edges {
		a, okA := pos[e.From]
		b, okB := pos[e.To]
		if !okA || !okB {
			continue
		}
		x1, x2 := a[0]+boxW, b[0]
		if b[0] < a[0] {
			x1, x2 = a[0], b[0]+boxW
		}
		m.Lines = append(m.Lines, fleetLine{X1: x1, Y1: a[1], X2: x2, Y2: b[1],
			Width: 1 + 3*float64(e.Calls)/float64(most),
			Title: fmt.Sprintf("%s → %s: %d calls", byID[e.From].Name, byID[e.To].Name, e.Calls)})
	}
	m.H = top + rows*rowH + 8
	m.Says = fmt.Sprintf("Who called what in the last %d days: %d connections between %d things.", v.Days, len(m.Lines), len(m.Boxes))
	return m
}

func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// A map of every agent and what it reaches is a map of the blast
	// radius: an administrator's, as Integrations is.
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	data := map[string]any{"Nav": "fleet", "Title": "Fleet", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if s.Fleet == nil || s.Fleet.View == nil {
		data["Off"] = true
		s.render(w, r, "fleet.html", data)
		return
	}
	days := 30
	if r.URL.Query().Get("days") == "7" {
		days = 7
	}
	v, err := s.Fleet.View(days)
	if err != nil {
		data["Error"] = err.Error()
	}
	groups := []fleetGroup{
		{Kind: fleet.KindAgent, Title: "Quilzo's agents"},
		{Kind: fleet.KindExternal, Title: "Other vendors' agents"},
		{Kind: fleet.KindApp, Title: "Connected apps"},
		{Kind: fleet.KindTool, Title: "Tool servers"},
		{Kind: fleet.KindRoute, Title: "Model routes"},
	}
	for i := range groups {
		for _, n := range v.Nodes {
			if n.Kind == groups[i].Kind {
				groups[i].Nodes = append(groups[i].Nodes, n)
			}
		}
	}
	data["Groups"], data["Shadow"], data["Days"], data["Map"] = groups, v.Shadow, v.Days, drawFleet(v)
	data["CanRegister"] = s.Fleet.Register != nil
	s.render(w, r, "fleet.html", data)
}

// handleFleetAct registers, removes or checks other vendors' agents.
func (s *Server) handleFleetAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	back := func(k, v string) { http.Redirect(w, r, "/fleet?"+k+"="+url.QueryEscape(v), http.StatusSeeOther) }
	if s.Fleet == nil {
		back("e", "the fleet is not wired up in this build")
		return
	}
	switch r.FormValue("op") {
	case "register":
		if s.Fleet.Register == nil {
			back("e", "registering is not wired up in this build")
			return
		}
		if err := s.Fleet.Register(strings.TrimSpace(r.FormValue("card")), strings.TrimSpace(r.FormValue("name")), p.Name); err != nil {
			back("e", err.Error())
			return
		}
		back("m", "registered; you answer for it here")
	case "remove":
		if err := s.Fleet.Remove(r.FormValue("name"), p.Name); err != nil {
			back("e", err.Error())
			return
		}
		back("m", "removed "+r.FormValue("name"))
	case "check":
		changed, err := s.Fleet.Check()
		if err != nil {
			back("e", err.Error())
			return
		}
		if len(changed) == 0 {
			back("m", "every card says what it said when it was registered")
			return
		}
		back("e", "these cards have changed since they were registered: "+strings.Join(changed, ", "))
	default:
		back("e", "choose what to do")
	}
}
