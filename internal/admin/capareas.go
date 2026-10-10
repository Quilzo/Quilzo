// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import "strings"

// What an agent may do, gathered by area.
//
// Sixty-odd capabilities in two alphabetical columns were a wall to scan for
// the one you wanted. Grouped by what they touch, each group says how many
// of its capabilities are chosen, and the groups holding none stay closed.
// Grouping is presentation only: every capability is still in the form, open
// or closed, and saving reads them exactly as before.

// capGroup is one area of capabilities on the agent form.
type capGroup struct {
	Name string
	Caps []capRow
	Held int
}

// capAreaOrder is the order the areas are shown in. Writes come first, as
// they did at the top of the single list.
var capAreaOrder = []string{
	"Writes", "Pages and content", "Checks and reports", "Security",
	"Agents, decisions and memory", "Other",
}

// capAreaOf names a read capability's area. A capability added later and not
// named here is listed under Other rather than guessed at.
var capAreaOf = map[string]string{
	"read_page": "Pages and content", "list_pages": "Pages and content",
	"search_pages": "Pages and content", "similar_pages": "Pages and content",
	"find": "Pages and content", "diff": "Pages and content",
	"content_id": "Pages and content", "list_media": "Pages and content",
	"list_menus": "Pages and content", "list_notes": "Pages and content",
	"list_records": "Pages and content", "list_terms": "Pages and content",
	"list_types": "Pages and content", "list_collections": "Pages and content",
	"run_listing": "Pages and content", "export_site": "Pages and content",

	"check_accessibility": "Checks and reports", "check_translations": "Checks and reports",
	"check_provenance": "Checks and reports", "list_checked": "Checks and reports",
	"verify_store": "Checks and reports", "site_report": "Checks and reports",
	"site_analytics": "Checks and reports", "experiment_report": "Checks and reports",
	"scan_content": "Checks and reports", "pipeline_status": "Checks and reports",

	"detection_stats": "Security", "incident_status": "Security",
	"list_findings": "Security", "read_finding": "Security",
	"propose_finding_decision": "Security", "shield_status": "Security",
	"vuln_plan": "Security", "policy_status": "Security",
	"control_implementation": "Security", "inventory": "Security",
	"estate_summary": "Security",

	"agent_activity": "Agents, decisions and memory", "ask_assistant": "Agents, decisions and memory",
	"declare_assistant": "Agents, decisions and memory", "list_assistants": "Agents, decisions and memory",
	"decide": "Agents, decisions and memory", "list_deciders": "Agents, decisions and memory",
	"eval_results": "Agents, decisions and memory", "recall": "Agents, decisions and memory",
	"remember": "Agents, decisions and memory",
}

// groupCaps gathers the rows by area, in capAreaOrder, leaving out empty
// areas. Within an area the rows keep the order they came in.
func groupCaps(caps []capRow) []capGroup {
	at := map[string]int{}
	out := make([]capGroup, 0, len(capAreaOrder))
	for i, name := range capAreaOrder {
		at[name] = i
		out = append(out, capGroup{Name: name})
	}
	for _, c := range caps {
		area := "Other"
		if c.Risk {
			area = "Writes"
		} else if a, ok := capAreaOf[strings.TrimSpace(c.Name)]; ok {
			area = a
		}
		g := &out[at[area]]
		g.Caps = append(g.Caps, c)
		if c.On {
			g.Held++
		}
	}
	kept := out[:0]
	for _, g := range out {
		if len(g.Caps) > 0 {
			kept = append(kept, g)
		}
	}
	return kept
}
