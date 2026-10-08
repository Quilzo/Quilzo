// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package aievidence

import "fmt"

// ISO/IEC 42001:2023's Annex A: the reference controls of an AI management
// system, as a statement of applicability. Every control is listed as
// applicable, because an organisation running agents has a reason for each;
// whether it is shown here, partly, or the organisation's own to show is
// what the evidence says.

// Annex is the statement of applicability.
func Annex(in Inputs) []Item {
	f := gather(in)
	c := f.c
	pinned, unpinned := 0, 0
	for _, t := range in.Tools {
		for _, u := range t.Uses {
			if t.Pins[u] != "" {
				pinned++
			} else {
				unpinned++
			}
		}
	}
	shadow := 0
	for _, n := range in.State.AI.ShadowAI {
		shadow += n
	}
	y := func(ref, title, yours string, ev ...string) Item {
		return Item{Ref: ref, Title: title, Status: Yours, Yours: yours, Evidence: ev}
	}
	s := func(ref, title string, ev ...string) Item {
		return Item{Ref: ref, Title: title, Status: Shown, Evidence: ev}
	}
	p := func(ref, title, yours string, ev ...string) Item {
		return Item{Ref: ref, Title: title, Status: Partly, Yours: yours, Evidence: ev}
	}
	evals := fmt.Sprintf("%d of %d agents evaluated against planted instructions, %d cases followed one", f.evaluated, f.agents, f.steer)
	items := []Item{
		y("A.2.2", "AI policy", "the policy",
			"the organisation's policy is held as NIST parameters, changed by two administrators and enforced as floors"),
		y("A.2.3", "Alignment with other organisational policies", "the alignment"),
		y("A.2.4", "Review of the AI policy", "the review"),
		s("A.3.2", "AI roles and responsibilities",
			fmt.Sprintf("%d of %d agents are answered for by a person with standing; roles and bindings say who may run, approve and publish", f.sponsored, f.agents),
			"actions outside the system need a second person"),
		p("A.3.3", "Reporting of concerns", "the channel people use",
			"the security contact is published (security.txt), and cases hold what is reported and done"),
		s("A.4.2", "Resource documentation", "the AI bill of materials lists the models, agents, data and services, and who uses which"),
		s("A.4.3", "Data resources", fmt.Sprintf("%d chatbots' knowledge and every agent's memory are in the AI bill of materials, with retention", len(in.Chatbots))),
		s("A.4.4", "Tooling resources", fmt.Sprintf("%d tools agreed and pinned, %d agreed and not pinned; a tool redefined by its server is refused until a person looks", pinned, unpinned)),
		s("A.4.5", "System and computing resources", fmt.Sprintf("%d model routes; agents' own programs run confined in a box", len(in.Routes))),
		y("A.4.6", "Human resources", "the people and their competence"),
		y("A.5.2", "AI system impact assessment process", "the process"),
		y("A.5.3", "Documentation of AI system impact assessments", "the assessments"),
		p("A.5.4", "Assessing AI system impact on individuals or groups of individuals", "the assessment",
			fmt.Sprintf("personal data is masked before prompts reach a model outside the organisation (%d times in the period)", c.Masked),
			"people see, rewrite and have forgotten what agents remember about them"),
		y("A.5.5", "Assessing societal impacts of AI systems", "the assessment"),
		y("A.6.1.2", "Objectives for responsible development of AI system", "the objectives"),
		p("A.6.1.3", "Processes for responsible AI system design and development", "the process",
			"a declaration is validated before it is saved, and a drafted one is shown what it could do first"),
		s("A.6.2.2", "AI system requirements and specification", "each agent declares its purpose, capabilities, reach, budget and autonomy, and is held to them"),
		s("A.6.2.3", "Documentation of AI system design and development", "the declarations, the public agent card and the AI bill of materials"),
		s("A.6.2.4", "AI system verification and validation", evals),
		s("A.6.2.5", "AI system deployment", "autonomy is earned from evaluations and lost on a hijack; publishing waits for a person"),
		s("A.6.2.6", "AI system operation and monitoring",
			fmt.Sprintf("the watchdog and the shield watch every run: %d pauses and %d flags in the period", c.Paused, c.Flagged),
			"the Fleet screen shows who called what"),
		s("A.6.2.7", "AI system technical documentation", "declarations, agent card, AI bill of materials and receipts"),
		s("A.6.2.8", "AI system recording of event logs",
			fmt.Sprintf("a signed, hash-chained log: %d runs and %d actions in the period, with receipts any run can be proved by", c.Runs, c.Actions)),
		p("A.7.2", "Data for development and enhancement of AI system", "what the organisation trains, if it does",
			fmt.Sprintf("what agents learn is held until a person confirms it when it came from somebody else's words (%d confirmed)", c.Confirmed)),
		s("A.7.3", "Acquisition of data", "chatbots read only what is published; a tool's answer makes a run's output need a person"),
		s("A.7.4", "Quality of data for AI systems", "passages addressed to an AI are left out, and invisible text is taken out, before a model reads them"),
		s("A.7.5", "Data provenance", "every run records what it read, by name, and its receipt carries it; memory records the run it came from and how far it can be trusted"),
		p("A.7.6", "Data preparation", "how data is prepared outside Quilzo", "text is cleaned and screened as it is indexed"),
		s("A.8.2", "System documentation and information for users", fmt.Sprintf("%d of %d public chatbots say they are automated; the agent card says what each agent may do", len(f.disclosed), f.publicBots)),
		y("A.8.3", "External reporting", "the reports", "the public agent card states each agent's capabilities, budget and oversight"),
		p("A.8.4", "Communication of incidents", "telling the people affected", "the shield tells the security contact and opens a case"),
		p("A.8.5", "Information for interested parties", "what is said to whom",
			"receipts of runs, app connections and forgotten memory can be checked by anybody against published keys"),
		s("A.9.2", "Processes for responsible use of AI systems",
			"the exfiltration breaker, the privacy guard and approvals stand between an agent and anything leaving",
			fmt.Sprintf("%d calls through the MCP gateway, %d through the agent interface and %d tasks from other agents, all checked and recorded", c.GatewayCalls, c.AppCalls, c.Tasks)),
		y("A.9.3", "Objectives for responsible use of AI system", "the objectives"),
		s("A.9.4", "Intended use of the AI system", "each agent's purpose is declared and its manifest enforced; other uses are refused"),
		s("A.10.2", "Allocating responsibilities", fmt.Sprintf("a sponsor for every agent, and for each of the %d other vendors' agents registered here", len(in.External))),
		s("A.10.3", "Suppliers", fmt.Sprintf("%d model routes and %d tool servers declared; %d sightings of AI used directly, not through Quilzo, in the last week", len(in.Routes), len(in.Tools), shadow)),
		y("A.10.4", "Customers", "the commitments to customers", "end customers' memory can be seen and erased, and SCIM deletion erases it"),
	}
	for i := range items {
		items[i] = settle(items[i], in, "iso-42001")
	}
	if len(f.unevaluated) > 0 {
		for i := range items {
			if items[i].Ref == "A.6.2.4" && items[i].Status == Shown {
				items[i].Status = Partly
				items[i].Evidence = append(items[i].Evidence, "never evaluated: "+list(f.unevaluated))
			}
		}
	}
	if shadow > 0 {
		for i := range items {
			if items[i].Ref == "A.10.3" && items[i].Status == Shown {
				items[i].Status = Partly
			}
		}
	}
	return items
}
