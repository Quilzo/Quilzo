// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

// The NIST Cybersecurity Framework 2.0: its twenty-two categories across
// the six functions, from Govern to Recover, each by its identifier with a
// line in Quilzo's own words. The subcategories are what an assessment
// looks at within each, and are read in NIST's publication.
var _ = starter(Starter{
	Framework: "nist-csf", Name: "NIST Cybersecurity Framework", Version: "2.0",
	About: "Outcomes an organisation's security programme should achieve, in six functions from Govern to Recover.",
	Level: "categories",
	Clauses: []Clause{
		{"GV.OC", "The mission, stakeholders and obligations behind cyber risk decisions are understood"},
		{"GV.RM", "Priorities, appetite and assumptions for cyber risk are set and used"},
		{"GV.RR", "Roles and authority for cyber risk are set, and people are accountable"},
		{"GV.PO", "Cybersecurity policy is set, communicated and enforced"},
		{"GV.OV", "What cyber risk management achieves is used to adjust the strategy"},
		{"GV.SC", "Risks from the supply chain are identified, assessed and managed"},
		{"ID.AM", "Assets are identified and managed by their importance"},
		{"ID.RA", "Cyber risk to the organisation, its assets and people is understood"},
		{"ID.IM", "Improvements are found from assessments, exercises and incidents"},
		{"PR.AA", "Access is limited to authorised identities, authenticated in proportion to the risk"},
		{"PR.AT", "People are made aware and trained to do their part"},
		{"PR.DS", "Data is protected in line with the risk strategy"},
		{"PR.PS", "Hardware, software and services are managed securely"},
		{"PR.IR", "Infrastructure is managed to be secure and resilient"},
		{"DE.CM", "Assets are monitored for anomalies and signs of compromise"},
		{"DE.AE", "Anomalies and events are analysed to understand incidents"},
		{"RS.MA", "Responses to detected incidents are managed"},
		{"RS.AN", "Incidents are investigated to support response and recovery"},
		{"RS.CO", "Response is coordinated with the people and bodies who must know"},
		{"RS.MI", "Incidents are contained and their effects reduced"},
		{"RC.RP", "Recovery is carried out to restore what incidents affected"},
		{"RC.CO", "Recovery is coordinated with those inside the organisation and outside"},
	},
})
