// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package programme

// DORA, the EU's regulation on digital operational resilience for the
// financial sector: the articles a financial entity meets on ICT risk
// management (chapter II), ICT-related incidents (chapter III), resilience
// testing (chapter IV) and ICT third-party risk (chapter V, section I),
// each by article with a line in Quilzo's own words. The articles written
// for the authorities, and the oversight of critical third-party providers,
// are not requirements of the entity and are left out.
var _ = starter(Starter{
	Framework: "dora", Name: "DORA", Version: "Regulation (EU) 2022/2554",
	About: "The EU's rules on the digital operational resilience of financial entities and their ICT providers.",
	Level: "articles",
	Clauses: []Clause{
		{"Art. 5", "The management body defines, approves and answers for ICT risk management"},
		{"Art. 6", "There is a documented ICT risk management framework, reviewed and audited"},
		{"Art. 7", "ICT systems are kept up to date, reliable, resilient and with enough capacity"},
		{"Art. 8", "ICT functions, assets, dependencies and risks are identified and kept up to date"},
		{"Art. 9", "ICT systems are protected and threats prevented by policies and tools"},
		{"Art. 10", "Anomalies are detected promptly"},
		{"Art. 11", "An ICT continuity policy holds response and recovery plans, which are tested"},
		{"Art. 12", "Backups are taken, and restoration and recovery are set and tested"},
		{"Art. 13", "Lessons are drawn from incidents and tests, and staff are trained"},
		{"Art. 14", "There are plans to communicate about ICT-related incidents"},
		{"Art. 16", "A smaller entity keeps a simplified ICT risk management framework"},
		{"Art. 17", "There is a process to detect, manage and notify ICT-related incidents"},
		{"Art. 18", "Incidents and cyber threats are classified by set criteria"},
		{"Art. 19", "Major ICT-related incidents are reported to the authority"},
		{"Art. 23", "Payment-related incidents are handled under the same rules"},
		{"Art. 24", "There is a programme for testing digital operational resilience"},
		{"Art. 25", "ICT tools and systems are tested by a suitable range of tests"},
		{"Art. 26", "Threat-led penetration testing is carried out where it is required"},
		{"Art. 27", "Testers for threat-led tests meet set requirements"},
		{"Art. 28", "ICT third-party risk is managed, with a register of every contractual arrangement"},
		{"Art. 29", "Concentration risk is assessed before contracting for ICT services"},
		{"Art. 30", "Contracts for ICT services hold the provisions the regulation requires"},
	},
})
