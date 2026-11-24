// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package frameworks

// Requirement is one entry of a published list: its identifier, and its
// title as the list gives it.
type Requirement struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// lists is each framework whose list is short enough to carry whole, entry
// for entry as published.
//
// Carrying the list is what lets a citation be checked. A list that is
// renumbered keeps its identifiers and moves what they mean: OWASP's 2026
// list for applications built on language models made LLM06 Unbounded
// Consumption, which had been LLM10, and a check that cited LLM06 for an
// agent writing with no role went on citing it, pointing a reader at the
// wrong risk without a character of it changing. Each list here is pinned
// in this package's tests to a copy of the published one, kept with where
// it was copied from, and each citation of it to the title it means, which
// a renumbering cannot move.
var lists = map[string][]Requirement{
	"owasp-llm": {
		{"LLM01", "Prompt Injection"},
		{"LLM02", "Sensitive Information Disclosure"},
		{"LLM03", "Excessive Agency"},
		{"LLM04", "Supply Chain"},
		{"LLM05", "Data and Model Poisoning"},
		{"LLM06", "Unbounded Consumption"},
		{"LLM07", "Misinformation"},
		{"LLM08", "Hidden Context Exposure"},
		{"LLM09", "Vector and Embedding Weaknesses"},
		{"LLM10", "Improper Output Handling"},
	},
	"owasp-asi": {
		{"ASI01", "Agent Goal Hijack"},
		{"ASI02", "Tool Misuse & Exploitation"},
		{"ASI03", "Identity & Privilege Abuse"},
		{"ASI04", "Agentic Supply Chain Vulnerabilities"},
		{"ASI05", "Unexpected Code Execution (RCE)"},
		{"ASI06", "Memory & Context Poisoning"},
		{"ASI07", "Insecure Inter-Agent Communication"},
		{"ASI08", "Cascading Failures"},
		{"ASI09", "Human-Agent Trust Exploitation"},
		{"ASI10", "Rogue Agents"},
	},
	// The ten measures every essential and important entity takes, in the
	// Directive's own words, lower case as they are written there.
	"nis2": {
		{"Art. 21(2)(a)", "policies on risk analysis and information system security"},
		{"Art. 21(2)(b)", "incident handling"},
		{"Art. 21(2)(c)", "business continuity, such as backup management and disaster recovery, and crisis management"},
		{"Art. 21(2)(d)", "supply chain security, including security-related aspects concerning the relationships between each entity and its direct suppliers or service providers"},
		{"Art. 21(2)(e)", "security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure"},
		{"Art. 21(2)(f)", "policies and procedures to assess the effectiveness of cybersecurity risk-management measures"},
		{"Art. 21(2)(g)", "basic cyber hygiene practices and cybersecurity training"},
		{"Art. 21(2)(h)", "policies and procedures regarding the use of cryptography and, where appropriate, encryption"},
		{"Art. 21(2)(i)", "human resources security, access control policies and asset management"},
		{"Art. 21(2)(j)", "the use of multi-factor authentication or continuous authentication solutions, secured voice, video and text communications and secured emergency communication systems within the entity, where appropriate"},
	},
}

// List is a framework's published list, in its order, or nothing for a
// framework too long to carry whole, whose identifiers are checked for
// their shape instead.
func List(framework string) []Requirement {
	l := lists[framework]
	if l == nil {
		return nil
	}
	out := make([]Requirement, len(l))
	copy(out, l)
	return out
}

// Title is what a requirement is called in its list, or "" where this
// package does not carry the list.
func Title(framework, id string) string {
	for _, r := range lists[framework] {
		if r.ID == id {
			return r.Title
		}
	}
	return ""
}
