// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package frameworks says which requirement of which framework each of this
// program's own checks bears on.
//
// The checks themselves live in internal/posture and are written against
// NIST SP 800-53, because that catalogue is the most granular and the one
// the others are most often mapped to. This package carries the rest: the
// FedRAMP baselines, ISO/IEC 27001, SOC 2, the NIST Cybersecurity
// Framework, the HIPAA Security Rule, and — for what 800-53 does not
// describe — GDPR, the EU AI Act, the NIST AI RMF, ISO/IEC 42001, the
// CCPA and OWASP's list for applications built on language models.
//
// # What a mapping here is, and is not
//
// It is the project's reading of where a check's evidence is relevant,
// made from the frameworks' own text and the published crosswalks between
// them. It is not an auditor's opinion, and a passing check is evidence
// towards a requirement, not the requirement met: "the audit log is
// intact" bears on ISO 27001 A.8.15 and does not on its own satisfy it.
// Where the project was not confident of a mapping it left it out rather
// than guess, so an absence means "not claimed", never "not relevant".
// Every framework below says so to whoever reads its section.
package frameworks

import (
	"sort"
	"strings"
)

// Kind groups frameworks by what they are about.
type Kind string

const (
	Security Kind = "security"
	Privacy  Kind = "privacy"
	AI       Kind = "ai"
)

// Framework is one framework this program maps its checks to.
type Framework struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Kind    Kind   `json:"kind"`
	// About is one sentence on what it is and who it binds.
	About string `json:"about"`
	URL   string `json:"url"`
}

// Catalogue is every framework, in the order a list shows them.
var Catalogue = []Framework{
	{ID: "nist-800-53", Name: "NIST SP 800-53", Version: "Rev. 5", Kind: Security,
		About: "The US federal catalogue of security and privacy controls; " +
			"the checks here are written against it.",
		URL: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"},
	{ID: "fedramp-low", Name: "FedRAMP Low", Version: "Rev. 5 baseline", Kind: Security,
		About: "The 800-53 baseline a cloud service offered to US federal " +
			"agencies is assessed against at low impact.",
		URL: "https://www.fedramp.gov/"},
	{ID: "fedramp-moderate", Name: "FedRAMP Moderate", Version: "Rev. 5 baseline", Kind: Security,
		About: "The baseline most federal cloud authorisations use.",
		URL:   "https://www.fedramp.gov/"},
	{ID: "fedramp-high", Name: "FedRAMP High", Version: "Rev. 5 baseline", Kind: Security,
		About: "The baseline for systems whose compromise would be severe or " +
			"catastrophic.",
		URL: "https://www.fedramp.gov/"},
	{ID: "iso-27001", Name: "ISO/IEC 27001", Version: "2022, Annex A", Kind: Security,
		About: "The international standard for an information security " +
			"management system, certified by accredited auditors.",
		URL: "https://www.iso.org/standard/27001"},
	{ID: "soc2", Name: "SOC 2", Version: "Trust Services Criteria (2017, rev. 2022)", Kind: Security,
		About: "The AICPA attestation most US buyers ask a software vendor for.",
		URL:   "https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2"},
	{ID: "nist-csf", Name: "NIST Cybersecurity Framework", Version: "2.0", Kind: Security,
		About: "Outcomes an organisation's security programme should achieve, " +
			"in six functions from Govern to Recover.",
		URL: "https://www.nist.gov/cyberframework"},
	{ID: "hipaa", Name: "HIPAA Security Rule", Version: "45 CFR Part 164, Subpart C", Kind: Security,
		About: "The US safeguards for electronic protected health information, " +
			"binding covered entities and their business associates.",
		URL: "https://www.hhs.gov/hipaa/for-professionals/security/index.html"},
	{ID: "gdpr", Name: "GDPR", Version: "Regulation (EU) 2016/679", Kind: Privacy,
		About: "The EU's law on personal data, binding anybody processing the " +
			"personal data of people in the EU.",
		URL: "https://eur-lex.europa.eu/eli/reg/2016/679/oj"},
	{ID: "ccpa", Name: "CCPA / CPRA", Version: "Cal. Civ. Code § 1798.100 et seq.", Kind: Privacy,
		About: "California's consumer privacy law, as amended by the CPRA.",
		URL:   "https://cppa.ca.gov/regulations/"},
	{ID: "eu-ai-act", Name: "EU AI Act", Version: "Regulation (EU) 2024/1689", Kind: AI,
		About: "The EU's law on AI systems. The transparency duties in " +
			"Article 50 apply from 2 August 2026; most high-risk duties " +
			"were deferred.",
		URL: "https://eur-lex.europa.eu/eli/reg/2024/1689/oj"},
	{ID: "nist-ai-rmf", Name: "NIST AI RMF", Version: "1.0, with the AI 600-1 profile", Kind: AI,
		About: "NIST's voluntary framework for managing AI risk: Govern, Map, " +
			"Measure, Manage.",
		URL: "https://www.nist.gov/itl/ai-risk-management-framework"},
	{ID: "iso-42001", Name: "ISO/IEC 42001", Version: "2023, Annex A", Kind: AI,
		About: "The international standard for an AI management system, " +
			"certifiable like ISO 27001.",
		URL: "https://www.iso.org/standard/42001"},
	{ID: "owasp-llm", Name: "OWASP Top 10 for LLM Applications", Version: "2025", Kind: AI,
		About: "The most common ways applications built on language models " +
			"are attacked.",
		URL: "https://genai.owasp.org/llm-top-10/"},
}

// Get finds a framework by its id.
func Get(id string) (Framework, bool) {
	for _, f := range Catalogue {
		if f.ID == id {
			return f, true
		}
	}
	return Framework{}, false
}

// Ref is one requirement in one framework.
type Ref struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
}

func (r Ref) String() string { return r.Framework + " " + r.ID }

// base is a control without its enhancement: AC-2(3) is AC-2.
func base(control string) string {
	if i := strings.IndexByte(control, '('); i > 0 {
		return control[:i]
	}
	return control
}

// fedramp is the FedRAMP Rev. 5 baselines each control is allocated to, as
// L, M and H. Only controls this program's checks cite, and only where the
// allocation is certain; an enhancement is listed on its own when it is
// allocated differently from its base control.
var fedramp = map[string]string{
	"AC-2": "LMH", "AC-2(3)": "MH", "AC-3": "LMH", "AC-5": "MH",
	"AC-6": "MH", "AC-6(2)": "MH", "AC-6(5)": "MH", "AC-17": "LMH",
	"AU-2": "LMH", "AU-3": "LMH", "AU-8": "LMH", "AU-9": "LMH",
	"AU-9(4)": "MH", "AU-10": "H", "AU-11": "LMH", "AU-12": "LMH",
	"CM-3": "MH", "CM-6": "LMH", "CM-7": "LMH", "CP-2": "LMH",
	"IA-2": "LMH", "IA-5": "LMH", "PL-4": "LMH",
	"SC-7": "LMH", "SC-8": "MH", "SC-8(1)": "MH", "SC-12": "LMH",
	"SC-18": "MH", "SC-23": "MH", "SC-39": "LMH",
	"SI-7": "MH", "SI-10": "MH", "SI-12": "LMH",
	"SI-4": "LMH", "SA-9": "LMH", "CA-7": "LMH",
}

// fromControl is where each 800-53 base control's evidence bears in the
// other security frameworks.
var fromControl = map[string][]Ref{
	"AC-2": {{"iso-27001", "A.5.16"}, {"iso-27001", "A.5.18"}, {"soc2", "CC6.2"},
		{"nist-csf", "PR.AA-01"}, {"hipaa", "164.308(a)(4)"}, {"hipaa", "164.312(a)(1)"}},
	"AC-3": {{"iso-27001", "A.8.3"}, {"soc2", "CC6.1"}, {"nist-csf", "PR.AA-05"},
		{"hipaa", "164.312(a)(1)"}},
	"AC-5": {{"iso-27001", "A.5.3"}, {"nist-csf", "PR.AA-05"}},
	"AC-6": {{"iso-27001", "A.8.2"}, {"iso-27001", "A.5.15"}, {"soc2", "CC6.3"},
		{"nist-csf", "PR.AA-05"}, {"hipaa", "164.308(a)(4)"}},
	"AC-17": {{"iso-27001", "A.6.7"}, {"soc2", "CC6.6"}, {"nist-csf", "PR.IR-01"}},
	"AU-2":  {{"iso-27001", "A.8.15"}, {"soc2", "CC7.2"}, {"nist-csf", "PR.PS-04"}, {"hipaa", "164.312(b)"}},
	"AU-3":  {{"iso-27001", "A.8.15"}, {"soc2", "CC7.2"}, {"nist-csf", "PR.PS-04"}, {"hipaa", "164.312(b)"}},
	"AU-8":  {{"iso-27001", "A.8.17"}, {"nist-csf", "PR.PS-04"}},
	"AU-9": {{"iso-27001", "A.8.15"}, {"soc2", "CC7.2"}, {"nist-csf", "PR.PS-04"},
		{"hipaa", "164.312(b)"}, {"hipaa", "164.312(c)(1)"}},
	"AU-10": {{"iso-27001", "A.8.15"}, {"hipaa", "164.312(c)(1)"}},
	"AU-11": {{"iso-27001", "A.8.15"}, {"iso-27001", "A.5.33"}, {"nist-csf", "PR.PS-04"}},
	"AU-12": {{"iso-27001", "A.8.15"}, {"soc2", "CC7.2"}, {"nist-csf", "PR.PS-04"}, {"hipaa", "164.312(b)"}},
	"CM-3":  {{"iso-27001", "A.8.32"}, {"soc2", "CC8.1"}, {"nist-csf", "PR.PS-01"}},
	"CM-5":  {{"iso-27001", "A.8.32"}, {"soc2", "CC8.1"}},
	"CM-6":  {{"iso-27001", "A.8.9"}, {"soc2", "CC7.1"}, {"nist-csf", "PR.PS-01"}},
	"CM-7":  {{"iso-27001", "A.8.9"}, {"soc2", "CC6.8"}, {"nist-csf", "PR.PS-01"}},
	"CP-2":  {{"iso-27001", "A.5.30"}, {"hipaa", "164.308(a)(7)"}},
	"IA-2": {{"iso-27001", "A.5.16"}, {"iso-27001", "A.8.5"}, {"soc2", "CC6.1"},
		{"nist-csf", "PR.AA-03"}, {"hipaa", "164.312(d)"}},
	"IA-5": {{"iso-27001", "A.5.17"}, {"soc2", "CC6.1"}, {"nist-csf", "PR.AA-01"},
		{"hipaa", "164.312(d)"}},
	"PL-4":  {{"iso-27001", "A.5.10"}},
	"PM-30": {{"iso-27001", "A.5.19"}, {"iso-27001", "A.5.21"}, {"soc2", "CC9.2"}, {"nist-csf", "GV.SC-01"}},
	"SC-7":  {{"iso-27001", "A.8.20"}, {"iso-27001", "A.8.22"}, {"soc2", "CC6.6"}, {"nist-csf", "PR.IR-01"}},
	"SC-8": {{"iso-27001", "A.8.24"}, {"iso-27001", "A.5.14"}, {"soc2", "CC6.7"},
		{"nist-csf", "PR.DS-02"}, {"hipaa", "164.312(e)(1)"}},
	"SC-12": {{"iso-27001", "A.8.24"}, {"soc2", "CC6.1"}},
	"SC-18": {{"soc2", "CC6.8"}},
	"SC-23": {{"iso-27001", "A.8.5"}, {"soc2", "CC6.1"}},
	"SI-7":  {{"nist-csf", "PR.DS-01"}, {"hipaa", "164.312(c)(1)"}},
	"SI-10": {{"iso-27001", "A.8.28"}, {"nist-csf", "PR.PS-06"}},
	"SI-12": {{"iso-27001", "A.5.33"}, {"iso-27001", "A.8.10"}, {"soc2", "C1.2"}},
	"SI-4": {{"iso-27001", "A.8.16"}, {"soc2", "CC7.2"}, {"nist-csf", "DE.CM-09"},
		{"hipaa", "164.308(a)(1)(ii)(D)"}},
	"SA-9": {{"iso-27001", "A.5.19"}, {"iso-27001", "A.5.23"}, {"soc2", "CC9.2"},
		{"hipaa", "164.308(b)(1)"}},
	"CA-7": {{"soc2", "CC4.1"}},
}

// fromRule is what a check bears on that 800-53 does not describe: the
// privacy laws and the AI frameworks, by the check's own id.
var fromRule = map[string][]Ref{
	// Security of processing is what every control on access, credentials,
	// logging and exposure is evidence for, under both privacy laws.
	"access.no-policy":              {{"gdpr", "Art. 32"}},
	"access.no-deny-anywhere":       {{"gdpr", "Art. 32"}},
	"access.too-many-admins":        {{"gdpr", "Art. 32"}, {"gdpr", "Art. 25"}},
	"token.long-lived":              {{"gdpr", "Art. 32"}},
	"token.admin-role":              {{"gdpr", "Art. 32"}},
	"sso.cert-expiring":             {{"gdpr", "Art. 32"}},
	"sso.unusable":                  {{"gdpr", "Art. 32"}},
	"token.stale":                   {{"gdpr", "Art. 32"}},
	"token.expired-not-revoked":     {{"gdpr", "Art. 32"}},
	"audit.chain-broken":            {{"gdpr", "Art. 32(1)(b)"}, {"gdpr", "Art. 5(2)"}},
	"audit.empty":                   {{"gdpr", "Art. 5(2)"}},
	"audit.unverified-identities":   {{"gdpr", "Art. 5(2)"}},
	"expose.cleartext":              {{"gdpr", "Art. 32(1)(a)"}, {"ccpa", "§ 1798.100(e)"}},
	"expose.admin-public":           {{"gdpr", "Art. 32"}},
	"config.weakened":               {{"gdpr", "Art. 32"}, {"gdpr", "Art. 25"}},
	"content.retention-unenforced":  {{"gdpr", "Art. 5(1)(e)"}, {"ccpa", "§ 1798.100(a)(3)"}},
	"privacy.form-basis-missing":    {{"gdpr", "Art. 6"}, {"gdpr", "Art. 13"}, {"gdpr", "Art. 5(1)(b)"}, {"ccpa", "§ 1798.100(b)"}},
	"content.unmarked-ai":           {{"eu-ai-act", "Art. 50(2)"}, {"iso-42001", "A.8.2"}},
	"content.raw-template":          {{"owasp-llm", "LLM05"}},
	"agent.write-without-role":      {{"owasp-llm", "LLM06"}, {"iso-42001", "A.9.2"}},
	"agent.shared-human-credential": {{"owasp-llm", "LLM06"}, {"iso-42001", "A.9.2"}},
	// The checks written for this package's frameworks in the first place.
	"ai.chatbot-undisclosed": {{"eu-ai-act", "Art. 50(1)"}, {"iso-42001", "A.8.2"}},
	"ai.chatbot-unevaluated": {{"nist-ai-rmf", "MEASURE 2.5"}, {"iso-42001", "A.6.2.4"},
		{"owasp-llm", "LLM09"}},
	"ai.agent-followed-plant": {{"owasp-llm", "LLM01"}, {"nist-ai-rmf", "MEASURE 2.7"},
		{"iso-42001", "A.6.2.4"}, {"eu-ai-act", "Art. 15"}},
	"ai.agent-unevaluated": {{"nist-ai-rmf", "MEASURE 2.5"}, {"iso-42001", "A.6.2.4"}},
	"ai.agent-flagged": {{"nist-ai-rmf", "MANAGE 4.1"}, {"iso-42001", "A.6.2.6"},
		{"owasp-llm", "LLM06"}},
	"privacy.model-egress": {{"gdpr", "Art. 28"}, {"gdpr", "Art. 44"},
		{"gdpr", "Art. 30"}, {"ccpa", "§ 1798.100(d)"}, {"owasp-llm", "LLM02"}},
}

// Refs is every requirement a check bears on: through the 800-53 controls
// it cites, and through its own id.
func Refs(rule string, controls []string) []Ref {
	seen := map[Ref]bool{}
	var out []Ref
	add := func(r Ref) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for _, c := range controls {
		add(Ref{"nist-800-53", c})
		levels, ok := fedramp[c]
		if !ok {
			levels = fedramp[base(c)]
		}
		for _, l := range levels {
			switch l {
			case 'L':
				add(Ref{"fedramp-low", c})
			case 'M':
				add(Ref{"fedramp-moderate", c})
			case 'H':
				add(Ref{"fedramp-high", c})
			}
		}
		for _, r := range fromControl[base(c)] {
			add(r)
		}
	}
	for _, r := range fromRule[rule] {
		add(r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Framework != out[j].Framework {
			return order(out[i].Framework) < order(out[j].Framework)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func order(id string) int {
	for i, f := range Catalogue {
		if f.ID == id {
			return i
		}
	}
	return len(Catalogue)
}
