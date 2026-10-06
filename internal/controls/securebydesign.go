// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package controls

// CISA's Secure by Design pledge: seven goals a software manufacturer
// commits to, and where Quilzo stands on each. A position is a statement a
// buyer can check, with what is not done said as plainly as what is.

// Standing is how far a goal is met.
type Standing string

const (
	Met    Standing = "met"
	Partly Standing = "partly"
	NotYet Standing = "not yet"
)

// Goal is one of the pledge's goals and Quilzo's position on it.
type Goal struct {
	N        int      `json:"goal"`
	Title    string   `json:"title"`
	Asks     string   `json:"asks"`
	Standing Standing `json:"standing"`
	Position string   `json:"position"`
	Where    []string `json:"where,omitempty"`
}

// PledgeURL is CISA's page for the pledge.
const PledgeURL = "https://www.cisa.gov/securebydesign/pledge"

// Pledge is the seven goals, in CISA's order and words.
var Pledge = []Goal{
	{N: 1, Title: "Multi-factor authentication (MFA)",
		Asks:     "Demonstrate actions taken to measurably increase the use of multi-factor authentication across the manufacturer's products.",
		Standing: Partly,
		Position: "Quilzo has no passwords. People sign in to the admin with passkeys or single sign-on, which can be required for a whole email domain and, for SAML, required to report multi-factor authentication; a session moved to another device or country must confirm its person again. A pasted token is still a single factor: single sign-on can be required instead for a domain, and the posture scan reports tokens that carry administrator rights.",
		Where:    []string{"/passkeys", "/sso"}},
	{N: 2, Title: "Default passwords",
		Asks:     "Demonstrate measurable progress towards reducing default passwords across the manufacturers' products.",
		Standing: Met,
		Position: "There is no default credential and no password of any kind. The first administrator is granted by name on the machine and given a 256-bit token, shown once and stored only as a hash.",
		Where:    []string{"quilzo auth grant", "quilzo token issue"}},
	{N: 3, Title: "Reducing entire classes of vulnerability",
		Asks:     "Demonstrate actions taken towards enabling a significant measurable reduction in the prevalence of one or more vulnerability classes.",
		Standing: Met,
		Position: "Classes removed by construction rather than by review: memory-safety bugs (Go, no cgo); SQL injection (there is no database); server-side template injection and script injection from content (the template language cannot execute or emit script, and escapes by default); server-side request forgery to internal addresses (checked at connect time, after DNS, so rebinding cannot pass); XML signature wrapping (SAML is read by a strict parser that re-reads only the verified bytes); and supply-chain compromise through dependencies (the standard library is the only one).",
		Where:    []string{"internal/tmpl", "internal/fetch", "internal/xmldsig"}},
	{N: 4, Title: "Security patches",
		Asks:     "Demonstrate actions taken to measurably increase the installation of security patches by customers.",
		Standing: Partly,
		Position: "Every running copy checks itself hourly against the Go vulnerability database, decided by what is actually linked into it, tells the administrator which release fixes a flaw that applies, and switches off the features a known exploited flaw reaches until it is upgraded. An upgrade is one binary. Quilzo does not update itself.",
		Where:    []string{"quilzo self check", "/security/inventory"}},
	{N: 5, Title: "Vulnerability disclosure policy",
		Asks:     "Publish a vulnerability disclosure policy (VDP) that authorizes testing by members of the public on products.",
		Standing: Partly,
		Position: "SECURITY.md publishes a private reporting channel, response times (first response within 5 days, a fix for a high or critical issue within 30) and the structural claims whose failure counts as a vulnerability. It does not yet say in so many words that good-faith testing is authorised.",
		Where:    []string{"SECURITY.md"}},
	{N: 6, Title: "CVEs",
		Asks:     "Demonstrate transparency in vulnerability reporting by including accurate Common Weakness Enumeration (CWE) and Common Platform Enumeration (CPE) fields.",
		Standing: NotYet,
		Position: "No advisory has been published for Quilzo yet. Advisories go through GitHub's security advisories, which carry a CVE and its CWE; a commitment to CPE fields has not been made.",
		Where:    []string{"SECURITY.md"}},
	{N: 7, Title: "Evidence of intrusions",
		Asks:     "Demonstrate a measurable increase in the ability for customers to gather evidence of cybersecurity intrusions affecting the manufacturer's products.",
		Standing: Met,
		Position: "The audit log is on by default, cannot be switched off, records who did what with whether the identity was verified and whether it was a person or a model, and is hash-chained with signed heads that can be published elsewhere. It exports to a SIEM; the shield's decisions, refused credentials and sign-in risk are in it; the browser's reports of blocked content are collected.",
		Where:    []string{"quilzo auditlog", "/logs", "internal/siem"}},
}
