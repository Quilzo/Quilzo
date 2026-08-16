package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/lithoform/lithoform/internal/agentwatch"
	"github.com/lithoform/lithoform/internal/auth"
	"github.com/lithoform/lithoform/internal/codescan"
	"github.com/lithoform/lithoform/internal/compliance"
	"github.com/lithoform/lithoform/internal/csp"
)

// The evidence, in the interface.
//
// Seven capabilities that produce evidence about this system — the static
// scanner, the generated content policy, the software bill of materials and
// crypto inventory, the store's own integrity check, encryption at rest, what
// the agents have been doing, and the anchors that make a publication
// timestamp checkable by somebody who does not trust us.
//
// Every one of them was terminal-only, which is close to the worst place for
// them to be: the person who has to answer an auditor is not usually the
// person with a shell on the box, and evidence somebody cannot get to is
// evidence they will recreate by hand from screenshots.
//
// These hang off /security rather than getting a navigation entry each. The
// posture dashboard is the front page of the same question — what is the state
// of this system — and eight top-level destinations for one topic is a menu
// nobody reads.

// Assurance gives the admin everything that produces evidence.
//
// Each field may be nil, and each screen says so rather than rendering an empty
// result. "The scanner found nothing" and "this build cannot run the scanner"
// look identical on a page and mean opposite things.
type Assurance struct {
	// Scan runs the static analysis over templates and content.
	Scan func() (scanned int, findings []codescan.Finding, err error)
	// CSP derives a content security policy from what the site actually
	// references.
	CSP func() (header, value string, sources csp.Sources, pages int, err error)
	// SBOM is the bill of materials and the crypto inventory.
	SBOM func() (*compliance.SBOM, error)
	// Verify re-hashes every object in the store.
	Verify func() (objects int, err error)
	// Vault reports encryption at rest.
	Vault func() (encrypted bool, active string, keys []string)
	// Agents summarises what non-human principals have been doing.
	Agents func() ([]agentwatch.Report, error)
	// Evidence lists timestamps and blockchain anchors as flat rows, because
	// the two answer the same question — can somebody else check when this was
	// published — and a screen with one table is easier to read than two.
	Evidence func() ([]Evidence, error)
}

// Evidence is one timestamp or anchor, flattened for display.
type Evidence struct {
	// Kind is "timestamp" or "anchor".
	Kind string
	// Subject is what was stamped: the fingerprint of a publication.
	Subject string
	// Authority is the TSA or calendar that produced it.
	Authority string
	// State says what it is worth right now. An anchor that has been submitted
	// and not yet committed to a block is evidence of an intention, not of a
	// time, and saying "pending" rather than showing a tick is the difference.
	State string
	// Detail carries whatever else matters — a block height, a token time.
	Detail string
	At     string
}

func (s *Server) handleScanScreen(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	data := map[string]any{
		"Nav": "security", "Title": "Code scan", "Principal": p,
		"Rules": codescan.Rules(),
	}
	if s.Assurance == nil || s.Assurance.Scan == nil {
		data["Unavailable"] = "This build was started without the scanner " +
			"wired in, so nothing has been scanned. An empty findings list " +
			"would read as a clean one."
		s.render(w, r, "scan.html", data)
		return
	}
	scanned, findings, err := s.Assurance.Scan()
	if err != nil {
		data["Unavailable"] = err.Error()
		s.render(w, r, "scan.html", data)
		return
	}
	// Most severe first. A list in file order buries the one thing worth
	// reading under forty style notes.
	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
	})
	data["Scanned"], data["Findings"] = scanned, findings
	s.render(w, r, "scan.html", data)
}

func severityRank(s codescan.Severity) int {
	switch s {
	case codescan.Critical:
		return 4
	case codescan.High:
		return 3
	case codescan.Medium:
		return 2
	case codescan.Low:
		return 1
	}
	return 0
}

func (s *Server) handleCSPScreen(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	data := map[string]any{
		"Nav": "security", "Title": "Content policy", "Principal": p,
	}
	if s.Assurance == nil || s.Assurance.CSP == nil {
		data["Unavailable"] = "This build cannot derive a policy."
		s.render(w, r, "csp.html", data)
		return
	}
	header, value, sources, pages, err := s.Assurance.CSP()
	if err != nil {
		data["Unavailable"] = err.Error()
		s.render(w, r, "csp.html", data)
		return
	}
	data["Header"], data["Value"] = header, value
	data["Sources"], data["Pages"] = sources, pages
	// A policy that was widened to accommodate something is worth naming. The
	// header alone does not say which of its allowances were forced.
	data["Widened"] = csp.Widened(value)
	s.render(w, r, "csp.html", data)
}

func (s *Server) handleComplianceScreen(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	data := map[string]any{
		"Nav": "security", "Title": "Inventory", "Principal": p,
		"Crypto": compliance.Inventory(), "Posture": compliance.Posture(),
		"Concerns": compliance.Concerns(),
	}
	if s.Assurance != nil && s.Assurance.SBOM != nil {
		if sb, err := s.Assurance.SBOM(); err == nil {
			data["SBOM"] = sb
			data["ThirdParty"] = compliance.ThirdParty(sb)
		} else {
			data["Unavailable"] = err.Error()
		}
	}
	s.render(w, r, "compliance.html", data)
}

func (s *Server) handleIntegrityScreen(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	data := map[string]any{
		"Nav": "security", "Title": "Integrity", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"CanRun": s.Policy.Evaluate(p.Name, auth.ActGrant, "/").Allowed,
	}
	if s.Assurance != nil && s.Assurance.Vault != nil {
		encrypted, active, keys := s.Assurance.Vault()
		data["Encrypted"], data["ActiveKey"], data["Keys"] = encrypted, active, keys
	}
	if s.Assurance != nil && s.Assurance.Evidence != nil {
		if rows, err := s.Assurance.Evidence(); err == nil {
			data["Evidence"] = rows
		}
	}
	s.render(w, r, "integrity.html", data)
}

// handleVerify re-hashes every object in the store.
//
// A POST, and not run on page load. Verification reads and re-hashes the whole
// store; doing that on every visit to a dashboard would make opening a page an
// I/O event proportional to the size of the site, which is how a check ends up
// being switched off.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
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
	if s.Assurance == nil || s.Assurance.Verify == nil {
		s.verifyRedirect(w, r, "", "this build cannot verify the store")
		return
	}
	start := time.Now()
	objects, err := s.Assurance.Verify()
	took := time.Since(start).Round(time.Millisecond)
	if err != nil {
		s.auditPub(p, "store.verify", "/", map[string]string{
			"outcome": "failed", "reason": err.Error()})
		s.verifyRedirect(w, r, "", err.Error())
		return
	}
	s.auditPub(p, "store.verify", "/", map[string]string{
		"objects": fmt.Sprint(objects), "took": took.String()})
	s.verifyRedirect(w, r, fmt.Sprintf(
		"%d object(s) re-hashed in %s, and every one matched the name it is "+
			"stored under.", objects, took), "")
}

func (s *Server) handleAgentsScreen(w http.ResponseWriter, r *http.Request) {
	p, ok := s.assuranceReader(w, r)
	if !ok {
		return
	}
	data := map[string]any{
		"Nav": "security", "Title": "Agents", "Principal": p,
		"Threshold": agentwatch.Threshold, "Window": agentwatch.Window.String(),
	}
	if s.Assurance == nil || s.Assurance.Agents == nil {
		data["Unavailable"] = "This build has no access to the audit log, so " +
			"nothing can be said about what any agent has done."
		s.render(w, r, "agents.html", data)
		return
	}
	reports, err := s.Assurance.Agents()
	if err != nil {
		data["Unavailable"] = err.Error()
		s.render(w, r, "agents.html", data)
		return
	}
	data["Reports"] = reports
	data["Flagged"] = agentwatch.Flagged(reports)
	s.render(w, r, "agents.html", data)
}

// assuranceReader is the shared preamble.
//
// Gated on ActGrant rather than ActView, for the reason the posture dashboard
// is: a detailed list of where this system's defences are thin is a target
// list, and the people who need it are the people who can already change it.
func (s *Server) assuranceReader(w http.ResponseWriter, r *http.Request) (principal, bool) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return principal{}, false
	}
	return p, true
}

func (s *Server) verifyRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/security/integrity"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// joined renders a source list for the policy page.
func joined(v []string) string { return strings.Join(v, " ") }
