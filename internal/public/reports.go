// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Violation reports: what visitors' browsers say a page tried to load that
// the policy refused.
//
// A script the site never names turning up on a page, in many visitors'
// browsers at once, is often the first sign of a compromised dependency, an
// injected tag, or a malicious extension spreading: the browser sees it
// before anybody else does. Chromium sends these with the Reporting API
// (Reporting-Endpoints, report-to) and older browsers with report-uri, so
// both are named.
//
// Anybody can post a report, so a report proves nothing about who sent it
// and is never a reason to refuse anybody: the shield may tell a person,
// and nothing more. Most reports are noise, from browser extensions and
// the software that injects into pages; those are dropped before anything
// is counted. The endpoint always answers 204 (a browser told 4xx marks the
// endpoint as failing), reads no cookie, and stores nothing itself.

// ReportsPath is where violation reports are posted.
const ReportsPath = "/.quilzo/reports"

const (
	maxReportBody = 64 << 10
	maxReports    = 100
)

// Violation is one report, as much of it as is used.
type Violation struct {
	// Directive is what refused it: script-src-elem, img-src.
	Directive string
	// Blocked is the origin of what was refused, or "inline" or "eval".
	Blocked string
	// Page is the path of the page it happened on.
	Page string
	// Enforced is false for a report-only policy, where it was not stopped.
	Enforced bool
}

// Group is the violation as one thing to count: the same directive, the
// same blocked origin, the same page.
func (v Violation) Group() string { return v.Directive + " " + v.Blocked + " " + v.Page }

// noise are the origins browser extensions and page-injecting software
// report from, which say nothing about the site.
var noise = []string{"chrome-extension:", "moz-extension:", "safari-extension:", "safari-web-extension:",
	"ms-browser-extension:", "chrome:", "resource:", "about:", "webkit-masked-url:", "chromewebdata",
	"data:text/html", "injections.adguard.com", "superfish.com", "zscaler"}

func isNoise(s string) bool {
	s = strings.ToLower(s)
	for _, n := range noise {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

// reportsHandler receives violation reports.
func (st *Site) reportsHandler(w http.ResponseWriter, r *http.Request) {
	if st.OnViolation == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ReportsHandler(st.OnViolation).ServeHTTP(w, r)
}

// ReportsHandler receives violation reports for any server: always 204,
// nothing stored, each kept report handed to on.
func ReportsHandler(on func(Violation, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receive(w, r, on)
	})
}

func receive(w http.ResponseWriter, r *http.Request, on func(Violation, *http.Request)) {
	defer w.WriteHeader(http.StatusNoContent)
	if r.Method != http.MethodPost || on == nil {
		return
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if !strings.HasPrefix(ct, "application/csp-report") && !strings.HasPrefix(ct, "application/reports+json") {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxReportBody+1))
	if err != nil || len(body) > maxReportBody {
		return
	}
	for _, v := range parseViolations(body, r.Host) {
		on(v, r)
	}
}

// WithReporting adds where to report to a policy.
func WithReporting(policy string) string { return withReporting(policy) }

// parseViolations reads either shape a browser sends, keeping only reports
// about this host's own pages and not from extensions.
func parseViolations(body []byte, host string) []Violation {
	type cspBody struct {
		Document    string `json:"documentURL"`
		Blocked     string `json:"blockedURL"`
		Directive   string `json:"effectiveDirective"`
		Disposition string `json:"disposition"`
		Source      string `json:"sourceFile"`
	}
	var raw []cspBody
	// The Reporting API: a list of {type, url, body}.
	var list []struct {
		Type string  `json:"type"`
		Body cspBody `json:"body"`
	}
	if json.Unmarshal(body, &list) == nil && len(list) > 0 {
		for i, x := range list {
			if i == maxReports {
				break
			}
			if x.Type == "csp-violation" {
				raw = append(raw, x.Body)
			}
		}
	} else {
		// report-uri: {"csp-report": {...}} with dashed names.
		var old struct {
			Report struct {
				Document    string `json:"document-uri"`
				Blocked     string `json:"blocked-uri"`
				Directive   string `json:"effective-directive"`
				Violated    string `json:"violated-directive"`
				Disposition string `json:"disposition"`
				Source      string `json:"source-file"`
			} `json:"csp-report"`
		}
		if json.Unmarshal(body, &old) != nil {
			return nil
		}
		d := old.Report.Directive
		if d == "" {
			d, _, _ = strings.Cut(old.Report.Violated, " ")
		}
		raw = append(raw, cspBody{Document: old.Report.Document, Blocked: old.Report.Blocked,
			Directive: d, Disposition: old.Report.Disposition, Source: old.Report.Source})
	}
	var out []Violation
	for _, b := range raw {
		if isNoise(b.Blocked) || isNoise(b.Source) || isNoise(b.Document) {
			continue
		}
		doc, err := url.Parse(b.Document)
		if err != nil || !strings.EqualFold(doc.Host, host) {
			continue // a report about somebody else's page
		}
		directive := strings.ToLower(strings.TrimSpace(b.Directive))
		if directive == "" || len(directive) > 40 {
			continue
		}
		blocked := strings.ToLower(strings.TrimSpace(b.Blocked))
		switch blocked {
		case "inline", "eval", "wasm-eval", "trusted-types-policy", "trusted-types-sink":
		default:
			u, err := url.Parse(b.Blocked)
			if err != nil || u.Host == "" {
				continue
			}
			blocked = u.Scheme + "://" + strings.ToLower(u.Host)
		}
		page := doc.Path
		if page == "" {
			page = "/"
		}
		if len(page) > 120 {
			page = page[:120]
		}
		out = append(out, Violation{Directive: directive, Blocked: blocked, Page: page,
			Enforced: b.Disposition != "report"})
	}
	return out
}

// withReporting adds where to report to a policy.
func withReporting(policy string) string {
	if policy == "" || strings.Contains(policy, "report-uri") || strings.Contains(policy, "report-to") {
		return policy
	}
	return policy + "; report-uri " + ReportsPath + "; report-to csp"
}
