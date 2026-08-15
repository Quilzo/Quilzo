// Package codescan looks for injection and leaked credentials in the things a
// customer writes: templates, content, redirect maps and configuration.
//
// The request was for built-in linters covering XSS, SQL injection and leaked
// secrets. Two of those need a note about what this program can honestly claim.
//
// **SQL injection.** There is no SQL here. The store is content-addressed files
// and there is no database, no query builder and no driver, so a rule matching
// SELECT statements in page bodies would be theatre — it would fire on an
// article *about* SQL and never on anything exploitable. What is real is the
// generic shape: content that ends up in somebody else's query. So the rules
// look for credentials and connection strings, which is what actually leaks
// through a CMS into a database, and say plainly that the injection risk lives
// in the consumer rather than here.
//
// **XSS.** This is real and it is the main event. The template language escapes
// by default and `{% raw %}` turns that off, which is the intended way to emit
// rich text and also the way somebody publishes an attacker's markup. The rules
// find raw output, event-handler attributes, and executable URL schemes in
// content — the three ways a value becomes script on a page.
//
// **Secrets.** Pattern matching for the credential formats that are actually
// recognisable, plus entropy for the ones that are not. Entropy is used to
// raise the confidence of a match that already looks like an assignment, never
// on its own: a bare high-entropy string is as likely to be a hash, an id or a
// base64 image as a key, and a scanner that cries wolf gets switched off, which
// costs more than the rule was worth.
//
// Every finding names the rule, the file, the line and what to do. A finding
// nobody can act on is noise, and noise is how a scanner ends up permanently
// disabled in CI.
package codescan

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Severity orders findings.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
)

func rank(s Severity) int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	}
	return 1
}

// Finding is one thing worth looking at.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Where    string   `json:"where"`
	Line     int      `json:"line,omitempty"`
	// Excerpt is the matching text, truncated and with any credential masked.
	// A scanner that prints the secret it found has copied it into the CI log,
	// which is usually more widely readable than the file it came from.
	Excerpt  string   `json:"excerpt,omitempty"`
	Detail   string   `json:"detail"`
	Fix      string   `json:"fix"`
	Controls []string `json:"controls,omitempty"`
	OWASP    string   `json:"owasp,omitempty"`
}

// Rule is one check over one line of text.
type Rule struct {
	ID       string
	Severity Severity
	Pattern  *regexp.Regexp
	Detail   string
	Fix      string
	Controls []string
	OWASP    string
	// Kinds limits the rule to certain inputs, because the same text means
	// different things in different places: `onclick=` in a template is a
	// finding, and in a page about HTML it is the subject.
	Kinds []Kind
	// Confirm lets a rule reject its own match. Used by the secret rules to
	// require entropy, so that `api_key = "example"` in documentation does not
	// become a critical finding.
	Confirm func(match string) bool
}

// Kind is what is being scanned.
type Kind string

const (
	Template Kind = "template" // markup with directives, rendered to a browser
	Content  Kind = "content"  // field values authors typed
	Config   Kind = "config"   // configuration and redirect maps
)

// Input is one thing to scan.
type Input struct {
	Name string
	Kind Kind
	Body string
}

// Scan runs every rule over every input.
func Scan(inputs []Input) []Finding {
	var out []Finding
	for _, in := range inputs {
		lines := strings.Split(in.Body, "\n")
		for i, line := range lines {
			for _, r := range rules {
				if !r.appliesTo(in.Kind) {
					continue
				}
				m := r.Pattern.FindString(line)
				if m == "" {
					continue
				}
				if r.Confirm != nil && !r.Confirm(m) {
					continue
				}
				out = append(out, Finding{
					Rule: r.ID, Severity: r.Severity, Where: in.Name,
					Line: i + 1, Excerpt: excerpt(r, m), Detail: r.Detail,
					Fix: r.Fix, Controls: r.Controls, OWASP: r.OWASP,
				})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rank(out[i].Severity) != rank(out[j].Severity) {
			return rank(out[i].Severity) > rank(out[j].Severity)
		}
		if out[i].Where != out[j].Where {
			return out[i].Where < out[j].Where
		}
		return out[i].Line < out[j].Line
	})
	return out
}

func (r Rule) appliesTo(k Kind) bool {
	if len(r.Kinds) == 0 {
		return true
	}
	for _, want := range r.Kinds {
		if want == k {
			return true
		}
	}
	return false
}

// excerpt truncates a match, and masks it entirely when the rule is about a
// credential.
//
// Printing the secret would copy it into the CI log, which is read by more
// people than the file it came from and kept longer. Enough is shown to find
// the line; nothing is shown that could be used.
func excerpt(r Rule, m string) string {
	if strings.HasPrefix(r.ID, "secret.") {
		if i := strings.IndexAny(m, "=:"); i > 0 && i < len(m)-1 {
			return strings.TrimSpace(m[:i+1]) + " <redacted>"
		}
		return "<redacted>"
	}
	m = strings.TrimSpace(m)
	if len(m) > 90 {
		return m[:87] + "..."
	}
	return m
}

// Worst returns the highest severity present, for an exit code.
func Worst(f []Finding) Severity {
	worst := Severity("")
	for _, x := range f {
		if rank(x.Severity) > rank(worst) {
			worst = x.Severity
		}
	}
	return worst
}

// AtLeast filters by severity, so CI can fail on high and log the rest.
func AtLeast(f []Finding, min Severity) []Finding {
	var out []Finding
	for _, x := range f {
		if rank(x.Severity) >= rank(min) {
			out = append(out, x)
		}
	}
	return out
}

// entropy is Shannon entropy in bits per character.
//
// Used only to confirm a match that already looks like a credential
// assignment. On its own it is a bad signal: a hash, an identifier and a
// base64 thumbnail all score highly, and a scanner that reports those is one
// somebody turns off — which costs more than the rule was ever worth.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]float64
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// looksSecret confirms a credential-shaped assignment.
func looksSecret(match string) bool {
	i := strings.IndexAny(match, "=:")
	if i < 0 {
		return true // the rule matched a whole credential format, not an assignment
	}
	value := strings.Trim(strings.TrimSpace(match[i+1:]), `"'`+"`")
	if len(value) < 16 {
		return false
	}
	// Placeholders. Documentation and templates are full of these, and a
	// scanner that reports them teaches people to ignore it.
	lower := strings.ToLower(value)
	for _, p := range []string{
		"example", "changeme", "your-", "xxx", "todo", "placeholder", "redacted",
		"<", "{{", "${", "...", "abc123", "secret", "password",
	} {
		if strings.Contains(lower, p) {
			return false
		}
	}
	return entropy(value) > 3.5
}

func fmtRule(id string) string { return fmt.Sprintf("codescan.%s", id) }
