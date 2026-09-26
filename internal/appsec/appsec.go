// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package appsec takes what a code scanner found and does the four things the
// scanner did not.
//
// Distinct from internal/codescan, which is this project's own linter for its
// own templates. This one reads the output of whatever the organisation
// already runs — Semgrep, CodeQL, a secret scanner, a dependency scanner —
// and is about the queue rather than about the analysis.
//
// # The arithmetic
//
// OX Security's 2026 application security benchmark puts the average
// enterprise at 865,398 security alerts a year, of which 795 are critical
// after exploitability analysis. One in one thousand and eighty-eight.
//
// A 2025 Ghost Security study measured a 91% false positive rate for static
// analysis on open source code. Untuned tools run 30 to 60 per cent; a
// well-tuned deployment with custom rules reaches 10 to 20. Developers stop
// adopting a tool above about 15 to 20 per cent, so the well-tuned case is
// the edge of tolerable and the ordinary case is four times past it.
//
// This package does not scan and does not claim to reduce that rate. Writing
// a static analyser with no dependencies would produce something worse than
// the tools that already exist, and a package claiming to fix false positives
// by reading their output would be claiming to know which of them were wrong.
//
// What it does is the part every scanner leaves undone.
//
// # An alert that moved is not a new alert
//
// Scanners key a finding on rule, path and line. A reformat closes four
// hundred findings and opens four hundred new ones; a file rename does the
// same; so does adding an import at the top. The queue churns, the ages
// reset, and every metric about how long things stay open is measuring
// whitespace.
//
// SARIF has carried partialFingerprints since 2.1.0 for exactly this, and
// most tools emit nothing in it. Where one does, it is used. Where one does
// not, a fingerprint is computed from the rule, the enclosing symbol and the
// normalised text — none of which change when the file does.
//
// # New is the only policy anybody sustains
//
// Every codebase has a baseline of debt. A gate on total debt means nothing
// merges and is switched off within a month; a gate on what this change
// introduced is one a team can live with for years. So the useful output is
// not the queue, it is the difference between the queue and the baseline.
//
// # A secret is not fixed by deleting the line
//
// The one that matters most and the one every tool gets wrong. A credential
// committed to a repository is in the history. If the branch was ever pushed
// it is on a server, in every clone, in the CI cache and in whatever mirrors
// the organisation runs. Removing the line changes the working tree and
// nothing else.
//
// The only fix is rotation. So a secret alert cannot be closed by
// disappearing: a secret that has gone from the working tree is reported as
// gone and not fixed, and it stays in the register until somebody records
// that the credential was replaced.
package appsec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Kind is what a scanner found.
type Kind string

const (
	// Weakness is a flaw in code somebody wrote: the SAST case, and the one
	// the false positive figures are about.
	Weakness Kind = "weakness"
	// Secret is a credential in the source.
	//
	// A different thing from a weakness in every way that matters. It is a
	// fact rather than an inference — the string either is a credential or
	// is not — so the false positive rate is near zero where the scanner
	// verified it, and it is the one kind that cannot be fixed by editing
	// the file.
	Secret Kind = "secret"
	// Dependency is a known weakness in something installed. It belongs to
	// internal/vuln once it has an advisory; here it is what the scanner
	// said.
	Dependency Kind = "dependency"
	// Configuration is infrastructure or pipeline definition.
	Configuration Kind = "configuration"
)

// Kinds lists them.
func Kinds() []Kind {
	return []Kind{Weakness, Secret, Dependency, Configuration}
}

func (k Kind) known() bool {
	for _, x := range Kinds() {
		if x == k {
			return true
		}
	}
	return false
}

// Alert is one thing a scanner reported.
type Alert struct {
	// Tool is what found it, and Rule which of its rules.
	Tool string `json:"tool"`
	Rule string `json:"rule"`
	Kind Kind   `json:"kind"`
	// Message is the scanner's own wording.
	Message  string             `json:"message,omitempty"`
	Severity telemetry.Severity `json:"severity,omitempty"`

	Path string `json:"path"`
	Line int    `json:"line,omitempty"`
	// Symbol is the enclosing function or class, where the scanner said.
	// Part of the fingerprint, because it does not move when the file does.
	Symbol string `json:"symbol,omitempty"`
	// Snippet is the offending text. Normalised before fingerprinting, and
	// removed for a secret — see Redact.
	Snippet string `json:"snippet,omitempty"`

	// Given is the scanner's own fingerprint, from SARIF
	// partialFingerprints or equivalent. Preferred over anything computed
	// here: the tool knows more about what it matched than this does.
	Given string `json:"given,omitempty"`
	// Pinned is a fingerprint already computed for this alert, carried
	// verbatim.
	//
	// Set by Redact, which removes the text a fingerprint is derived from.
	// Without it, redacting a secret changed its identity — which is the
	// churn this package exists to prevent, occurring in this package.
	Pinned string `json:"pinned,omitempty"`

	// Introduced is when the line first appeared, and By who, from blame.
	Introduced time.Time `json:"introduced,omitempty"`
	By         string    `json:"by,omitempty"`

	// Verified marks a secret the scanner confirmed is live by using it.
	// The difference between a string that looks like a token and a token.
	Verified bool `json:"verified,omitempty"`
	// Repository is which one, for a deployment scanning several.
	Repository string `json:"repository,omitempty"`
}

// Validate refuses an alert nothing can be done with.
func (a Alert) Validate() error {
	if strings.TrimSpace(a.Tool) == "" {
		return fmt.Errorf(
			"an alert names no tool. A queue nobody can trace to what " +
				"raised it cannot be verified, re-run, or switched off when " +
				"it is wrong")
	}
	if strings.TrimSpace(a.Rule) == "" {
		return fmt.Errorf("%s reported an alert with no rule", a.Tool)
	}
	if !a.Kind.known() {
		return fmt.Errorf("%s/%s: %q is not a kind", a.Tool, a.Rule, a.Kind)
	}
	if strings.TrimSpace(a.Path) == "" {
		return fmt.Errorf("%s/%s points at no file", a.Tool, a.Rule)
	}
	if a.Line < 0 {
		return fmt.Errorf("%s/%s is at line %d", a.Tool, a.Rule, a.Line)
	}
	return nil
}

// Fingerprint identifies this finding across moves.
//
// The scanner's own where it gave one, because the tool knows what it
// matched. Otherwise the rule, the enclosing symbol and the normalised text —
// none of which change when a file is renamed, reformatted, or has an import
// added at the top.
//
// Not the line number, and not the path unless there is nothing else. Every
// scanner keys on both, which is why a reformat closes four hundred findings
// and opens four hundred new ones.
func (a Alert) Fingerprint() string {
	if pinned := strings.TrimSpace(a.Pinned); pinned != "" {
		return pinned
	}
	if given := strings.TrimSpace(a.Given); given != "" {
		return "g:" + short(a.Tool+"\x00"+a.Rule+"\x00"+given)
	}
	parts := []string{a.Tool, a.Rule, a.Repository}
	if s := strings.TrimSpace(a.Symbol); s != "" {
		parts = append(parts, s)
	} else {
		// No symbol. The path is the next most stable thing, and it is
		// used deliberately rather than silently so that a tool emitting no
		// symbol is known to produce fingerprints a rename breaks.
		parts = append(parts, a.Path)
	}
	if n := normalise(a.Snippet); n != "" {
		parts = append(parts, n)
	}
	return "c:" + short(strings.Join(parts, "\x00"))
}

// Stable reports whether this alert's identity survives a file being moved.
func (a Alert) Stable() bool {
	return strings.TrimSpace(a.Pinned) != "" ||
		strings.TrimSpace(a.Given) != "" ||
		strings.TrimSpace(a.Symbol) != ""
}

// normalise reduces a line to what it means.
//
// Whitespace collapsed and nothing else. Not case, because identifiers are
// case-sensitive in every language this will see; not quotes, because the
// string is often the point.
func normalise(s string) string { return strings.Join(strings.Fields(s), " ") }

func short(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

// Redact returns the alert with a secret's text removed.
//
// A queue of secret findings that quotes the secrets is a second copy of
// them, in a file with wider access than the repository. The fingerprint is
// computed first and carried, so the finding is still tracked.
func (a Alert) Redact() Alert {
	if a.Kind != Secret {
		return a
	}
	out := a
	out.Pinned = a.Fingerprint()
	out.Snippet = ""
	out.Message = redactMessage(a.Message)
	return out
}

// redactMessage keeps a scanner's wording and drops anything long enough to
// be the credential it is describing.
func redactMessage(in string) string {
	fields := strings.Fields(in)
	for i, f := range fields {
		if len(f) >= 20 {
			fields[i] = "[redacted]"
		}
	}
	return strings.Join(fields, " ")
}

// Rotation records that a credential found in the source was replaced.
//
// The only thing that closes a secret. Removing the line changes the working
// tree; the commit is still in the history, on the server, in every clone and
// in the CI cache.
type Rotation struct {
	// Secret is the alert's fingerprint.
	Secret string `json:"secret"`
	// Where is what was rotated, in words: "the Stripe live key", "the
	// deploy user's password".
	Where string     `json:"where"`
	At    time.Time  `json:"at"`
	By    string     `json:"by"`
	Kind  audit.Kind `json:"kind,omitempty"`
	// Because is what was done, in one line.
	Because string `json:"because"`
	// Purged says the history was rewritten as well.
	//
	// Recorded and deliberately not required. Rewriting history breaks every
	// clone and every fork and is often the wrong call; the credential being
	// dead is what matters, and a tool that demanded a purge before closing
	// the finding would be demanding the more dangerous of the two.
	Purged bool `json:"purged,omitempty"`
}

// Validate refuses a rotation that does not close anything.
func (r Rotation) Validate() error {
	if strings.TrimSpace(r.Secret) == "" {
		return fmt.Errorf("a rotation needs the finding it closes")
	}
	if strings.TrimSpace(r.Where) == "" {
		return fmt.Errorf(
			"%s does not say what was rotated. Six months from now the "+
				"question is not whether somebody did something, it is "+
				"which credential is dead", r.Secret)
	}
	if r.At.IsZero() {
		return fmt.Errorf("%s has no date", r.Secret)
	}
	if strings.TrimSpace(r.By) == "" {
		return fmt.Errorf("%s names nobody", r.Secret)
	}
	if r.Kind == audit.KindAI {
		return fmt.Errorf(
			"%s was recorded by a model. Whether a credential is actually "+
				"dead is a fact about another system, and asserting it is "+
				"how a finding gets closed over a key that still works",
			r.Secret)
	}
	if strings.TrimSpace(r.Because) == "" {
		return fmt.Errorf("%s records nothing about what was done", r.Secret)
	}
	return nil
}

// Record turns a rotation into an audit entry.
func (r Rotation) Record() audit.Record {
	detail := map[string]string{
		"finding": r.Secret, "where": r.Where, "because": r.Because,
	}
	if r.Purged {
		detail["purged"] = "true"
	}
	return audit.Record{
		Action: "appsec.rotated", Resource: "/secret/" + r.Secret,
		Outcome: audit.Success, Principal: r.By, Kind: r.Kind,
		Verified: r.Kind != audit.KindUnknown, Detail: detail,
	}
}

// Baseline is the fingerprints a codebase already carried, and when each was
// first seen.
type Baseline map[string]time.Time

// Of builds a baseline from a run.
func Of(alerts []Alert, at time.Time) Baseline {
	out := Baseline{}
	for _, a := range alerts {
		f := a.Fingerprint()
		when := a.Introduced
		if when.IsZero() {
			when = at
		}
		if existing, seen := out[f]; !seen || when.Before(existing) {
			out[f] = when
		}
	}
	return out
}

// Has reports whether the baseline already carried this alert.
func (b Baseline) Has(a Alert) bool {
	_, ok := b[a.Fingerprint()]
	return ok
}

// Keys returns the fingerprints, sorted.
func (b Baseline) Keys() []string {
	out := make([]string, 0, len(b))
	for k := range b {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
