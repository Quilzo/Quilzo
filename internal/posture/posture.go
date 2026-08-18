// Package posture continuously checks the running configuration for the
// mistakes that actually get people compromised.
//
// # Why this exists
//
// OWASP moved Security Misconfiguration from fifth place to **second** in the
// 2025 Top 10, and reported that essentially every application they tested
// carried at least one instance. Their explanation is the part worth acting on:
// continuous deployment without continuous checking creates an exposure window
// that widens with deployment cadence. A configuration is not a thing you get
// right once. It drifts, because people grant access to unblock a colleague and
// nobody takes it back.
//
// NIST SP 800-137 names the same idea from the defensive side: information
// security continuous monitoring, meaning ongoing awareness of whether controls
// are still effective, rather than an assessment performed annually and believed
// for a year.
//
// So this runs on every request that touches the admin, on every CLI invocation
// that changes configuration, and on a timer. Not when someone remembers.
//
// # Why the rules are data and the checks are pure
//
// Every rule receives a State and returns findings. The package performs no I/O
// at all: it cannot read a file, open a socket or shell out. That is deliberate
// twice over. It makes each rule testable by construction, and it means a rule
// cannot be tricked into reading something it was not meant to — a scanner with
// filesystem access is a file-disclosure primitive wearing a badge.
//
// The caller assembles State and hands it over. What the scanner sees is
// therefore exactly what the caller chose to show it, which is a boundary you
// can audit by reading one function.
//
// # Why findings expire rather than accumulate
//
// A scanner that cries wolf gets muted, and a muted scanner is worse than none
// because its silence is mistaken for health. Two decisions follow. Severity is
// assigned by what an attacker gains, not by how alarming the rule sounds. And
// suppressions carry an expiry date, because a permanent exception is how a
// finding becomes invisible — an expired suppression is itself reported, so
// "we accepted that risk" stays a decision somebody renews rather than a thing
// that happened once in 2024.
package posture

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/schema"
)

// Severity is what an attacker gains, not how the rule sounds.
type Severity string

const (
	// Critical: a control that is supposed to be enforced is not, and the gap
	// is directly reachable. Someone can act as an administrator, or the audit
	// record can be edited without detection.
	Critical Severity = "critical"
	// High: a real path to privilege or to data, needing one more step.
	High Severity = "high"
	// Medium: weakens a defence without opening one by itself. Defence in depth
	// is exactly the set of controls whose individual absence is Medium.
	Medium Severity = "medium"
	// Low: hygiene. Worth fixing on a normal day, not worth waking anyone.
	Low Severity = "low"
	// Info: an observation with no security claim attached.
	Info Severity = "info"
)

var severityRank = map[Severity]int{
	Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1,
}

// AtLeast compares severities.
func (s Severity) AtLeast(other Severity) bool {
	return severityRank[s] >= severityRank[other]
}

// Finding is one misconfiguration, in one place, right now.
type Finding struct {
	Rule     string   `json:"rule"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	// Resource is what the finding is about: a principal, a token id, a page.
	// It is part of the identity of the finding, so two stale tokens are two
	// findings rather than one that keeps changing its mind.
	Resource string `json:"resource,omitempty"`
	// Detail says what is true, in the specific. "3 tokens have no expiry" is a
	// summary; "token svc-deploy expires in 2031" is a fact somebody can act on.
	Detail string `json:"detail"`
	// Fix is the command that resolves it. A finding without a remedy is a
	// complaint, and people learn to scroll past complaints.
	Fix string `json:"fix,omitempty"`
	// Controls are the NIST SP 800-53 identifiers this maps to, which is what
	// turns a finding into evidence for an assessor rather than an opinion.
	Controls []string `json:"controls,omitempty"`
	// OWASP is the Top 10:2025 category.
	OWASP string `json:"owasp,omitempty"`
}

// ID is the stable identity of a finding: the same problem in the same place
// keeps the same id across scans, so "first seen" means something.
func (f Finding) ID() string {
	if f.Resource == "" {
		return f.Rule
	}
	return f.Rule + ":" + f.Resource
}

// FileFact is what the caller observed about a file on disk.
//
// A fact rather than a path, because the scanner does not open files. The
// caller stats them and reports; the rule reasons about what it was told.
// WeakenedSetting is a configuration value running below its default.
type WeakenedSetting struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Why      string `json:"why"`
	Reason   string `json:"reason,omitempty"`
	By       string `json:"by,omitempty"`
	Accepted bool   `json:"accepted"`
	Expired  bool   `json:"expired,omitempty"`
}

type FileFact struct {
	Path        string `json:"path"`
	Mode        uint32 `json:"mode"`
	Exists      bool   `json:"exists"`
	Description string `json:"description"`
	// SharedWithGroup marks a file that is meant to be group-readable,
	// because a second account has to read it and is deliberately not allowed
	// to write it. Without this the inspector flags the separated audit
	// deployment — the one this program recommends — and tells the operator to
	// chmod away the access that makes it work.
	SharedWithGroup bool `json:"shared_with_group,omitempty"`
}

// ServerFacts describe how the interfaces are exposed.
type ServerFacts struct {
	AdminAddr  string `json:"admin_addr"`
	PublicAddr string `json:"public_addr"`
	AdminTLS   bool   `json:"admin_tls"`
	PublicTLS  bool   `json:"public_tls"`
	// BehindProxy says a reverse proxy terminates TLS. It changes what a plain
	// HTTP listener means, and taking the operator's word for it is correct:
	// the alternative is a rule that cannot be satisfied by a correct
	// deployment, which teaches people to ignore the scanner.
	BehindProxy bool `json:"behind_proxy"`
}

// ContentFacts are the properties of what is published.
type ContentFacts struct {
	LivePages       []string `json:"live_pages"`
	UnmarkedPages   []string `json:"unmarked_pages"`
	StalePages      []string `json:"stale_pages"`
	RawTemplates    []string `json:"raw_templates"`
	BlockingA11y    int      `json:"blocking_a11y"`
	PublishedAt     int64    `json:"published_at,omitempty"`
	LastTimestamped int64    `json:"last_timestamped,omitempty"`
}

// AgentFacts describe the machine-facing surface.
type AgentFacts struct {
	// WriteOpsWithoutRole are MCP operations that change state without
	// declaring a required role.
	WriteOpsWithoutRole []string `json:"write_ops_without_role"`
	// Enabled says the MCP server is reachable at all.
	Enabled bool `json:"enabled"`
}

// ExtFacts describe the extension runner and what confines it.
type ExtFacts struct {
	// Registered is how many extensions this store runs.
	Registered int `json:"registered"`
	// Sandboxed says the host can confine them with the kernel.
	Sandboxed bool `json:"sandboxed"`
	// Why explains an absent sandbox, so the report can say which of the two
	// reasons applies — a kernel without Landlock and a build that cannot use
	// it need different answers from an operator.
	Why string `json:"why,omitempty"`
	// NetworkOpen says the sandbox does not bound what an extension can send.
	// True on a kernel below Landlock ABI 4, and reported separately from
	// Sandboxed because a filesystem-only sandbox is a real improvement and
	// not the whole control.
	NetworkOpen bool `json:"network_open"`
	// Checked distinguishes "no extensions" from "nobody looked". An absent
	// answer reported as a clean one is the failure this scanner exists to
	// avoid.
	Checked bool `json:"checked"`
}

// State is everything the scanner is allowed to see.
//
// Assembled by the caller. The scanner reads this and nothing else — there is
// no path from a rule to the filesystem, the network or the clock.
type State struct {
	Policy   *auth.Policy      `json:"-"`
	Tokens   *auth.TokenStore  `json:"-"`
	Types    *schema.Store     `json:"-"`
	Audit    []audit.Event     `json:"-"`
	Files    []FileFact        `json:"files"`
	Weakened []WeakenedSetting `json:"weakened,omitempty"`
	Server   ServerFacts       `json:"server"`
	Content  ContentFacts      `json:"content"`
	Agents   AgentFacts        `json:"agents"`
	Ext      ExtFacts          `json:"ext"`
	Now      time.Time         `json:"-"`
	Extra    map[string]string `json:"extra,omitempty"`
}

// Rule is one check.
type Rule struct {
	ID       string
	Title    string
	Severity Severity
	Controls []string
	OWASP    string
	// Why explains the consequence, not the rule. It is shown when someone asks
	// why a finding matters, and it is the difference between a scanner people
	// act on and one they argue with.
	Why   string
	Check func(State) []Finding
}

// Suppression silences a finding until a date.
//
// The expiry is required and bounded. An exception with no end is not an
// exception, it is a quiet decision to stop looking, and the person who made it
// will not be the person who inherits it.
type Suppression struct {
	ID      string `json:"id"`
	Reason  string `json:"reason"`
	By      string `json:"by"`
	Until   int64  `json:"until"`
	AddedAt int64  `json:"added_at"`
}

// MaxSuppression bounds how long a finding can be silenced.
//
// Ninety days is one quarter: long enough to schedule real work, short enough
// that the person who accepted the risk is still around to renew it.
const MaxSuppression = 90 * 24 * time.Hour

// Report is the result of one scan.
type Report struct {
	At         string          `json:"at"`
	Findings   []Finding       `json:"findings"`
	Suppressed []Finding       `json:"suppressed,omitempty"`
	Counts     map[string]int  `json:"counts"`
	Checked    int             `json:"rules_checked"`
	NotChecked []string        `json:"not_checked,omitempty"`
	Score      int             `json:"score"`
	Controls   map[string]bool `json:"controls,omitempty"`
}

// Worst returns the highest severity present.
func (r Report) Worst() Severity {
	worst := Info
	for _, f := range r.Findings {
		if f.Severity.AtLeast(worst) {
			worst = f.Severity
		}
	}
	if len(r.Findings) == 0 {
		return ""
	}
	return worst
}

// Scan runs every rule against the state.
//
// Rules are independent by construction: none can see another's findings, so
// there is no ordering to get wrong and no rule that quietly depends on an
// earlier one having run.
func Scan(s State, suppressions []Suppression) Report {
	if s.Now.IsZero() {
		// A zero clock would make every age-based rule report the entire epoch.
		// Refusing is better than reporting nonsense confidently.
		s.Now = time.Unix(0, 0)
	}

	silenced := map[string]Suppression{}
	for _, sp := range suppressions {
		if s.Now.Unix() < sp.Until {
			silenced[sp.ID] = sp
		}
	}

	rep := Report{
		At:       s.Now.UTC().Format(time.RFC3339),
		Counts:   map[string]int{},
		Controls: map[string]bool{},
		Checked:  len(rules),
	}

	for _, r := range rules {
		for _, f := range r.Check(s) {
			// The rule owns its metadata; a check that forgets to set severity
			// gets the rule's, so a finding can never arrive unclassified.
			if f.Rule == "" {
				f.Rule = r.ID
			}
			if f.Title == "" {
				f.Title = r.Title
			}
			if f.Severity == "" {
				f.Severity = r.Severity
			}
			if len(f.Controls) == 0 {
				f.Controls = r.Controls
			}
			if f.OWASP == "" {
				f.OWASP = r.OWASP
			}
			for _, c := range f.Controls {
				rep.Controls[c] = true
			}
			if _, quiet := silenced[f.ID()]; quiet {
				rep.Suppressed = append(rep.Suppressed, f)
				continue
			}
			rep.Findings = append(rep.Findings, f)
			rep.Counts[string(f.Severity)]++
		}
	}

	// An expired suppression is a finding of its own. Otherwise silencing
	// something once silences it forever, and the expiry is decoration.
	for _, sp := range suppressions {
		if s.Now.Unix() >= sp.Until {
			f := Finding{
				Rule:     "suppression.expired",
				Title:    "An accepted risk has come back",
				Severity: Low,
				Resource: sp.ID,
				Detail: fmt.Sprintf("%q was suppressed by %s until %s; that has passed",
					sp.ID, sp.By, time.Unix(sp.Until, 0).UTC().Format("2006-01-02")),
				Fix:      "quilzo posture suppress " + sp.ID + " --days 90 --reason ...",
				Controls: []string{"CA-5", "RA-5"},
			}
			rep.Findings = append(rep.Findings, f)
			rep.Counts[string(Low)]++
		}
	}

	// Say what could not be checked. A report that lists three findings and
	// stays silent about the eleven rules it skipped reads as "eleven things
	// are fine", which is the failure mode of every scanner anyone has learned
	// to distrust.
	rep.NotChecked = missing(s)

	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		return a.ID() < b.ID()
	})
	rep.Score = score(rep)
	return rep
}

// missing names the inputs the caller did not supply.
func missing(s State) []string {
	var out []string
	if s.Policy == nil {
		out = append(out, "access policy: no rules about who can do what were checked")
	}
	if s.Tokens == nil {
		out = append(out, "API tokens: no rules about credentials were checked")
	}
	if s.Audit == nil {
		out = append(out, "audit log: the chain was not verified")
	}
	if s.Types == nil {
		out = append(out, "content types: validation coverage was not checked")
	}
	if len(s.Files) == 0 {
		out = append(out, "file permissions: nothing on disk was inspected")
	}
	if _, ok := s.Extra["published_heads"]; !ok && len(s.Audit) > 0 {
		out = append(out, "log transparency: whether any audit head has been "+
			"published outside this machine was not checked")
	}
	return out
}

// score is 100 minus weighted findings and minus what could not be checked.
//
// A single number is what gets looked at on a dashboard, and it is also the
// easiest thing to game, so the weights are steep: one critical finding costs
// forty points, because a posture with a critical finding is not a good posture
// with one flaw. It is a bad posture.
//
// Unchecked areas are deducted too, and that is the part most scanners get
// wrong. Scoring 100 for a scan that looked at nothing is the single most
// misleading output this could produce — it converts absence of information
// into a claim of health. NIST SP 800-137 is a document about *awareness*;
// under it, not knowing is a deficiency rather than a neutral state, so it
// costs points like one.
func score(r Report) int {
	total := 100
	total -= 40 * r.Counts[string(Critical)]
	total -= 15 * r.Counts[string(High)]
	total -= 5 * r.Counts[string(Medium)]
	total -= 1 * r.Counts[string(Low)]
	total -= 10 * len(r.NotChecked)
	if total < 0 {
		return 0
	}
	return total
}

// Rules returns every rule, for documentation and for the dashboard.
func Rules() []Rule {
	out := make([]Rule, len(rules))
	copy(out, rules)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Explain returns the reasoning behind a rule.
func Explain(id string) (Rule, bool) {
	for _, r := range rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func days(d time.Duration) string {
	return fmt.Sprintf("%d %s", int(d.Hours()/24),
		plural(int(d.Hours()/24), "day", "days"))
}

func joinShort(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more",
		strings.Join(items[:max], ", "), len(items)-max)
}
