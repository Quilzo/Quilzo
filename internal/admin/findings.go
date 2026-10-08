// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// The queue, on a screen.
//
// Detections, vulnerabilities, failed controls, vendor and questionnaire
// gaps and weaknesses in code are one kind of thing — internal/finding makes
// that argument and this is the screen it was waiting for. Before it, the
// only way to see what was wrong was a command that printed twenty lines, and
// the only way to decide anything was a second command that took the id from
// the first.
//
// Three things this screen does that most queues do not:
//
//   - It separates "nothing is wrong" from "nothing has looked". A register
//     no producer has ever written is not an empty queue, and the screen
//     says which it is.
//   - It says, on every finding resting on log text, that a person decides.
//     Log text is written by whoever can reach the log, and that includes
//     whoever is being detected.
//   - A verdict is a verdict. False positive and benign are recorded as such
//     rather than as "closed", because they are what a rule's precision is
//     measured from.

// Findings is the finding register, supplied by whatever wired this server.
type Findings struct {
	// Queue returns every finding with decisions applied, ranked, and
	// whether any producer has ever written the register.
	Queue func(now time.Time) (q []finding.Finding, produced bool, err error)
	// History returns the decisions about one finding, oldest first.
	History func(id string) ([]finding.Decision, error)
	// Decide records a decision in the audit log. It is the whole of what a
	// decision is: the register has no field for it.
	Decide func(finding.Decision) error
	// Proposals returns what agents have suggested for one finding, newest
	// first. Suggestions only: nothing here changes a state.
	Proposals func(id string) ([]finding.Proposal, error)
}

// who names a principal from the audit log when this store knows them.
func (s *Server) who(pseudonym string) string {
	if s.ResolvePrincipal != nil {
		if name := s.ResolvePrincipal(pseudonym); name != "" {
			return name
		}
	}
	return pseudonym
}

// severityName is how a severity reads, and the class its chip takes.
func severityName(s telemetry.Severity) string {
	switch s {
	case telemetry.SeverityInfo:
		return "info"
	case telemetry.SeverityLow:
		return "low"
	case telemetry.SeverityMedium:
		return "medium"
	case telemetry.SeverityHigh:
		return "high"
	case telemetry.SeverityCritical, telemetry.SeverityFatal:
		return "critical"
	}
	return "unknown"
}

// stateWords is what each state means, in the words the form offers it.
var stateWords = map[finding.State]string{
	finding.Open:          "Open — nobody has decided yet",
	finding.Triaged:       "Triaged — looked at, and it is real",
	finding.Fixed:         "Fixed — the underlying thing changed",
	finding.FalsePositive: "False positive — what it says did not happen",
	finding.Benign:        "Benign — it happened, and it is expected",
	finding.Accepted:      "Accepted — a risk carried on purpose, until a date",
	finding.Stale:         "Stale — stopped being reported, cause unknown",
}

// stateWord is a state's short name for a filter: the words before the
// dash, "False positive" rather than "false-positive".
func stateWord(st finding.State) string {
	if w, ok := stateWords[st]; ok {
		name, _, _ := strings.Cut(w, " — ")
		return name
	}
	return string(st)
}

// findingRow is one finding as the queue shows it.
type findingRow struct {
	finding.Finding
	Sev      string
	Age      string
	Why      string
	Person   bool
	Closed   bool
	Expired  bool
	Evidence []evidenceRow
}

type evidenceRow struct {
	finding.Evidence
	When string
}

func rowOf(f finding.Finding, now time.Time) findingRow {
	r := findingRow{
		Finding: f, Sev: severityName(f.Severity), Age: plainAge(f.Age(now)),
		Why: f.Why(now), Person: f.NeedsAPerson() != "",
		Closed: f.State.Closed(), Expired: f.Expired(now),
	}
	for _, e := range f.Evidence {
		r.Evidence = append(r.Evidence, evidenceRow{Evidence: e,
			When: e.At.UTC().Format("2006-01-02 15:04")})
	}
	return r
}

// plainAge says how long, the way a person would.
func plainAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// facet is one filter chip.
type facet struct {
	Label string
	Href  string
	Count int
	On    bool
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	data := map[string]any{
		"Nav": "findings", "Title": "Findings", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
	}
	if s.Findings == nil || s.Findings.Queue == nil {
		data["Unavailable"] = "This build was started without a finding " +
			"register. That is not an empty queue: a screen showing nothing " +
			"here would say nothing is wrong, and this build cannot see " +
			"whether anything is."
		s.render(w, r, "findings.html", data)
		return
	}
	now := time.Now().UTC()
	all, produced, err := s.Findings.Queue(now)
	if err != nil {
		data["Unavailable"] = "The finding register could not be read: " +
			err.Error() + ". A register that cannot be read is not one with " +
			"nothing in it."
		s.render(w, r, "findings.html", data)
		return
	}
	data["Produced"] = produced

	q := r.URL.Query()
	kind, state := finding.Kind(q.Get("kind")), q.Get("state")
	sev := q.Get("severity")

	// Counts for the chips are over what the other filters leave, so a chip
	// says how many a click would show.
	inState := func(f finding.Finding) bool {
		switch state {
		case "":
			// Trial-ring findings are kept out of the working queue;
			// that is what the ring is for.
			return !f.State.Closed() && !f.Trial
		case "trial":
			return f.Trial && !f.State.Closed()
		case "all":
			return true
		}
		return string(f.State) == state
	}
	var rows []findingRow
	byKind := map[finding.Kind]int{}
	byState := map[string]int{}
	bySev := map[string]int{}
	var open, person, unowned, expired int
	for _, f := range all {
		if !f.State.Closed() && !f.Trial {
			open++
			if f.NeedsAPerson() != "" {
				person++
			}
			if strings.TrimSpace(f.Owner) == "" {
				unowned++
			}
			bySev[severityName(f.Severity)]++
		}
		if f.Expired(now) {
			expired++
		}
		if (kind == "" || f.Kind == kind) && (sev == "" || severityName(f.Severity) == sev) {
			byState[string(f.State)]++
			switch {
			case f.State.Closed():
			case f.Trial:
				byState["trial"]++
			default:
				byState[""]++
			}
			byState["all"]++
		}
		if !inState(f) || (sev != "" && severityName(f.Severity) != sev) {
			continue
		}
		byKind[f.Kind]++
		if kind != "" && f.Kind != kind {
			continue
		}
		rows = append(rows, rowOf(f, now))
	}

	link := func(k, st, sv string) string {
		v := url.Values{}
		if k != "" {
			v.Set("kind", k)
		}
		if st != "" {
			v.Set("state", st)
		}
		if sv != "" {
			v.Set("severity", sv)
		}
		if len(v) == 0 {
			return "/findings"
		}
		return "/findings?" + v.Encode()
	}
	kinds := []facet{{Label: "Every kind", Href: link("", state, sev),
		Count: sumCounts(byKind), On: kind == ""}}
	for _, k := range finding.Kinds() {
		if byKind[k] == 0 && kind != k {
			continue
		}
		kinds = append(kinds, facet{Label: kindLabel(k),
			Href: link(string(k), state, sev), Count: byKind[k], On: kind == k})
	}
	states := []facet{
		{Label: "Needs attention", Href: link(string(kind), "", sev),
			Count: byState[""], On: state == ""},
	}
	for _, st := range finding.States() {
		if byState[string(st)] == 0 && state != string(st) {
			continue
		}
		states = append(states, facet{Label: stateWord(st),
			Href: link(string(kind), string(st), sev), Count: byState[string(st)],
			On: state == string(st)})
	}
	if byState["trial"] > 0 || state == "trial" {
		states = append(states, facet{Label: "From rules on trial",
			Href: link(string(kind), "trial", sev), Count: byState["trial"],
			On: state == "trial"})
	}
	states = append(states, facet{Label: "Everything",
		Href: link(string(kind), "all", sev), Count: byState["all"], On: state == "all"})

	data["Rows"] = rows
	data["Kinds"], data["States"] = kinds, states
	data["Open"], data["Person"] = open, person
	data["Unowned"], data["Expired"] = unowned, expired
	data["BySev"] = []facet{
		{Label: "critical", Count: bySev["critical"], Href: link(string(kind), state, "critical"), On: sev == "critical"},
		{Label: "high", Count: bySev["high"], Href: link(string(kind), state, "high"), On: sev == "high"},
		{Label: "medium", Count: bySev["medium"], Href: link(string(kind), state, "medium"), On: sev == "medium"},
		{Label: "low", Count: bySev["low"] + bySev["info"] + bySev["unknown"], Href: link(string(kind), state, "low"), On: sev == "low"},
	}
	data["Filtered"] = kind != "" || state != "" || sev != ""
	data["Total"] = len(all)
	s.render(w, r, "findings.html", data)
}

func sumCounts(m map[finding.Kind]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// kindLabel is a kind as a person names it.
func kindLabel(k finding.Kind) string {
	switch k {
	case finding.FromDetection:
		return "Detections"
	case finding.FromVulnerability:
		return "Vulnerabilities"
	case finding.FromControl:
		return "Controls"
	case finding.FromQuestionnaire:
		return "Questionnaires"
	case finding.FromVendor:
		return "Vendors"
	case finding.FromCode:
		return "Code"
	}
	return string(k)
}

// handleFinding shows one finding: why it is here, its evidence, what has
// been decided, and the form for deciding.
func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	if s.Findings == nil || s.Findings.Queue == nil {
		http.Redirect(w, r, "/findings", http.StatusSeeOther)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/findings/")
	if id == "" {
		http.Redirect(w, r, "/findings", http.StatusSeeOther)
		return
	}
	now := time.Now().UTC()
	all, _, err := s.Findings.Queue(now)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var found *finding.Finding
	for i := range all {
		if all[i].ID == id {
			found = &all[i]
			break
		}
	}
	if found == nil {
		http.NotFound(w, r)
		return
	}
	var history []finding.Decision
	if s.Findings.History != nil {
		if history, err = s.Findings.History(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	type decided struct {
		finding.Decision
		When, Until string
	}
	var hist []decided
	for _, d := range history {
		d.By = s.who(d.By)
		h := decided{Decision: d, When: d.At.UTC().Format("2006-01-02 15:04")}
		if !d.Until.IsZero() {
			h.Until = d.Until.UTC().Format("2006-01-02")
		}
		hist = append(hist, h)
	}
	// Newest first on screen: the question is usually "what is the latest".
	sort.SliceStable(hist, func(i, j int) bool { return hist[i].At.After(hist[j].At) })

	type option struct {
		Value, Words string
		On           bool
	}
	var opts []option
	for _, st := range finding.States() {
		opts = append(opts, option{Value: string(st), Words: stateWords[st],
			On: st == found.State})
	}
	type proposed struct {
		finding.Proposal
		When string
	}
	var props []proposed
	if s.Findings.Proposals != nil {
		ps, perr := s.Findings.Proposals(id)
		if perr != nil {
			http.Error(w, perr.Error(), http.StatusInternalServerError)
			return
		}
		for _, pr := range ps {
			pr.By, pr.For = s.who(pr.By), s.who(pr.For)
			props = append(props, proposed{Proposal: pr,
				When: pr.At.UTC().Format("2006-01-02 15:04")})
		}
	}
	row := rowOf(*found, now)
	data := map[string]any{
		"Nav": "findings", "Title": found.Title, "Principal": p,
		"F": row, "History": hist, "Options": opts, "Proposals": props,
		"NeedsAPerson": found.NeedsAPerson(),
		"CanDecide":    s.mayDecide(p),
		"Message":      r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"MinUntil": now.Add(24 * time.Hour).Format("2006-01-02"),
	}
	if found.First.Equal(found.Last) {
		data["Span"] = found.First.UTC().Format("2006-01-02 15:04")
	} else {
		data["Span"] = found.First.UTC().Format("2006-01-02 15:04") + " to " +
			found.Last.UTC().Format("2006-01-02 15:04")
	}
	s.render(w, r, "finding.html", data)
}

// mayDecide is whether this person may record a decision.
//
// Publish, as on the command line: deciding a risk is acceptable is a
// statement the organisation stands behind.
func (s *Server) mayDecide(p principal) bool {
	if p.Limits.ReadOnly {
		return false
	}
	return s.mayUse(p, auth.ActPublish, "/")
}

// handleFindingDecide records a decision from the form.
func (s *Server) handleFindingDecide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "a decision is made with a POST", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActPublish, "/") {
		return
	}
	if s.Findings == nil || s.Findings.Decide == nil {
		http.Error(w, "this build cannot record decisions",
			http.StatusServiceUnavailable)
		return
	}
	id := strings.TrimSpace(r.FormValue("id"))
	back := "/findings/" + url.PathEscape(id) + "?"
	// Only a finding that exists can be decided. The command line takes any
	// id, which is how a typo becomes a decision about nothing that sits in
	// the log for ever.
	all, _, err := s.Findings.Queue(time.Now().UTC())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	exists := false
	for _, f := range all {
		if f.ID == id {
			exists = true
			break
		}
	}
	if !exists {
		http.NotFound(w, r)
		return
	}
	d := finding.Decision{
		Finding: id, At: time.Now().UTC(), By: p.Name, Kind: audit.KindHuman,
		To:      finding.State(r.FormValue("to")),
		Because: strings.TrimSpace(r.FormValue("because")),
	}
	if u := strings.TrimSpace(r.FormValue("until")); u != "" {
		t, perr := time.Parse("2006-01-02", u)
		if perr != nil {
			http.Redirect(w, r, back+"e="+url.QueryEscape(
				"The date should look like 2026-12-31."), http.StatusSeeOther)
			return
		}
		d.Until = t.UTC()
	}
	if d.To != finding.Accepted {
		d.Until = time.Time{}
	}
	if err := d.Validate(); err != nil {
		http.Redirect(w, r, back+"e="+url.QueryEscape(err.Error()),
			http.StatusSeeOther)
		return
	}
	if err := s.Findings.Decide(d); err != nil {
		http.Redirect(w, r, back+"e="+url.QueryEscape(
			"The decision was not recorded: "+err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, back+"m="+url.QueryEscape(
		"Recorded as "+string(d.To)+" in the audit log."), http.StatusSeeOther)
}
