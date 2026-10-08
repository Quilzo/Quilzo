// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package estate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// The checks: what two tools disagreeing means.
//
// Every one of them needs at least two tools, because the findings a single
// console raises are already in that console. Each says what it needs, and
// when a tool it needs was not read — or not read to the end — it is listed
// as not run with the reason. A leaver check that ran without the device
// list would report no leavers with laptops, and that reads exactly like a
// company that has none.

// Live is how recently a device must have checked in to count as in use.
const Live = 30 * 24 * time.Hour

// Recent is how far back a phishing failure counts.
const Recent = 90 * 24 * time.Hour

// Check is one question asked across tools.
type Check struct {
	ID    string
	About string
	// Needs says whether this estate can answer it, and why not.
	Needs func(e *Estate) (bool, string)
	Run   func(e *Estate, now time.Time, add func(finding.Finding))
}

// Outcome is what a round of checks found, and what it could not look at.
type Outcome struct {
	Ran      []string          `json:"ran"`
	Skipped  map[string]string `json:"skipped,omitempty"`
	Findings []finding.Finding `json:"findings"`
}

// Checks lists them.
func Checks() []Check {
	return []Check{
		{ID: "leaver-device", About: "somebody a tool says has left, " +
			"whose device still checks in",
			Needs: needs(KindPerson, KindDevice), Run: leaverDevice},
		{ID: "leaver-still-active", About: "somebody one tool says has " +
			"left and another still has as current",
			Needs: needsTwo(KindPerson), Run: leaverStillActive},
		{ID: "training-disagrees", About: "training one tool calls " +
			"complete and another does not",
			Needs: needsTasksAndTraining, Run: trainingDisagrees},
		{ID: "not-in-training", About: "somebody current who is not in " +
			"the training platform at all",
			Needs: needsTasksAndTraining, Run: notInTraining},
		{ID: "phished-untrained", About: "somebody who failed a phishing " +
			"test recently and has finished no training since",
			Needs: needs(KindPhishing, KindTraining), Run: phishedUntrained},
		{ID: "unmanaged-device", About: "a device one tool knows by serial " +
			"number and another that manages its kind of machine does not",
			Needs: needsTwo(KindDevice), Run: unmanagedDevice},
		{ID: "owner-disagrees", About: "a device two tools say belongs to " +
			"two different people",
			Needs: needsTwo(KindDevice), Run: ownerDisagrees},
		{ID: "encryption-disagrees", About: "a device one tool says is " +
			"encrypted and another says is not",
			Needs: needsTwo(KindDevice), Run: encryptionDisagrees},
	}
}

// Evaluate runs every check the estate can answer.
func Evaluate(e *Estate, now time.Time) Outcome {
	out := Outcome{Skipped: map[string]string{}}
	seen := map[string]bool{}
	for _, c := range Checks() {
		if ok, why := c.Needs(e); !ok {
			out.Skipped[c.ID] = why
			continue
		}
		out.Ran = append(out.Ran, c.ID)
		source := "estate/" + c.ID
		c.Run(e, now, func(f finding.Finding) {
			f.Kind = finding.FromControl
			f.Source = source
			f.State = finding.Open
			f.First, f.Last, f.Seen = now, now, 1
			f.ID = finding.Key(f.Kind, f.Source, f.Entity)
			if seen[f.ID] {
				return
			}
			seen[f.ID] = true
			out.Findings = append(out.Findings, f)
		})
	}
	sort.Slice(out.Findings, func(i, j int) bool {
		return out.Findings[i].ID < out.Findings[j].ID
	})
	return out
}

func needs(kinds ...Kind) func(*Estate) (bool, string) {
	return func(e *Estate) (bool, string) {
		for _, k := range kinds {
			if len(e.With(k)) == 0 {
				return false, fmt.Sprintf("no tool was read completely for "+
					"%s records", k)
			}
		}
		return true, ""
	}
}

func needsTwo(k Kind) func(*Estate) (bool, string) {
	return func(e *Estate) (bool, string) {
		if n := len(e.With(k)); n < 2 {
			return false, fmt.Sprintf("it compares two tools and %d was "+
				"read completely for %s records", n, k)
		}
		return true, ""
	}
}

// taskTools are the tools that report a training task per person, and
// trainingTools those that list enrolments. The comparison needs one of
// each, and they must be different tools.
func taskTools(e *Estate) []string {
	var out []string
	for _, src := range e.With(KindPerson) {
		for _, ind := range e.People {
			if s, from := ind.Task("training"); s != "" && from == src {
				out = append(out, src)
				break
			}
		}
	}
	return out
}

func needsTasksAndTraining(e *Estate) (bool, string) {
	tasks, training := taskTools(e), e.With(KindTraining)
	for _, t := range tasks {
		for _, tr := range training {
			if t != tr {
				return true, ""
			}
		}
	}
	return false, "it needs a tool that tracks each person's training task " +
		"and a different tool that lists their enrolments, both read completely"
}

// evidence is one line of what the tools said. Always tainted: names and
// titles in it were typed by people using those tools.
func evidence(now time.Time, source, what string) []finding.Evidence {
	return []finding.Evidence{{At: now, Source: source, What: what,
		Tainted: true}}
}

func since(d time.Duration) string {
	switch {
	case d < time.Hour:
		return "within the hour"
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

// live reports whether a machine is in use: not removed, and checked in
// within Live by some tool.
func (m *Machine) live(now time.Time) bool {
	for _, r := range m.Records {
		if r.Removed {
			return false
		}
	}
	s := m.Seen()
	return !s.IsZero() && now.Sub(s) <= Live
}

func leaverDevice(e *Estate, now time.Time, add func(finding.Finding)) {
	for _, ind := range e.People {
		_, _, _, no := ind.Current()
		if len(no) == 0 {
			continue
		}
		for _, m := range ind.Devices {
			if !m.live(now) {
				continue
			}
			add(finding.Finding{
				Severity: telemetry.SeverityCritical,
				Entity:   m.Records[0].ID,
				Title: fmt.Sprintf("%s has left according to %s, and %s "+
					"still checked in %s", ind.Name(), strings.Join(no, " and "),
					m.Name(), since(now.Sub(m.Seen()))),
				Evidence: evidence(now, strings.Join(sortedKeys(m.Sources), ","),
					fmt.Sprintf("%s reports the person as no longer current. "+
						"%s reports %s (serial %s) as checking in. Neither "+
						"console is wrong and neither will raise this",
						strings.Join(no, ", "),
						strings.Join(sortedKeys(m.Sources), ", "), m.Name(),
						orNone(m.Serial))),
			})
		}
	}
}

func leaverStillActive(e *Estate, now time.Time, add func(finding.Finding)) {
	for _, ind := range e.People {
		_, _, yes, no := ind.Current()
		if len(yes) == 0 || len(no) == 0 {
			continue
		}
		for _, r := range ind.Records {
			if r.Active == nil || !*r.Active {
				continue
			}
			add(finding.Finding{
				Severity: telemetry.SeverityMedium,
				Entity:   r.ID,
				Title: fmt.Sprintf("%s has left according to %s and is still "+
					"active in %s", ind.Name(), strings.Join(no, " and "),
					r.ID.Issuer),
				Evidence: evidence(now, r.ID.Issuer, fmt.Sprintf(
					"%s lists the account as current. An account a leaver "+
						"still holds is one nobody is watching", r.ID.Issuer)),
			})
		}
	}
}

// liveTraining is an individual's course enrolments (not policies) from
// tools other than the one tracking their task.
func liveTraining(ind *Individual, notFrom string) []Training {
	var out []Training
	for _, t := range ind.Training {
		if !t.Policy && t.ID.Issuer != notFrom {
			out = append(out, t)
		}
	}
	return out
}

func trainingDisagrees(e *Estate, now time.Time, add func(finding.Finding)) {
	trainingTools := map[string]bool{}
	for _, t := range e.With(KindTraining) {
		trainingTools[t] = true
	}
	for _, ind := range e.People {
		known, current, _, _ := ind.Current()
		if known && !current {
			continue
		}
		status, from := ind.Task("training")
		if status == "" {
			continue
		}
		courses := liveTraining(ind, from)
		if len(courses) == 0 || !trainingTools[courses[0].ID.Issuer] {
			continue
		}
		var open []string
		for _, c := range courses {
			if !c.Done {
				open = append(open, c.Module)
			}
		}
		sort.Strings(open)
		platform := courses[0].ID.Issuer
		entity := ind.Records[0].ID
		switch {
		case status == "COMPLETE" && len(open) > 0:
			add(finding.Finding{
				Severity: telemetry.SeverityMedium, Entity: entity,
				Title: fmt.Sprintf("%s's training is complete in %s and %d "+
					"course(s) are unfinished in %s", ind.Name(), from,
					len(open), platform),
				Evidence: evidence(now, from+","+platform, fmt.Sprintf(
					"%s marks the training task complete. %s has not "+
						"finished: %s. The evidence an auditor reads says "+
						"done", from, platform, strings.Join(open, "; "))),
			})
		case status == "OVERDUE" && len(open) == 0:
			add(finding.Finding{
				Severity: telemetry.SeverityLow, Entity: entity,
				Title: fmt.Sprintf("%s finished every course in %s and %s "+
					"still says their training is overdue", ind.Name(),
					platform, from),
				Evidence: evidence(now, from+","+platform, fmt.Sprintf(
					"%s is not seeing completions from %s, so it reports "+
						"people overdue who are not, and its reminders go to "+
						"them", from, platform)),
			})
		}
	}
}

func notInTraining(e *Estate, now time.Time, add func(finding.Finding)) {
	for _, platform := range e.With(KindTraining) {
		if !e.Complete(platform, KindPerson) {
			// Absence from a tool whose people were not read completely
			// is not absence.
			continue
		}
		for _, ind := range e.People {
			known, current, _, _ := ind.Current()
			if !known || !current || ind.Sources[platform] {
				continue
			}
			status, from := ind.Task("training")
			if status == "" || from == platform {
				continue
			}
			add(finding.Finding{
				Severity: telemetry.SeverityMedium, Entity: ind.Records[0].ID,
				Title: fmt.Sprintf("%s is current in %s and not in %s at all",
					ind.Name(), from, platform),
				Evidence: evidence(now, from+","+platform, fmt.Sprintf(
					"Not enrolled is not the same as not finished: nothing "+
						"in %s will ever remind them, and their phishing "+
						"results do not exist", platform)),
			})
		}
	}
}

func phishedUntrained(e *Estate, now time.Time, add func(finding.Finding)) {
	for _, ind := range e.People {
		known, current, _, _ := ind.Current()
		if known && !current {
			continue
		}
		var worst Phish
		var at time.Time
		entered := false
		for _, p := range ind.Phishing {
			t, failed := p.Failed()
			if !failed || now.Sub(t) > Recent {
				continue
			}
			isEntry := !p.DataEntered.IsZero()
			if at.IsZero() || (isEntry && !entered) ||
				(isEntry == entered && t.After(at)) {
				worst, at, entered = p, t, isEntry
			}
		}
		if at.IsZero() {
			continue
		}
		trainedSince := false
		for _, t := range ind.Training {
			if !t.Policy && t.Done && t.Completed.After(at) {
				trainedSince = true
			}
		}
		if trainedSince {
			continue
		}
		sev, what := telemetry.SeverityMedium, "clicked a simulated phish"
		if entered {
			sev, what = telemetry.SeverityHigh, "entered data into a "+
				"simulated phish"
		}
		add(finding.Finding{
			Severity: sev, Entity: worst.User,
			Title: fmt.Sprintf("%s %s %s and has finished no training since",
				ind.Name(), what, since(now.Sub(at))),
			Evidence: evidence(now, worst.ID.Issuer, fmt.Sprintf(
				"Phishing test %s, result %s. A failure followed by "+
					"nothing is the pattern a real one exploits",
				orNone(worst.Test), worst.ID.Value)),
		})
	}
}

// family is the operating system family a machine is, for deciding which
// tools are expected to manage it.
func family(m *Machine) string {
	for _, r := range m.Records {
		low := strings.ToLower(r.OS + " " + r.Platform)
		for _, f := range []string{"windows", "mac", "linux", "ios",
			"ipados", "android", "chrome"} {
			if strings.Contains(low, f) {
				if f == "mac" && strings.Contains(low, "ios") {
					continue
				}
				return f
			}
		}
	}
	return ""
}

// covers reports which tools manage which families: a tool covers a family
// when it holds at least three of those machines and a tenth of all of them.
// Declared from the data rather than from a table of vendors, so an MDM
// that happens to hold one Mac is not taken to manage every Mac, and a new
// tool is judged by what it actually holds.
func covers(e *Estate) map[string]map[string]bool {
	count := map[string]map[string]int{}
	total := map[string]int{}
	for _, m := range e.Machines {
		f := family(m)
		if f == "" || m.Serial == "" {
			continue
		}
		total[f]++
		for src := range m.Sources {
			if count[src] == nil {
				count[src] = map[string]int{}
			}
			count[src][f]++
		}
	}
	out := map[string]map[string]bool{}
	for src, fams := range count {
		if !e.Complete(src, KindDevice) {
			continue
		}
		for f, n := range fams {
			if n >= 3 && n*10 >= total[f] {
				if out[src] == nil {
					out[src] = map[string]bool{}
				}
				out[src][f] = true
			}
		}
	}
	return out
}

func unmanagedDevice(e *Estate, now time.Time, add func(finding.Finding)) {
	cov := covers(e)
	for _, m := range e.Machines {
		if m.Serial == "" || m.Ambiguous || !m.live(now) {
			continue
		}
		f := family(m)
		for _, src := range sortedKeys(cov) {
			if !cov[src][f] || m.Sources[src] {
				continue
			}
			add(finding.Finding{
				Severity: telemetry.SeverityMedium,
				Entity: telemetry.ID{Issuer: src,
					Value: "missing:" + m.Serial},
				Title: fmt.Sprintf("%s (serial %s) is in %s and not in %s",
					m.Name(), m.Serial, strings.Join(sortedKeys(m.Sources),
						" and "), src),
				Evidence: evidence(now, strings.Join(sortedKeys(m.Sources),
					","), fmt.Sprintf("%s manages this kind of machine (%s) "+
					"and has no record of this one, which checked in %s. "+
					"Whatever %s enforces is not enforced on it",
					src, f, since(now.Sub(m.Seen())), src)),
			})
		}
	}
}

func ownerDisagrees(e *Estate, now time.Time, add func(finding.Finding)) {
	for _, m := range e.Machines {
		if len(m.Owners) < 2 || m.Ambiguous {
			continue
		}
		people := map[string]bool{}
		for _, o := range m.Owners {
			if ind, ok := e.byEmail[o]; ok {
				people[ind.Key] = true
			} else {
				people[o] = true
			}
		}
		if len(people) < 2 {
			continue
		}
		var said []string
		for _, r := range m.Records {
			if r.OwnerEmail != "" {
				said = append(said, r.ID.Issuer+": "+r.OwnerEmail)
			}
		}
		sort.Strings(said)
		add(finding.Finding{
			Severity: telemetry.SeverityMedium, Entity: m.Records[0].ID,
			Title: fmt.Sprintf("%s (serial %s) belongs to %d different people "+
				"depending on the tool", m.Name(), m.Serial, len(people)),
			Evidence: evidence(now, strings.Join(sortedKeys(m.Sources), ","),
				strings.Join(said, "; ")+". Its posture is counted against "+
					"nobody until they agree"),
		})
	}
}

func encryptionDisagrees(e *Estate, now time.Time, add func(finding.Finding)) {
	for _, m := range e.Machines {
		said := m.Posture(func(d Device) *bool { return d.Encrypted })
		var yes, no []string
		for src, v := range said {
			if v {
				yes = append(yes, src)
			} else {
				no = append(no, src)
			}
		}
		if len(yes) == 0 || len(no) == 0 {
			continue
		}
		sort.Strings(yes)
		sort.Strings(no)
		add(finding.Finding{
			Severity: telemetry.SeverityHigh, Entity: m.Records[0].ID,
			Title: fmt.Sprintf("%s (serial %s) is encrypted according to %s "+
				"and not according to %s", m.Name(), orNone(m.Serial),
				strings.Join(yes, " and "), strings.Join(no, " and ")),
			Evidence: evidence(now, strings.Join(sortedKeys(m.Sources), ","),
				"One of these is the evidence an auditor is shown, and one of "+
					"them is wrong. A drive the endpoint manager sees "+
					"unencrypted is unencrypted"),
		})
	}
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
