// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package estate

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// A person's risk, as points somebody can check.
//
// # Why points and not a model
//
// Every point here is a fact a tool reported, with the tool's name on it,
// and the weights are the table below. A score somebody cannot take apart is
// a score nobody can dispute, and one that nobody can dispute about a named
// employee is profiling under GDPR Article 22 whatever it is called. So the
// score is the sum of its reasons, each reason is shown, and the weights are
// in one place to argue about.
//
// # Unknown is not safe
//
// An area no tool reported on scores nothing and is listed as unknown. A
// person whose laptop no tool can see is not a person with a secure laptop,
// and a dashboard that averaged them in as zero would get safer every time
// a connector broke.

// Area is what a factor is about, and a column of the heatmap.
type Area string

const (
	AreaPhishing  Area = "phishing"
	AreaTraining  Area = "training"
	AreaPolicies  Area = "policies"
	AreaDevice    Area = "device"
	AreaPatching  Area = "patching"
	AreaLifecycle Area = "lifecycle"
)

// Areas is the order they are shown in.
func Areas() []Area {
	return []Area{AreaPhishing, AreaTraining, AreaPolicies, AreaDevice,
		AreaPatching}
}

// Weights is what each fact is worth. One table, so the argument about
// whether an unencrypted laptop matters more than a missed course happens in
// one place and is visible in the product.
var Weights = struct {
	DataEntered, OtherFailure, PerPhishProneFifth, PhishProneCap int
	PhishProneFrom                                               float64
	Reported                                                     int
	TrainingOverdue, TrainingDueSoon, NotInTraining              int
	PoliciesOverdue, PolicyUnacknowledged                        int
	NoDevice, Unencrypted, Rooted, NoScreenLock, NoPasscode      int
	NoAntivirus, Prohibited, Unmanaged                           int
	PerMissingPatch, PatchCap, PerSevereVuln, VulnCap            int
	LeaverWithDevice                                             int
}{
	DataEntered: 25, OtherFailure: 12, PerPhishProneFifth: 1,
	PhishProneCap: 10, PhishProneFrom: 20, Reported: -5,
	TrainingOverdue: 15, TrainingDueSoon: 3, NotInTraining: 10,
	PoliciesOverdue: 10, PolicyUnacknowledged: 5,
	NoDevice: 10, Unencrypted: 20, Rooted: 20, NoScreenLock: 8,
	NoPasscode: 8, NoAntivirus: 10, Prohibited: 8, Unmanaged: 10,
	PerMissingPatch: 3, PatchCap: 15, PerSevereVuln: 5, VulnCap: 15,
	LeaverWithDevice: 50,
}

// Band is where a score falls.
type Band string

const (
	BandLow      Band = "low"
	BandModerate Band = "moderate"
	BandHigh     Band = "high"
	BandCritical Band = "critical"
)

// Bands in order.
func Bands() []Band { return []Band{BandLow, BandModerate, BandHigh, BandCritical} }

func band(points int) Band {
	switch {
	case points >= 75:
		return BandCritical
	case points >= 50:
		return BandHigh
	case points >= 25:
		return BandModerate
	}
	return BandLow
}

// Factor is one reason for some of a score.
type Factor struct {
	Area   Area   `json:"area"`
	What   string `json:"what"`
	Points int    `json:"points"`
	Source string `json:"source"`
}

// Score is one person's risk.
type Score struct {
	Key        string   `json:"key"`
	Name       string   `json:"name"`
	Email      string   `json:"email,omitempty"`
	Department string   `json:"department,omitempty"`
	Title      string   `json:"title,omitempty"`
	Points     int      `json:"points"`
	Band       Band     `json:"band"`
	Factors    []Factor `json:"factors"`
	// Unknown lists the areas nothing reported on, with why.
	Unknown map[Area]string `json:"unknown,omitempty"`
	// Vendor is a tool's own score for them, shown beside this one and
	// never folded into it: KnowBe4's risk score weighs things this cannot
	// see, and averaging two opaque numbers makes a third.
	Vendor map[string]float64 `json:"vendor,omitempty"`
	Leaver bool               `json:"leaver,omitempty"`
}

// Has reports whether any factor is in an area.
func (s Score) Has(a Area) bool {
	for _, f := range s.Factors {
		if f.Area == a && f.Points > 0 {
			return true
		}
	}
	return false
}

// Scores rates everybody current, and every leaver whose device still
// checks in; somebody who left and has nothing live has nothing to score.
func (e *Estate) Scores(now time.Time) []Score {
	phishing := len(e.With(KindPhishing)) > 0
	training := len(e.With(KindTraining)) > 0 || e.anyTask("training")
	policies := e.anyTask("policies") || e.anyPolicyTraining()
	devices := len(e.With(KindDevice)) > 0
	patching := e.anyPatchData()
	cov := covers(e)

	var out []Score
	for _, ind := range e.People {
		known, current, _, no := ind.Current()
		leaver := known && !current
		live := 0
		for _, m := range ind.Devices {
			if m.live(now) {
				live++
			}
		}
		if leaver && live == 0 {
			continue
		}
		s := Score{Key: ind.Key, Name: ind.Name(), Leaver: leaver,
			Unknown: map[Area]string{}}
		if len(ind.Emails) > 0 {
			s.Email = ind.Emails[0]
		}
		for _, r := range ind.Records {
			if s.Department == "" {
				s.Department = r.Department
			}
			if s.Title == "" {
				s.Title = r.Title
			}
			if r.RiskScore != nil {
				if s.Vendor == nil {
					s.Vendor = map[string]float64{}
				}
				s.Vendor[r.ID.Issuer] = *r.RiskScore
			}
		}
		add := func(a Area, pts int, source, format string, args ...any) {
			s.Factors = append(s.Factors, Factor{Area: a, Points: pts,
				Source: source, What: fmt.Sprintf(format, args...)})
		}

		if leaver {
			add(AreaLifecycle, Weights.LeaverWithDevice, strings.Join(no, ", "),
				"has left according to %s and a device of theirs still "+
					"checks in", strings.Join(no, " and "))
		}

		// Phishing.
		if !phishing {
			s.Unknown[AreaPhishing] = "no phishing results were read"
		} else {
			var entered, other time.Time
			var reported bool
			var src string
			for _, p := range ind.Phishing {
				src = p.ID.Issuer
				if t, failed := p.Failed(); failed && now.Sub(t) <= Recent {
					if !p.DataEntered.IsZero() && p.DataEntered.After(entered) {
						entered = p.DataEntered
					} else if t.After(other) {
						other = t
					}
				} else if !p.Reported.IsZero() && now.Sub(p.Reported) <= Recent {
					reported = true
				}
			}
			switch {
			case !entered.IsZero():
				add(AreaPhishing, Weights.DataEntered, src,
					"entered data into a simulated phish %s",
					since(now.Sub(entered)))
			case !other.IsZero():
				add(AreaPhishing, Weights.OtherFailure, src,
					"clicked or opened a simulated phish %s",
					since(now.Sub(other)))
			case reported:
				add(AreaPhishing, Weights.Reported, src,
					"reported a simulated phish in the last 90 days")
			}
			// Only a rate that stands out. Untrained staff run around 30%
			// in KnowBe4's own benchmark and trained ones well under 20, so
			// below that the number says little about this person and would
			// put nearly everybody in the phishing column.
			for _, r := range ind.Records {
				if r.PhishProne == nil || *r.PhishProne < Weights.PhishProneFrom {
					continue
				}
				pts := int(math.Round(*r.PhishProne / 5 *
					float64(Weights.PerPhishProneFifth)))
				if pts > Weights.PhishProneCap {
					pts = Weights.PhishProneCap
				}
				if pts > 0 {
					add(AreaPhishing, pts, r.ID.Issuer,
						"%s rates them %.1f%% phish-prone", r.ID.Issuer,
						*r.PhishProne)
				}
				break
			}
		}

		// Training.
		if !training {
			s.Unknown[AreaTraining] = "no training was read"
		} else {
			status, from := ind.Task("training")
			overdue, dueSoon := status == "OVERDUE", status == "DUE_SOON"
			src := from
			for _, t := range ind.Training {
				if t.Policy || t.Done {
					continue
				}
				if strings.Contains(strings.ToLower(t.Status), "past due") {
					overdue, src = true, t.ID.Issuer
				}
			}
			switch {
			case overdue:
				add(AreaTraining, Weights.TrainingOverdue, src,
					"security training is overdue")
			case dueSoon:
				add(AreaTraining, Weights.TrainingDueSoon, src,
					"security training is due soon")
			}
			for _, platform := range e.With(KindTraining) {
				if e.Complete(platform, KindPerson) && !ind.Sources[platform] {
					add(AreaTraining, Weights.NotInTraining, platform,
						"is not enrolled in %s at all", platform)
				}
			}
		}

		// Policies.
		if !policies {
			s.Unknown[AreaPolicies] = "no policy acceptance was read"
		} else {
			if status, from := ind.Task("policies"); status == "OVERDUE" {
				add(AreaPolicies, Weights.PoliciesOverdue, from,
					"has not accepted the policies they are due to")
			}
			for _, t := range ind.Training {
				if t.Policy && t.Acknowledged != nil && !*t.Acknowledged &&
					t.Done {
					add(AreaPolicies, Weights.PolicyUnacknowledged,
						t.ID.Issuer, "finished %s without acknowledging it",
						orNone(t.Module))
					break
				}
			}
		}

		// Devices: the worst machine counts, because an attacker needs one.
		if !devices {
			s.Unknown[AreaDevice] = "no device tool was read"
		} else if live == 0 && !leaver {
			add(AreaDevice, Weights.NoDevice, strings.Join(e.With(KindDevice),
				", "), "has no device any tool can see, so its state is unknown")
		} else {
			var worst []Factor
			worstPts := -1
			for _, m := range ind.Devices {
				if !m.live(now) {
					continue
				}
				fs := machineFactors(m, cov)
				pts := 0
				for _, f := range fs {
					pts += f.Points
				}
				if pts > worstPts {
					worst, worstPts = fs, pts
				}
			}
			s.Factors = append(s.Factors, worst...)
		}

		// Patching.
		if !patching {
			s.Unknown[AreaPatching] = "no tool reported patches or " +
				"vulnerabilities"
		} else {
			worst := 0
			var why []Factor
			for _, m := range ind.Devices {
				if !m.live(now) {
					continue
				}
				fs := patchFactors(m)
				pts := 0
				for _, f := range fs {
					pts += f.Points
				}
				if pts > worst {
					worst, why = pts, fs
				}
			}
			s.Factors = append(s.Factors, why...)
		}

		sum := 0
		for _, f := range s.Factors {
			sum += f.Points
		}
		s.Points = clamp(sum)
		s.Band = band(s.Points)
		sort.SliceStable(s.Factors, func(i, j int) bool {
			return s.Factors[i].Points > s.Factors[j].Points
		})
		if len(s.Unknown) == 0 {
			s.Unknown = nil
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Points != out[j].Points {
			return out[i].Points > out[j].Points
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func clamp(n int) int {
	switch {
	case n < 0:
		return 0
	case n > 100:
		return 100
	}
	return n
}

// machineFactors is what makes one machine risky, each from the tool that
// said so. Where tools disagree the worse word counts — that disagreement is
// already a finding, and scoring the optimistic one would hide it twice.
func machineFactors(m *Machine, cov map[string]map[string]bool) []Factor {
	var out []Factor
	bad := func(get func(Device) *bool) (bool, string) {
		for _, r := range m.Records {
			if v := get(r); v != nil && !*v {
				return true, r.ID.Issuer
			}
		}
		return false, ""
	}
	name := m.Name()
	check := func(get func(Device) *bool, pts int, what string) {
		if isBad, src := bad(get); isBad {
			out = append(out, Factor{Area: AreaDevice, Points: pts,
				Source: src, What: name + " " + what})
		}
	}
	check(func(d Device) *bool { return d.Encrypted }, Weights.Unencrypted,
		"is not encrypted")
	check(func(d Device) *bool { return d.ScreenLock }, Weights.NoScreenLock,
		"has no screen lock")
	check(func(d Device) *bool { return d.Passcode }, Weights.NoPasscode,
		"has no passcode")
	check(func(d Device) *bool { return d.Antivirus }, Weights.NoAntivirus,
		"has no antivirus")
	for _, r := range m.Records {
		if r.Rooted != nil && *r.Rooted {
			out = append(out, Factor{Area: AreaDevice, Points: Weights.Rooted,
				Source: r.ID.Issuer, What: name + " is rooted or jailbroken"})
			break
		}
	}
	for _, r := range m.Records {
		if r.Prohibited != nil && *r.Prohibited > 0 {
			out = append(out, Factor{Area: AreaDevice,
				Points: Weights.Prohibited, Source: r.ID.Issuer,
				What: fmt.Sprintf("%s runs %d prohibited application%s",
					name, *r.Prohibited, map[bool]string{true: "", false: "s"}[*r.Prohibited == 1])})
			break
		}
	}
	if m.Serial != "" && !m.Ambiguous {
		f := family(m)
		for _, src := range sortedKeys(cov) {
			if cov[src][f] && !m.Sources[src] {
				out = append(out, Factor{Area: AreaDevice,
					Points: Weights.Unmanaged, Source: src,
					What: name + " is not managed by " + src})
				break
			}
		}
	}
	return out
}

func patchFactors(m *Machine) []Factor {
	var out []Factor
	for _, r := range m.Records {
		if r.MissingPatches != nil && *r.MissingPatches > 0 {
			pts := *r.MissingPatches * Weights.PerMissingPatch
			if pts > Weights.PatchCap {
				pts = Weights.PatchCap
			}
			out = append(out, Factor{Area: AreaPatching, Points: pts,
				Source: r.ID.Issuer, What: fmt.Sprintf(
					"%s is missing %d patch(es)", m.Name(), *r.MissingPatches)})
			break
		}
	}
	severe := 0
	src := ""
	for _, v := range m.Vulns {
		s := strings.ToLower(v.Severity)
		if v.Open && (s == "critical" || s == "important" || s == "high") {
			severe++
			src = v.Device.Issuer
		}
	}
	if severe > 0 {
		pts := severe * Weights.PerSevereVuln
		if pts > Weights.VulnCap {
			pts = Weights.VulnCap
		}
		out = append(out, Factor{Area: AreaPatching, Points: pts, Source: src,
			What: fmt.Sprintf("%s has %d open critical or important "+
				"vulnerabilit(ies)", m.Name(), severe)})
	}
	return out
}

func (e *Estate) anyTask(name string) bool {
	for _, ind := range e.People {
		if s, from := ind.Task(name); s != "" &&
			e.Complete(from, KindPerson) {
			return true
		}
	}
	return false
}

func (e *Estate) anyPolicyTraining() bool {
	for _, ind := range e.People {
		for _, t := range ind.Training {
			if t.Policy {
				return true
			}
		}
	}
	return false
}

func (e *Estate) anyPatchData() bool {
	for _, m := range e.Machines {
		if len(m.Vulns) > 0 {
			return true
		}
		for _, r := range m.Records {
			if r.MissingPatches != nil {
				return true
			}
		}
	}
	return len(e.With(KindVulnerability)) > 0
}

// Summary is the estate's risk in aggregate: what history keeps, because a
// history of aggregates is a trend and a history of named scores is a file
// on each employee.
type Summary struct {
	Date    string       `json:"date"`
	Scored  int          `json:"scored"`
	Mean    float64      `json:"mean"`
	Bands   map[Band]int `json:"bands"`
	Leavers int          `json:"leavers,omitempty"`
	// Areas counts people with a factor in each area.
	Areas map[Area]int `json:"areas"`
}

// Summarise aggregates scores for a day.
func Summarise(scores []Score, day time.Time) Summary {
	s := Summary{Date: day.UTC().Format("2006-01-02"), Scored: len(scores),
		Bands: map[Band]int{}, Areas: map[Area]int{}}
	total := 0
	for _, sc := range scores {
		total += sc.Points
		s.Bands[sc.Band]++
		if sc.Leaver {
			s.Leavers++
		}
		for _, a := range Areas() {
			if sc.Has(a) {
				s.Areas[a]++
			}
		}
	}
	if len(scores) > 0 {
		s.Mean = math.Round(float64(total)/float64(len(scores))*10) / 10
	}
	return s
}
