// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package workforce

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// What the join is for: the questions no single system can answer.
//
// Every finding here needs two systems to disagree. A leaver whose laptop
// still checks in is invisible in the directory, which correctly shows a
// disabled account, and invisible in the MDM, which correctly shows a healthy
// enrolled device. Neither console is wrong and neither will ever raise it.
//
// # Two kinds of gap, kept apart
//
// Somebody absent from a system is a coverage gap. Somebody present in a
// system and missing something it tracks is a control gap. Most tools report
// both as "not compliant", which means the person who was never enrolled in
// the training platform and the person who was enrolled and did not finish
// land in one queue with one fix suggested, and the first one is not a
// training problem at all.
//
// # Nothing is reported as a percentage
//
// Coverage decides whether any of this is quotable, and Findings says so
// rather than leaving somebody to divide two numbers that are not comparable.

// Requirement is something a system is expected to hold about a person.
type Requirement struct {
	// Name is what it is, in words: "security awareness training".
	Name string `json:"name"`
	// Issuer is the system that would know.
	Issuer string `json:"issuer"`
	// Attribute is the key on the identity in that system.
	Attribute string `json:"attribute"`
	// Severity is how bad its absence is.
	Severity telemetry.Severity `json:"severity"`
}

// Validate refuses a requirement nothing could satisfy.
func (r Requirement) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("a requirement needs a name somebody can read")
	}
	if strings.TrimSpace(r.Issuer) == "" {
		return fmt.Errorf(
			"%q names no system. A requirement nobody can point at a source "+
				"for is one that will be reported against everybody for "+
				"ever", r.Name)
	}
	if strings.TrimSpace(r.Attribute) == "" {
		return fmt.Errorf("%q names no attribute to read", r.Name)
	}
	return nil
}

// Expect is what a deployment believes should be true of its workforce.
type Expect struct {
	// In names the systems every person should appear in.
	In []string `json:"in,omitempty"`
	// Device is whether every person should have at least one.
	Device bool `json:"device,omitempty"`
	// Require is what particular systems should hold about them.
	Require []Requirement `json:"require,omitempty"`
	// Stale overrides how long a device may go quiet. Zero means StaleAfter.
	Stale time.Duration `json:"stale,omitempty"`
}

func (e Expect) stale() time.Duration {
	if e.Stale > 0 {
		return e.Stale
	}
	return StaleAfter
}

// Findings is everything the join found that no single system could.
func (r *Roster) Findings(e Expect, now time.Time) []finding.Finding {
	var out []finding.Finding
	add := func(f finding.Finding) {
		f.Source = "workforce"
		f.State = finding.Open
		f.Seen = 1
		if f.First.IsZero() {
			f.First = now
		}
		f.Last = now
		f.ID = finding.Key(f.Kind, f.Source, f.Entity)
		out = append(out, f)
	}

	for _, p := range r.People() {
		gone, said := p.Gone()

		// The one that needs the join and nothing else can see.
		if gone {
			for _, d := range p.Devices {
				if d.Seen.IsZero() || now.Sub(d.Seen) > e.stale() {
					continue
				}
				add(finding.Finding{
					Kind:     finding.FromControl,
					Severity: telemetry.SeverityCritical,
					Entity:   d.ID,
					Title: fmt.Sprintf(
						"%s is disabled in %s and %s still checked in %s ago",
						p.Name(), strings.Join(said, " and "), d.ID.Value,
						plainly(now.Sub(d.Seen))),
					Evidence: []finding.Evidence{{
						At: now, Source: "workforce",
						What: fmt.Sprintf(
							"%s reports the account as no longer current; "+
								"%s reports the device as enrolled and last "+
								"seen %s. Neither console is wrong and "+
								"neither will raise this",
							strings.Join(said, ", "), d.ID.Issuer,
							d.Seen.Format(time.RFC3339)),
					}},
				})
			}
			// A leaver is not also reported as missing from systems or
			// short of training. They have left.
			continue
		}

		for _, want := range e.In {
			if p.In(want) {
				continue
			}
			add(finding.Finding{
				Kind:     finding.FromControl,
				Severity: telemetry.SeverityMedium,
				Entity:   anyID(p),
				Title:    fmt.Sprintf("%s is not in %s at all", p.Name(), want),
				Evidence: []finding.Evidence{{
					At: now, Source: "workforce",
					What: fmt.Sprintf(
						"found in %s and not in %s. Absent from a system is "+
							"not the same as failing one of its checks, and "+
							"the fix is enrolment rather than a reminder",
						strings.Join(p.Issuers(), ", "), want),
				}},
			})
		}

		if e.Device && len(p.Devices) == 0 {
			add(finding.Finding{
				Kind:     finding.FromControl,
				Severity: telemetry.SeverityMedium,
				Entity:   anyID(p),
				Title: fmt.Sprintf("no managed device is assigned to %s",
					p.Name()),
				Evidence: []finding.Evidence{{
					At: now, Source: "workforce",
					What: "every device control passes for somebody who has " +
						"no device on record, which is the same result as " +
						"having one that is fully compliant",
				}},
			})
		}

		for _, req := range e.Require {
			// Only for somebody that system actually holds. Absence from the
			// system is the coverage finding above, and reporting it twice
			// puts one person in two queues with two different fixes.
			held, ok := p.identityIn(req.Issuer)
			if !ok {
				continue
			}
			if v := strings.TrimSpace(held.Attributes[req.Attribute]); v != "" {
				continue
			}
			sev := req.Severity
			if sev == telemetry.SeverityUnknown {
				sev = telemetry.SeverityLow
			}
			add(finding.Finding{
				Kind: finding.FromControl, Severity: sev, Entity: held.ID,
				Title: fmt.Sprintf("%s has no %s recorded", p.Name(),
					req.Name),
				Evidence: []finding.Evidence{{
					At: now, Source: req.Issuer,
					What: fmt.Sprintf(
						"%s holds this person and has no value for %s",
						req.Issuer, req.Attribute),
				}},
			})
		}

		for _, d := range p.Devices {
			if d.Seen.IsZero() || now.Sub(d.Seen) <= e.stale() {
				continue
			}
			add(finding.Finding{
				Kind: finding.FromControl, Severity: telemetry.SeverityMedium,
				Entity: d.ID,
				Title: fmt.Sprintf("%s has not checked in for %s", d.ID.Value,
					plainly(now.Sub(d.Seen))),
				Evidence: []finding.Evidence{{
					At: now, Source: d.ID.Issuer,
					What: fmt.Sprintf(
						"assigned to %s and last seen %s. A device that "+
							"stopped reporting is one whose console still "+
							"shows the last good answer it gave", p.Name(),
						d.Seen.Format(time.RFC3339)),
				}},
			})
		}
	}

	orphans := r.Orphans()
	for _, d := range append(orphans.Unowned, orphans.Dangling...) {
		what := "names no owner"
		if !d.Owner.Zero() {
			what = fmt.Sprintf("names %s as its owner, and no system that "+
				"has been read holds that record", d.Owner)
		}
		add(finding.Finding{
			Kind: finding.FromControl, Severity: telemetry.SeverityHigh,
			Entity: d.ID,
			Title:  fmt.Sprintf("%s belongs to nobody", d.ID.Value),
			Evidence: []finding.Evidence{{
				At: now, Source: d.ID.Issuer,
				What: fmt.Sprintf(
					"%s %s. A device outside every per-person control is "+
						"still counted as enrolled by the console that "+
						"manages it", d.ID, what),
			}},
		})
	}
	for _, i := range orphans.Alone {
		if i.Says(false) {
			// A leaver present in one system is not a join failure, it is a
			// leaver. Reporting them here puts the one finding that matters
			// about them — the laptop still checking in — in a queue
			// alongside a row saying the join did not work.
			continue
		}
		add(finding.Finding{
			Kind: finding.FromControl, Severity: telemetry.SeverityLow,
			Entity: i.ID,
			Title: fmt.Sprintf("%s appears only in %s", label(i),
				i.ID.Issuer),
			Evidence: []finding.Evidence{{
				At: now, Source: "workforce",
				What: "either this person really is only in one system, or " +
					"the join failed for them — and if it failed, nothing " +
					"else here will ever be reported about them",
			}},
		})
	}

	return finding.Rank(out, now)
}

func (p Person) identityIn(issuer string) (Identity, bool) {
	var keys []string
	for k, i := range p.Identities {
		if i.ID.Issuer == issuer {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return Identity{}, false
	}
	return p.Identities[keys[0]], true
}

// anyID is a stable identifier for a person, for deduplicating findings.
func anyID(p Person) telemetry.ID {
	var keys []string
	for k := range p.Identities {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return telemetry.ID{Issuer: "workforce", Value: p.Key}
	}
	return p.Identities[keys[0]].ID
}

// plainly renders a duration the way somebody reading a queue would say it.
//
// Go prints 2280h0m0s for three months, which is correct and is not an
// answer to "how long has this laptop been missing".
func plainly(d time.Duration) string {
	switch {
	case d < 0:
		return "no time at all"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	case d < 90*24*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours())/24)
	default:
		return fmt.Sprintf("%d months", int(d.Hours())/24/30)
	}
}

func label(i Identity) string {
	if strings.TrimSpace(i.Name) != "" {
		return i.Name
	}
	if strings.TrimSpace(i.Email) != "" {
		return i.Email
	}
	return i.ID.Value
}
