// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package vendor

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/connector"
	"github.com/quilzo/quilzo/internal/finding"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Comparing the register against the credentials that actually exist.
//
// A vendor register is a list somebody typed in, and every list somebody
// typed in is behind. The standard practice makes this worse rather than
// better: an inherent risk questionnaire at onboarding produces a tier that
// is right on the day, and from then on the vendor adds a scope, an engineer
// connects a second system, and nothing in the register moves.
//
// internal/connector knows exactly which third parties this deployment holds
// credentials for and which fields each one may read. That is not a
// substitute for the register — it only sees one of the two directions — but
// it is a set of facts, and a fact beats a form.

// Gap is a disagreement between the register and the credentials.
type Gap struct {
	// Vendor names the party, whether or not the register knows them.
	Vendor string `json:"vendor"`
	What   string `json:"what"`
	// Connector names the manifest, where one is involved.
	Connector string `json:"connector,omitempty"`
}

// Reconciliation is what the comparison found.
type Reconciliation struct {
	// Unregistered are connectors pointing at parties the register does not
	// hold.
	//
	// The interesting one. Not a paperwork problem: it is a processor
	// nobody has assessed, holding a credential somebody issued, and it is
	// invisible to a register that only knows what was typed into it.
	Unregistered []Gap `json:"unregistered,omitempty"`
	// Undeclared are registered vendors with a connector whose access the
	// register does not mention.
	Undeclared []Gap `json:"undeclared,omitempty"`
	// Lingering are vendors that are exiting or terminated and still have
	// access of any kind.
	//
	// The one that matters most. Offboarding is a checklist item that
	// reliably gets half done, and nothing else in an organisation notices.
	Lingering []Gap `json:"lingering,omitempty"`
	// Checked is how many connectors were compared.
	Checked int `json:"checked"`
}

// Clean reports whether the two agree.
func (r Reconciliation) Clean() bool {
	return len(r.Unregistered)+len(r.Undeclared)+len(r.Lingering) == 0
}

// Why explains a reconciliation in one line, leading with the worst.
func (r Reconciliation) Why() string {
	switch {
	case len(r.Lingering) > 0:
		return fmt.Sprintf(
			"%d vendor(s) are exiting or terminated and still have access. "+
				"The contract ended and the credential did not",
			len(r.Lingering))
	case len(r.Unregistered) > 0:
		return fmt.Sprintf(
			"%d connector(s) point at parties the vendor register does not "+
				"hold. Somebody issued a credential to a processor nobody "+
				"has assessed", len(r.Unregistered))
	case len(r.Undeclared) > 0:
		return fmt.Sprintf(
			"%d registered vendor(s) have access the register does not "+
				"mention", len(r.Undeclared))
	default:
		return fmt.Sprintf(
			"the register and the %d configured connector(s) agree",
			r.Checked)
	}
}

// Reconcile compares the register against the connectors configured here.
func Reconcile(r *Register, manifests []connector.Manifest,
	now time.Time) Reconciliation {

	out := Reconciliation{Checked: len(manifests)}
	for _, m := range manifests {
		v, known := r.Get(m.Name)
		if !known {
			out.Unregistered = append(out.Unregistered, Gap{
				Vendor: m.Name, Connector: m.Name,
				What: fmt.Sprintf(
					"a connector holds a credential to %s and reads %d "+
						"endpoint(s) there, and no vendor called %s is in "+
						"the register", m.Host, len(m.Endpoints), m.Name),
			})
			continue
		}
		if !mentions(v, m) {
			out.Undeclared = append(out.Undeclared, Gap{
				Vendor: v.ID, Connector: m.Name,
				What: fmt.Sprintf(
					"a connector reads %s and the register records no "+
						"access to it. The tier is derived from what a "+
						"vendor reaches, so an access nobody wrote down is "+
						"a tier that is too low", m.Host),
			})
		}
	}

	live := map[string]bool{}
	for _, m := range manifests {
		live[m.Name] = true
	}
	for _, v := range r.All() {
		if v.Status != Exiting && v.Status != Terminated {
			continue
		}
		if live[v.ID] {
			out.Lingering = append(out.Lingering, Gap{
				Vendor: v.ID, Connector: v.ID,
				What: fmt.Sprintf(
					"%s is %s and a connector still holds a credential to "+
						"them", v.Name, v.Status),
			})
		}
		for _, a := range v.Access {
			if !a.Reach.Inbound() {
				continue
			}
			out.Lingering = append(out.Lingering, Gap{
				Vendor: v.ID,
				What: fmt.Sprintf(
					"%s is %s and still holds a credential in %s. That "+
						"token works until somebody revokes it, not until "+
						"the contract ends", v.Name, v.Status, a.What),
			})
		}
	}
	for _, list := range [][]Gap{out.Unregistered, out.Undeclared,
		out.Lingering} {
		sort.Slice(list, func(i, j int) bool {
			return list[i].Vendor < list[j].Vendor
		})
	}
	return out
}

// mentions reports whether the register records this connector's access.
func mentions(v Vendor, m connector.Manifest) bool {
	for _, a := range v.Access {
		if a.Connector == m.Name {
			return true
		}
		if a.Reach == WeRead && strings.EqualFold(a.What, m.Host) {
			return true
		}
	}
	return false
}

// Derived turns a connector manifest into the access it implies.
//
// Offered rather than applied. What a connector proves is that a credential
// exists and what it may read; whether that is the whole of the relationship
// is a question for whoever owns the vendor, and a register that silently
// absorbed this would be a register nobody had read.
func Derived(m connector.Manifest, now time.Time) Access {
	var scopes []string
	for _, e := range m.Endpoints {
		scopes = append(scopes, e.Name)
	}
	sort.Strings(scopes)
	return Access{
		Reach: WeRead, What: m.Host, Scopes: scopes,
		Since: now, Connector: m.Name,
	}
}

// Findings turns the state of the register into the queue.
func Findings(r *Register, rec Reconciliation,
	now time.Time) []finding.Finding {

	var out []finding.Finding
	add := func(id string, sev telemetry.Severity, title, what string) {
		f := finding.Finding{
			Kind: finding.FromVendor, Title: title, Source: "vendor",
			Entity:   telemetry.ID{Issuer: "vendor", Value: id},
			Severity: sev, State: finding.Open, Seen: 1,
			First: now, Last: now,
			Evidence: []finding.Evidence{{
				At: now, Source: "vendor", What: what,
			}},
		}
		if v, ok := r.Get(id); ok {
			f.Owner = v.Owner
		}
		f.ID = finding.Key(f.Kind, f.Source, f.Entity)
		out = append(out, f)
	}

	// The contract ended and the credential did not.
	for _, g := range rec.Lingering {
		add(g.Vendor, telemetry.SeverityCritical,
			fmt.Sprintf("%s still has access after the relationship ended",
				g.Vendor), g.What)
	}
	// A processor nobody assessed.
	for _, g := range rec.Unregistered {
		add(g.Vendor, telemetry.SeverityHigh,
			fmt.Sprintf("%s holds a credential and is not in the register",
				g.Vendor), g.What)
	}
	for _, g := range rec.Undeclared {
		add(g.Vendor, telemetry.SeverityMedium,
			fmt.Sprintf("%s has access the register does not mention",
				g.Vendor), g.What)
	}

	for _, v := range r.All() {
		if v.Status == Terminated {
			continue
		}
		tier, because := v.Tier()
		if v.Overdue(now) {
			sev := telemetry.SeverityLow
			switch tier {
			case Critical:
				sev = telemetry.SeverityHigh
			case High:
				sev = telemetry.SeverityMedium
			}
			when := "never"
			if !v.Reviewed.IsZero() {
				when = "due " + v.Due().Format("2006-01-02")
			}
			add(v.ID, sev,
				fmt.Sprintf("%s has not been reviewed (%s)", v.Name, when),
				fmt.Sprintf("%s, because %s. A critical vendor is reviewed "+
					"twice as often because what makes it critical changes "+
					"without anybody telling us", tier, because))
		}
		if strings.TrimSpace(v.Owner) == "" {
			add(v.ID, telemetry.SeverityLow,
				fmt.Sprintf("%s has nobody accountable", v.Name),
				"a vendor with no owner is one whose renewal happens "+
					"automatically and whose review does not")
		}
		// Fourth party. The guidance is to get direct visibility rather
		// than assuming the vendor has it, and nobody asking is different
		// from their having none.
		if tier >= High && v.Asked.IsZero() {
			add(v.ID, telemetry.SeverityMedium,
				fmt.Sprintf("nobody has asked %s who their processors are",
					v.Name),
				"an empty subprocessor list is not the same as a vendor "+
					"with no subprocessors. The Drift compromise reached "+
					"more than 700 organisations through one vendor, and "+
					"every one of them was a fourth party to somebody")
		}
	}
	return finding.Rank(out, now)
}
