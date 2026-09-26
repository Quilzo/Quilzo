// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package engagement is what an auditor is given, and what they can check
// without being given anything else.
//
// # The two ways this is done and why both are bad
//
// The auditor gets a login to the compliance platform, which hands them every
// company, every framework and every period — more than the engagement
// covers, and a standing credential into the system of record for as long as
// somebody forgets to revoke it. Or the auditor gets a folder of exported
// PDFs, which is scoped correctly and proves nothing: it is a set of files
// the audited party assembled, and the only reason to believe them is that
// the audited party says so.
//
// The published complaint about the compliance platforms is the middle of
// this: awkward three-way communication between the company, the platform and
// the auditor, and audit timelines that get longer rather than shorter.
//
// # A package that proves itself
//
// internal/audit is a hash chain with an RFC 6962 Merkle tree over it and a
// head signed with Ed25519 and ML-DSA-65. That was built so that a specific
// record could be proved without handing over the log, and this is the thing
// it was built for.
//
// An engagement package carries, for each piece of evidence in scope: the
// evidence itself, the audit entry that recorded it being gathered, an
// inclusion proof of that entry, and one signed head the proofs resolve
// against. An auditor with the package and the published verifying key can
// then establish, on their own machine, with no access to this system:
//
//   - each entry is genuinely in a log whose head was signed by this
//     organisation, so the evidence was recorded when it says it was
//   - the tree is consistent with the head of any earlier package, so
//     nothing was removed between engagements
//   - the entries carry the hash chain, so a rewritten one fails twice
//
// What it does not prove is that the log is complete — an organisation can
// omit an entry before the tree is built, and no cryptography fixes that.
// What it does prove is that nothing was changed afterwards, and that two
// packages issued to two parties describe the same log. That is the honest
// shape of the guarantee and it is worth saying plainly, because this is
// usually sold as something stronger than anybody can deliver.
//
// # Scope is the engagement, not the platform
//
// An engagement names one entity scope, one period and the frameworks it
// covers. Nothing outside reaches the package: a SOC 2 for the American
// company does not carry the German company's evidence, and Build refuses a
// package that would.
package engagement

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assurance"
	"github.com/quilzo/quilzo/internal/audit"
)

// MaxWindow is the longest an engagement may be open.
//
// Eighteen months. A Type II observation period plus the examination and the
// report, with room to spare — and short enough that an engagement nobody
// closed expires before it becomes a standing credential. The complaint about
// auditor access in every one of these products is the access that was never
// revoked.
const MaxWindow = 18 * 30 * 24 * time.Hour

// Engagement is one audit: who, of what, for when.
type Engagement struct {
	ID string `json:"id"`
	// Firm and Auditor are the organisation and the person. Both, because
	// the firm is who was engaged and the person is who looked.
	Firm    string `json:"firm"`
	Auditor string `json:"auditor"`

	// Scope is the entity this covers. Everything beneath it is in scope and
	// nothing else is.
	Scope string `json:"scope"`
	// Period is the observation window the evidence has to speak to.
	Period assurance.Period `json:"period"`
	// Frameworks are what is being examined.
	Frameworks []string `json:"frameworks,omitempty"`

	// Opened and Until bound the access itself, which is not the same as the
	// period being examined: an examination of last spring happens this
	// autumn.
	Opened time.Time `json:"opened"`
	Until  time.Time `json:"until"`

	// By is who engaged them.
	By   string     `json:"by"`
	Kind audit.Kind `json:"kind,omitempty"`
	// Because is the engagement, in one line.
	Because string `json:"because"`
}

// Validate refuses an engagement that would be a standing credential.
func (e Engagement) Validate() error {
	if strings.TrimSpace(e.ID) == "" {
		return fmt.Errorf("an engagement needs an identifier")
	}
	if strings.TrimSpace(e.Firm) == "" {
		return fmt.Errorf("%s names no firm", e.ID)
	}
	if strings.TrimSpace(e.Auditor) == "" {
		return fmt.Errorf(
			"%s names a firm and no person. The firm is who was engaged and "+
				"the person is who looked, and a log that records only the "+
				"firm cannot answer either question", e.ID)
	}
	if strings.TrimSpace(e.Scope) == "" {
		return fmt.Errorf(
			"%s covers no entity. An engagement with no scope is a login to "+
				"everything, which is the thing this exists to avoid", e.ID)
	}
	if !e.Period.Valid() {
		return fmt.Errorf("%s examines no period", e.ID)
	}
	if e.Opened.IsZero() {
		return fmt.Errorf("%s has no start", e.ID)
	}
	if e.Until.IsZero() {
		return fmt.Errorf(
			"%s never ends. The complaint about auditor access in every one "+
				"of these products is the access nobody revoked", e.ID)
	}
	if !e.Until.After(e.Opened) {
		return fmt.Errorf("%s ends before it begins", e.ID)
	}
	if e.Until.Sub(e.Opened) > MaxWindow {
		return fmt.Errorf(
			"%s is open for %s. The ceiling is %s: an observation period "+
				"plus the examination and the report, with room to spare",
			e.ID, e.Until.Sub(e.Opened).Round(24*time.Hour), MaxWindow)
	}
	if strings.TrimSpace(e.By) == "" {
		return fmt.Errorf("%s was opened by nobody", e.ID)
	}
	if e.Kind == audit.KindAI {
		return fmt.Errorf(
			"%s was opened by a model. Granting an outside firm access to "+
				"this organisation's evidence is a commercial decision with "+
				"a contract behind it, and a person makes it", e.ID)
	}
	if strings.TrimSpace(e.Because) == "" {
		return fmt.Errorf("%s says nothing about what the audit is", e.ID)
	}
	return nil
}

// Open reports whether the engagement is live at a moment.
func (e Engagement) Open(now time.Time) bool {
	return !now.Before(e.Opened) && now.Before(e.Until)
}

// Why explains an engagement's standing in one line.
func (e Engagement) Why(now time.Time) string {
	switch {
	case now.Before(e.Opened):
		return fmt.Sprintf("opens %s", e.Opened.Format("2006-01-02"))
	case !e.Open(now):
		return fmt.Sprintf("closed %s; nothing more can be issued under it",
			e.Until.Format("2006-01-02"))
	default:
		return fmt.Sprintf("open until %s, covering %s over %s",
			e.Until.Format("2006-01-02"), e.Scope, e.Period)
	}
}

// Record turns an engagement into an audit entry.
func (e Engagement) Record() audit.Record {
	return audit.Record{
		Action: "engagement.opened", Resource: "/engagement/" + e.ID,
		Outcome: audit.Success, Principal: e.By, Kind: e.Kind,
		Verified: e.Kind != audit.KindUnknown,
		Detail: map[string]string{
			"engagement": e.ID, "firm": e.Firm, "auditor": e.Auditor,
			"scope": e.Scope, "because": e.Because,
			"from":  e.Period.From.UTC().Format(time.RFC3339),
			"to":    e.Period.To.UTC().Format(time.RFC3339),
			"until": e.Until.UTC().Format(time.RFC3339),
		},
	}
}

// Item is one piece of evidence with the proof that it was recorded.
type Item struct {
	Evidence assurance.Evidence `json:"evidence"`
	// Entry is the audit record of it being gathered.
	Entry audit.Event `json:"entry"`
	// Index is the entry's position in the tree, and Proof the hashes that
	// place it under the head.
	Index int      `json:"index"`
	Proof []string `json:"proof"`
}

// Package is what the auditor is handed.
type Package struct {
	Engagement Engagement `json:"engagement"`
	// Issued is when this package was built.
	Issued time.Time `json:"issued"`
	// Head is the one commitment every proof in here resolves against.
	Head audit.SignedHead `json:"head"`
	// Items are the evidence and its proofs.
	Items []Item `json:"items"`
	// Controls are the controls in scope, so the auditor knows what was
	// claimed as well as what was evidenced.
	Controls []assurance.Control `json:"controls"`
	// Coverage is what this organisation says the evidence shows, which the
	// auditor is free to disagree with — and can, because the underlying
	// evidence is all here.
	Coverage []assurance.Coverage `json:"coverage"`
	// Unevidenced names controls in scope with nothing in the period.
	//
	// Included deliberately. A package that quietly omitted them would be a
	// package whose completeness depends on the audited party, which is the
	// thing the proofs exist to remove — and an auditor finds them anyway.
	Unevidenced []string `json:"unevidenced,omitempty"`
	// Note is what the auditor should read first.
	Note string `json:"note"`
}

// Count is how many pieces of evidence are in the package.
func (p Package) Count() int { return len(p.Items) }

// Verify checks a package the way an auditor would, with nothing else.
//
// The whole point: this function takes a package and a verifier built from a
// published key, and needs no access to the log, the store or the network.
func (p Package) Verify(v *audit.HeadVerifier) error {
	if v == nil {
		return fmt.Errorf(
			"no verifying key. The head's signature is the reason to " +
				"believe any of this, and checking a package without it is " +
				"reading a file the audited party wrote")
	}
	if err := v.Verify(p.Head); err != nil {
		return fmt.Errorf("the head does not verify: %w", err)
	}
	if err := p.Engagement.Validate(); err != nil {
		return fmt.Errorf("the engagement is malformed: %w", err)
	}
	for _, item := range p.Items {
		if err := audit.VerifyInclusion(item.Entry, item.Index, item.Proof,
			p.Head.Head); err != nil {
			return fmt.Errorf(
				"%s: the entry recording this evidence is not in the signed "+
					"log: %w", item.Evidence.Ref, err)
		}
		if err := item.agrees(); err != nil {
			return err
		}
	}
	return nil
}

// agrees checks that the evidence and the audit entry describe the same act.
//
// The proof establishes that the entry is in the log. It says nothing about
// whether the evidence handed over alongside it is the evidence that entry
// recorded — so the fields the entry carries are compared, and a package
// where they diverge is one where the proofs are real and attached to the
// wrong thing.
func (i Item) agrees() error {
	for _, f := range []struct{ name, entry, evidence string }{
		{"control", i.Entry.Detail["control"], i.Evidence.Control},
		{"reference", i.Entry.Detail["ref"], i.Evidence.Ref},
		{"source", i.Entry.Detail["source"], i.Evidence.Source},
	} {
		if f.entry != f.evidence {
			return fmt.Errorf(
				"the proof for %s is real and is attached to a different "+
					"act: the log says the %s was %q and the evidence says "+
					"%q", i.Evidence.Ref, f.name, f.entry, f.evidence)
		}
	}
	if i.Entry.Detail["from"] != i.Evidence.From.UTC().Format(time.RFC3339) ||
		i.Entry.Detail["to"] != i.Evidence.To.UTC().Format(time.RFC3339) {
		return fmt.Errorf(
			"the proof for %s covers a different period from the evidence "+
				"it is attached to", i.Evidence.Ref)
	}
	return nil
}

// Outside returns any evidence in the package that the engagement does not
// cover, which should always be empty.
//
// A belt to Build's braces, and the check an auditor's own tooling would run
// first: a package containing another company's evidence is a disclosure, and
// one containing evidence from outside the period is somebody padding.
func (p Package) Outside(inScope func(entity string) bool) []string {
	var out []string
	for _, item := range p.Items {
		at := item.Evidence.Entity
		if at != "" && !inScope(at) {
			out = append(out, fmt.Sprintf("%s speaks for %s",
				item.Evidence.Ref, at))
			continue
		}
		if _, ok := (assurance.Period{
			From: item.Evidence.From, To: item.Evidence.To,
		}).Overlap(p.Engagement.Period); !ok {
			out = append(out, fmt.Sprintf("%s is outside the period",
				item.Evidence.Ref))
		}
	}
	sort.Strings(out)
	return out
}
