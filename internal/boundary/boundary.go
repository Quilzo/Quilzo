// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package boundary says what each part of this program holds, and what it
// would cost to run two of them together.
//
// # The question, and why the obvious answer is wrong
//
// "Should log analysis be separated from production" has a well-known
// answer — NIST SP 800-53 AU-9 puts it plainly, that log destinations
// operate in a separate security boundary from the systems they audit and
// the audited system may append and never read, modify or delete. PCI DSS
// requirement 10.3 says the same from the other side.
//
// The tempting next step is to apply that everywhere: separate the
// vulnerability scanner, separate the compliance evidence, separate the
// content. That is wrong, and it is wrong in a way that matters, because
// separating everything costs the same as separating the one thing that
// needs it and buys much less.
//
// The reason is that the SIEM case is two arguments wearing one name, and
// only one of them generalises.
//
// # The argument that generalises: nothing rewrites its own record
//
// A system must not be able to edit the account of what it did. That
// applies to the content store, the vulnerability queue, the compliance
// evidence and the detections equally, and this program already answers it
// without separating anything: internal/audit is a hash chain with signed
// heads, internal/logd runs the writer as a different account so the
// application cannot hold a descriptor that could seek or truncate, and
// internal/spool's segments are append-only and sealed.
//
// So the answer for the vulnerability queue, for GRC and for the CMS is
// the same: they do not need their own process, they need their decisions
// in the chain, and they are.
//
// # The argument that does not: what the collector holds
//
// The collector is different in kind, and not because logs are sensitive.
// It is because of what it must hold to fetch them.
//
// To read Okta's system log, Entra's sign-ins, CloudTrail, Salesforce's
// login history and a dozen more, something must hold a credential at each
// of those platforms. That is the largest concentration of authority
// anywhere in an estate, and it points outward: compromising the collector
// does not give an attacker your logs, it gives them read access to every
// system your logs come from.
//
// Nothing in the vulnerability queue is like that. It reads a bill of
// materials the build produced and a public advisory database. Nothing in
// GRC is like that. Nothing in the CMS is like that. The collector is the
// only part of this program that holds keys to somebody else's system, and
// that — rather than log sensitivity — is the reason it belongs on its own
// side of a line.
//
// # The part you cannot design away
//
// Several platforms do not offer a credential that reads only their audit
// log. GitHub needed a roadmap item to add read:audit_log because one did
// not exist; the same request has been made of other vendors and is still
// open at some of them. Where a platform has no log-only scope, pulling
// its logs means holding something that reads more than its logs, and no
// amount of care at this end changes that.
//
// So the table below records, per platform, what the narrowest documented
// credential is and what it reaches beyond the log. The excess is the
// thing to compensate for, and it cannot be compensated for if nobody has
// written it down.
package boundary

import (
	"fmt"
	"sort"
	"strings"
)

// Side is which half of the line a capability belongs on.
type Side string

const (
	// Collect reaches outward: it holds credentials at other people's
	// systems and fetches from them.
	Collect Side = "collect"
	// Analyse reads what was collected and decides things about it. It
	// holds no outward credential.
	Analyse Side = "analyse"
	// Serve is the application itself: the thing the others watch.
	Serve Side = "serve"
	// Record is the account of what happened, which everything writes to
	// and nothing edits.
	Record Side = "record"
)

// Sides in the order they are worth thinking about.
var Sides = []Side{Collect, Analyse, Serve, Record}

// Why says what each side is, and what it is exposed to.
func (s Side) Why() string {
	switch s {
	case Collect:
		return "holds credentials at other people's systems and reaches " +
			"outward. Compromising it does not give an attacker your " +
			"logs, it gives them read access to every system your logs " +
			"come from"
	case Analyse:
		return "reads what was collected and decides things about it. It " +
			"holds no credential that reaches outside this deployment, " +
			"which is what makes it the cheap side to run anywhere"
	case Serve:
		return "the application itself, and the thing the others watch. " +
			"A bug here is the one an attacker is most likely to reach"
	case Record:
		return "the account of what happened. Everything appends and " +
			"nothing edits, which is the property internal/logd enforces " +
			"by not handing the application a descriptor it could seek"
	}
	return string(s)
}

// Outward reports whether this side holds authority at somebody else's
// system.
func (s Side) Outward() bool { return s == Collect }

// Part is one capability of this program, and what it holds.
type Part struct {
	Name string `json:"name"`
	Side Side   `json:"side"`
	What string `json:"what"`
	// Holds is what an attacker gets by compromising it, in one sentence.
	Holds string `json:"holds"`
	// Tamper says how this part is stopped from editing its own record.
	// Empty means it writes no record, which is its own answer.
	Tamper string `json:"tamper,omitempty"`
}

// Parts is what this program is made of, by side.
//
// The list is deliberately short. A boundary that names forty components
// is a diagram rather than a decision, and the decision here is about one
// line.
func Parts() []Part {
	return []Part{
		{
			Name: "collector", Side: Collect,
			What:  "fetches records from the platforms an estate uses",
			Holds: "read access at every platform a connector is configured for",
			Tamper: "it writes to internal/spool, whose segments are " +
				"append-only and sealed with a digest, so a collector that " +
				"is compromised can add events and cannot remove the ones " +
				"already there",
		},
		{
			Name: "detection", Side: Analyse,
			What:  "runs rules and correlations over what was collected",
			Holds: "the collected events, and nothing that reaches outside",
			Tamper: "a decision about a finding goes into the audit chain, " +
				"which the application cannot rewrite",
		},
		{
			Name: "vulnerability", Side: Analyse,
			What: "compares an inventory against an advisory database",
			Holds: "a bill of materials the build produced and a public " +
				"database. No credential at anybody else's system",
			Tamper: "an assessment is a recorded decision with a reason, " +
				"in the chain",
		},
		{
			Name: "compliance", Side: Analyse,
			What: "assembles evidence about this system for somebody else",
			Holds: "the evidence, which is about this deployment and not " +
				"about anybody else's",
			Tamper: "internal/engagement issues a signed package a firm " +
				"verifies without touching this system, so the subject of " +
				"an assessment cannot quietly edit the assessment",
		},
		{
			Name: "application", Side: Serve,
			What:  "the content store, the admin and the public site",
			Holds: "the content, and whatever credentials publishing needs",
			Tamper: "internal/logd runs the audit writer as a different " +
				"account, so code execution as the application cannot " +
				"seek, truncate or reorder the log of what it did",
		},
		{
			Name: "audit", Side: Record,
			What:  "the account of what happened",
			Holds: "everything, in the sense that it describes everything",
			Tamper: "a hash chain with dual-signed heads. Root can still " +
				"rewrite the file and cannot rewrite a head that was " +
				"already published",
		},
	}
}

// Find looks a part up.
func Find(name string) (Part, bool) {
	for _, p := range Parts() {
		if strings.EqualFold(p.Name, name) {
			return p, true
		}
	}
	return Part{}, false
}

// On is every part on a side.
func On(s Side) []Part {
	var out []Part
	for _, p := range Parts() {
		if p.Side == s {
			out = append(out, p)
		}
	}
	return out
}

// Together says what running two parts in one process costs.
//
// The question a deployment actually asks, and the answer is not always
// "do not". Running the detection and vulnerability parts together costs
// nothing: neither holds anything the other does not. Running the
// collector with the application is the one that matters, and saying so
// specifically is more useful than a rule that separates everything.
func Together(a, b string) (string, bool) {
	x, okA := Find(a)
	y, okB := Find(b)
	if !okA || !okB {
		return "", false
	}
	if x.Name == y.Name {
		return "", false
	}
	switch {
	case x.Side.Outward() && y.Side == Serve,
		y.Side.Outward() && x.Side == Serve:
		return fmt.Sprintf(
			"%s holds %s, and %s is the part most exposed to whatever "+
				"arrives from outside. Run together, a bug in the second "+
				"reaches the first, and the blast radius stops being this "+
				"deployment and becomes every platform a connector is "+
				"configured for",
			outward(x, y).Name, outward(x, y).Holds, served(x, y).Name), true
	case x.Side == Record || y.Side == Record:
		return fmt.Sprintf(
			"%s is the account of what %s did, and a process that can "+
				"write its own record can edit it. internal/logd exists "+
				"for exactly this and is the answer rather than a warning",
			recordOf(x, y).Name, otherThanRecord(x, y).Name), true
	case x.Side.Outward() && y.Side == Analyse,
		y.Side.Outward() && x.Side == Analyse:
		return fmt.Sprintf(
			"%s reaches outward and %s does not. Together is ordinary and "+
				"the cost is that the analysing half inherits the "+
				"collector's exposure, which is worth knowing and is not "+
				"usually worth a second machine",
			outward(x, y).Name, analysed(x, y).Name), true
	}
	return fmt.Sprintf(
		"%s and %s both %s and neither holds anything the other does "+
			"not. Running them together costs nothing", x.Name, y.Name,
		sideVerb(x.Side)), true
}

func outward(a, b Part) Part {
	if a.Side.Outward() {
		return a
	}
	return b
}

func served(a, b Part) Part {
	if a.Side == Serve {
		return a
	}
	return b
}

func analysed(a, b Part) Part {
	if a.Side == Analyse {
		return a
	}
	return b
}

func recordOf(a, b Part) Part {
	if a.Side == Record {
		return a
	}
	return b
}

func otherThanRecord(a, b Part) Part {
	if a.Side == Record {
		return b
	}
	return a
}

func sideVerb(s Side) string {
	if s == Analyse {
		return "only read what was already collected"
	}
	return string(s)
}

// Generalises reports whether the separation argument for a part is the
// one that applies to everything, or the one that does not.
//
// The distinction this package exists for. "Nothing rewrites its own
// record" applies to every part and is already answered without
// separating anything. "The collector holds keys to somebody else's
// system" applies to one part and is the reason a line exists at all.
func (p Part) Generalises() bool { return !p.Side.Outward() }

// Sorted is the parts in side order, for a stable display.
func Sorted() []Part {
	out := append([]Part(nil), Parts()...)
	rank := map[Side]int{}
	for i, s := range Sides {
		rank[s] = i
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Side] != rank[out[j].Side] {
			return rank[out[i].Side] < rank[out[j].Side]
		}
		return out[i].Name < out[j].Name
	})
	return out
}
