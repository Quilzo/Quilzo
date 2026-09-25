// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package telemetry is the event a detection reads and a log arrives as.
//
// # Why this is not the content store
//
// internal/form already makes this argument once, about form submissions, and
// every word of it applies here twice over:
//
//	A submission is personal data. Somebody has a right to have it erased,
//	and an append-only merkle store cannot erase anything.
//
// Telemetry is that, plus volume. The content store verifies a SHA-256 on
// every read and takes the ref lock on every write, which is exactly right for
// a page somebody publishes and absurd for a million authentication events an
// hour. So events live in their own store, and what goes in the audit chain is
// the *evidence about* them — which detection fired, who triaged it, what they
// concluded — because that is the part whose integrity anybody will later be
// asked to prove.
//
// # Shaped like OCSF, not conformant to it
//
// OCSF 1.9.0 is the interchange format and internal/siem already exports it.
// It is the wrong internal model: nine minor releases in under three years,
// 126 deprecations backfilled in 1.9 alone, and its own maintainers now run an
// LLM over pull requests because humans can no longer keep the schema
// internally consistent. Hand-maintaining Go structs against that, with no
// dependency to absorb the churn, is an unbounded tax for a benefit only
// needed at the boundary.
//
// So the cheap, stable, genuinely good parts are borrowed and the rest is not.
// The classification arithmetic is the good part:
//
//	class_uid = category_uid*1000 + class_index
//	type_uid  = class_uid*100    + activity_id
//
// Any consumer can bucket an event it has never seen by integer division
// alone. That is worth copying. Deep nesting and full-schema validation are
// not.
//
// # Two things OCSF gets wrong, fixed here because they are expensive later
//
// FIRST, DISPOSITION. OCSF has no disposition_id on its Network, HTTP or
// Process classes — the allow/block/deny field an analyst filters on before
// anything else, missing from precisely the classes where it decides whether
// an event is an attack or a stopped attack. It is on every event here.
//
// SECOND, IDENTIFIER PROVENANCE. OCSF flattens every identity to a bare
// user.uid. Microsoft's ASIM does not: it tags each identifier with the
// directory that issued it. Flattening is lossy in a way that cannot be undone
// downstream — "u-1043" from Okta and "u-1043" from an MDM are different
// people, and a correlation that treats them as one is worse than no
// correlation. Every identifier here carries its issuer, and that is what
// makes comparing a workforce across Okta, an MDM and a training platform a
// join rather than a guess.
//
// # Event time is not arrival time
//
// Both are recorded, always. A forwarder that buffers for six hours delivers
// events whose windows closed long ago, and a correlation engine that cannot
// tell the two apart either silently drops them or silently reopens windows.
// The literature on stream processing settled this with watermarks decades
// ago; security products mostly do not say what they do. Saying it requires
// having both numbers, so both are here from the start.
package telemetry

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Category is the top level of the classification, matching OCSF's
// category_uid so that an exported event needs no translation.
type Category uint16

const (
	CategorySystem      Category = 1
	CategoryFindings    Category = 2
	CategoryIAM         Category = 3
	CategoryNetwork     Category = 4
	CategoryDiscovery   Category = 5
	CategoryApplication Category = 6
	CategoryRemediation Category = 7
)

// Class identifies the event class. The value is category*1000 + index, which
// is OCSF's own arithmetic, so Category() below is division rather than a
// lookup table that can drift.
type Class uint32

const (
	ClassAuthentication  Class = 3002
	ClassAccountChange   Class = 3001
	ClassAPIActivity     Class = 6003
	ClassHTTPActivity    Class = 4002
	ClassNetworkActivity Class = 4001
	ClassProcessActivity Class = 1007
	ClassFileActivity    Class = 1001
	ClassDetection       Class = 2004
)

// Category is the category this class belongs to, derived rather than stored.
func (c Class) Category() Category { return Category(c / 1000) }

// Valid reports whether a class number is well-formed.
//
// The index has to be non-zero: category*1000 exactly is the category, not a
// class in it, and a source that emitted 3000 has told us it does not know
// what it is sending.
func (c Class) Valid() bool {
	cat := c.Category()
	return cat >= CategorySystem && cat <= CategoryRemediation && c%1000 != 0
}

// Disposition is what happened to the thing the event describes.
//
// First-class, on every event. See the package comment: OCSF leaves this off
// the classes where it matters most, and an analyst's first filter is almost
// always "show me what was not blocked".
type Disposition uint8

const (
	DispositionUnknown Disposition = 0
	// DispositionAllowed is the action completed.
	DispositionAllowed Disposition = 1
	// DispositionBlocked is a control stopped it. The distinction from
	// Allowed is the difference between an incident and a control working.
	DispositionBlocked Disposition = 2
	// DispositionDetected is it was noticed and not stopped, which is a third
	// thing and is the one that most often needs a person.
	DispositionDetected Disposition = 3
	// DispositionFailed is it did not complete for reasons unrelated to any
	// control — a wrong password, a network error. Not a security outcome,
	// and conflating it with Blocked inflates every "attacks stopped" figure.
	DispositionFailed Disposition = 4
)

var dispositionNames = map[Disposition]string{
	DispositionUnknown:  "unknown",
	DispositionAllowed:  "allowed",
	DispositionBlocked:  "blocked",
	DispositionDetected: "detected",
	DispositionFailed:   "failed",
}

func (d Disposition) String() string {
	if s, ok := dispositionNames[d]; ok {
		return s
	}
	return fmt.Sprintf("disposition(%d)", uint8(d))
}

// Severity follows OCSF's severity_id so it survives export unchanged.
type Severity uint8

const (
	SeverityUnknown  Severity = 0
	SeverityInfo     Severity = 1
	SeverityLow      Severity = 2
	SeverityMedium   Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
	SeverityFatal    Severity = 6
)

// ID is an identifier and the system that issued it.
//
// The pair, never the bare value. Two directories both issue "u-1043" and they
// are not the same person; a correlation that joins on the value alone has
// invented a relationship. This is the field that makes comparing a workforce
// across an identity provider, an MDM and a training platform a join rather
// than a guess, and it is the one OCSF discards.
type ID struct {
	// Issuer names the system whose namespace Value belongs to: "okta",
	// "entra", "aws", "kandji", "knowbe4". Lowercase, stable, chosen by
	// whoever wrote the connector and never by a model.
	Issuer string `json:"issuer"`
	Value  string `json:"value"`
}

func (i ID) String() string {
	if i.Issuer == "" {
		return i.Value
	}
	return i.Issuer + ":" + i.Value
}

// Zero reports whether an identifier says nothing.
func (i ID) Zero() bool { return i.Issuer == "" && i.Value == "" }

// Event is one thing that happened somewhere, normalised.
//
// Flat on purpose. Every field here is either something a detection predicate
// reads or something an analyst needs to see, and anything else belongs in
// Raw, where it costs nothing to carry and nothing to maintain.
type Event struct {
	// Time is when it happened, as the source reports it.
	Time time.Time `json:"time"`
	// Received is when this program took delivery.
	//
	// Not derivable from Time and not the same number. The gap is the whole
	// of what a correlation window has to reason about, and a store that kept
	// only one of them cannot answer "did we miss this because it arrived
	// late, or because nothing matched".
	Received time.Time `json:"received"`

	Class       Class       `json:"class"`
	Activity    uint8       `json:"activity"`
	Severity    Severity    `json:"severity"`
	Disposition Disposition `json:"disposition"`

	// Source is the connector that produced this: "aws/cloudtrail",
	// "crowdstrike/detections". Stable, because detections are written
	// against it.
	Source string `json:"source"`
	// Message is the human-readable summary, from the source.
	//
	// Attacker-controlled, like most of this struct. Nothing here should ever
	// reach a model's context without the isolation internal/agent applies to
	// stored content, for the reason that whoever can write a log line can
	// write a prompt.
	Message string `json:"message,omitempty"`

	// Actor is who did it, Target what it was done to.
	Actor  ID `json:"actor,omitempty"`
	Target ID `json:"target,omitempty"`
	// Device is where it happened.
	Device ID `json:"device,omitempty"`

	// Observables are the values worth pivoting on — addresses, hashes,
	// domains, ports. Kept as typed pairs rather than a free-form map so a
	// detection can ask for "every IP in this event" without knowing which
	// field a particular source put it in.
	Observables []Observable `json:"observables,omitempty"`

	// Raw is whatever else the source said, flattened to strings.
	//
	// Strings because a detection compares, and comparing across JSON's
	// number/string ambiguity is where normalisation bugs live. A connector
	// that wants a number typed puts it in a field above.
	Raw map[string]string `json:"raw,omitempty"`
}

// TypeUID is OCSF's type_uid: the class and the activity in one number.
func (e Event) TypeUID() uint32 { return uint32(e.Class)*100 + uint32(e.Activity) }

// Lateness is how long this event took to arrive.
//
// Negative when a source's clock runs ahead of ours, which happens constantly
// and is not an error. Returned rather than clamped so a caller can decide:
// a correlation window may want to ignore it, and a health check very much
// wants to know a fleet is minutes ahead.
func (e Event) Lateness() time.Duration { return e.Received.Sub(e.Time) }

// ObservableKind is what a pivotable value is.
type ObservableKind uint8

const (
	ObservableOther ObservableKind = iota
	ObservableIP
	ObservableHostname
	ObservableDomain
	ObservableURL
	ObservableEmail
	ObservableHash
	ObservableFile
	ObservableProcess
	ObservablePort
	ObservableUserAgent
)

var observableNames = map[ObservableKind]string{
	ObservableOther: "other", ObservableIP: "ip",
	ObservableHostname: "hostname", ObservableDomain: "domain",
	ObservableURL: "url", ObservableEmail: "email",
	ObservableHash: "hash", ObservableFile: "file",
	ObservableProcess: "process", ObservablePort: "port",
	ObservableUserAgent: "user_agent",
}

func (k ObservableKind) String() string {
	if s, ok := observableNames[k]; ok {
		return s
	}
	return "other"
}

// Observable is one pivotable value.
type Observable struct {
	Kind  ObservableKind `json:"kind"`
	Value string         `json:"value"`
	// Name is the field it came from, kept so an analyst can see whether an
	// address was the source or the destination without the detection having
	// to encode that in the value.
	Name string `json:"name,omitempty"`
}

// Of returns every observable of one kind, in the order they were recorded.
func (e Event) Of(kind ObservableKind) []string {
	var out []string
	for _, o := range e.Observables {
		if o.Kind == kind {
			out = append(out, o.Value)
		}
	}
	return out
}

// Validate refuses an event that cannot mean what it appears to.
//
// Called on the way in, once, by the ingest path. A detection that has to
// defend against malformed events is a detection nobody can read, and the
// cost of checking here is paid once per event rather than once per rule per
// event.
func (e Event) Validate() error {
	if e.Time.IsZero() {
		return fmt.Errorf("the event has no time, so nothing can window it")
	}
	if e.Received.IsZero() {
		return fmt.Errorf(
			"the event has no arrival time. It is not the same number as the " +
				"event time and cannot be derived from it: the gap is what " +
				"tells a late delivery from a quiet period")
	}
	if !e.Class.Valid() {
		return fmt.Errorf(
			"%d is not a class. The value is category*1000 + index, so a "+
				"multiple of 1000 names a category and not a class in it",
			e.Class)
	}
	if strings.TrimSpace(e.Source) == "" {
		return fmt.Errorf(
			"the event names no source. Detections are written against the " +
				"source, and one that arrives anonymously cannot be matched " +
				"by any of them or attributed by anybody reading it later")
	}
	for _, id := range []struct {
		what string
		id   ID
	}{{"actor", e.Actor}, {"target", e.Target}, {"device", e.Device}} {
		if id.id.Zero() {
			continue
		}
		if strings.TrimSpace(id.id.Issuer) == "" {
			return fmt.Errorf(
				"the %s is %q with no issuer. An identifier without the "+
					"system that issued it cannot be joined against another "+
					"system's — two directories both issue the same string "+
					"for different people", id.what, id.id.Value)
		}
		if strings.TrimSpace(id.id.Value) == "" {
			return fmt.Errorf("the %s names an issuer and no value", id.what)
		}
	}
	return nil
}

// Fields is every comparable value in an event, by name.
//
// The surface a detection predicate addresses. Built here rather than in the
// rule engine so that one answer to "what can a rule refer to" exists, and a
// rule naming something absent is a rule that can be refused at authoring
// time rather than one that silently never fires.
func (e Event) Fields() map[string]string {
	f := map[string]string{
		"source":      e.Source,
		"class":       fmt.Sprint(uint32(e.Class)),
		"activity":    fmt.Sprint(e.Activity),
		"severity":    fmt.Sprint(uint8(e.Severity)),
		"disposition": e.Disposition.String(),
		"message":     e.Message,
	}
	for name, id := range map[string]ID{
		"actor": e.Actor, "target": e.Target, "device": e.Device,
	} {
		if id.Zero() {
			continue
		}
		f[name] = id.String()
		f[name+".issuer"] = id.Issuer
		f[name+".value"] = id.Value
	}
	for _, o := range e.Observables {
		// Addressable by kind, so a rule can say "any ip" without knowing
		// which field carried it.
		k := o.Kind.String()
		if existing, ok := f[k]; ok {
			f[k] = existing + " " + o.Value
			continue
		}
		f[k] = o.Value
	}
	for k, v := range e.Raw {
		// Prefixed, so a source cannot shadow a field a rule relies on by
		// naming one of its own attributes "severity".
		f["raw."+k] = v
	}
	return f
}

// FieldNames is Fields' keys, sorted, for telling an author what exists.
func (e Event) FieldNames() []string {
	f := e.Fields()
	out := make([]string, 0, len(f))
	for k := range f {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
