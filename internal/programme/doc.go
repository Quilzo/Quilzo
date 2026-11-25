// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package programme is the security programme kept in the register: what
// the organisation has to do (requirements, from starters in Quilzo's own
// words), what it decided applies (the statement of applicability, within
// a scope a person approved), what it does (controls, mapped to the
// requirements in NIST IR 8477's relationships), and what shows a control
// working (control tests, their runs and the evidence each run leaves),
// counted against populations whose denominators say where they come from.
//
// It is behaviour over the register's kinds (internal/register), and it
// writes only through register.Put, register.Propose and the acceptance of
// a proposal. It never writes a figure: every count is code over records,
// and no model's words reach a status, a date or a name.
//
// # Requirements and starters
//
// A starter (starter.go) is one framework's requirements, referred to by
// the framework's own identifiers, each with a line in Quilzo's own words:
// ISO/IEC 27001:2022 Annex A, NIS2 Article 21(2)(a) to (j), the SOC 2 Trust
// Services Criteria, DORA's chapters on ICT risk, incidents, testing and
// third parties, NIST CSF 2.0 and ISO/IEC 42001:2023 Annex A. No
// standard's text is copied: the identifiers are what a reader looks the
// clause up by, in the copy they are licensed to read. Installing a starter
// is one decision, a Starter record with its approval, and one commit;
// taking it out is another. A NIS2 starter brings its mappings to ISO
// 27001, each a relation with its rationale.
//
// # The statement of applicability
//
// Each line (soa.go) is an Applicability record: whether a requirement
// applies within a Scope, why, and who approved it. Both are decisions and
// carry their approval. A requirement nobody has decided about is shown as
// such, and is never counted as applying or as not. Beside each line are
// the controls mapped to the requirement and how each stood at its latest
// run: evidence towards the requirement, never "compliant".
//
// # Control tests
//
// A test (ctest.go) is a typed query (query.go) and an assertion over a
// population: every member is selected, or none is. The query is a
// register record filed under its own digest; a term compares one field by
// equals, not-equals, in, exists or absent, and there are no expressions.
// A person approves a test, its approval bound to the test by the hash of
// what they were shown, its population's source and query among it, so a
// population redefined since stops the test until it is approved again; and
// the scheduler then runs it (schedule.go). Each
// run reads the register at its head and writes a TestRun naming that
// commit, the digest of the members it ran over, the digest of what it read
// and the members that failed, by identifier, and an Evidence record. The
// explanation of a failure is code, made from the query's own terms and the
// failing identifiers. A replay (replay.go) reads the commit the run named
// and says whether it gives the same run.
//
// # Links and populations
//
// A link (link.go) joins two records from two sources that report the same
// identifier, compared byte for byte: a serial number, a host name, a cloud
// resource's identifier, the hash of an address. A near match is not a
// match, and an identifier two records of one source share links neither.
// A population (population.go) is the N of every "n of N": it says which
// source its members are read from, of a kind whose records name the
// source that reported them, is compared with a second source where there
// is one, and keeps the disagreement as a number of its own. One with
// no second source is labelled unchecked, and one drawn from the tool it is
// used to measure is labelled circular.
//
// # Who decides
//
// A decision (decide.go) is raised by a person as a proposal, where it
// waits, and is approved through the approvals module's engine, as every
// decision in the register is: under the organisation's separation policy,
// by somebody other than whoever raised it unless they are the only person
// eligible, who then approves it alone with a review by somebody else owed,
// each approval bound to the hash of exactly what was shown and kept with
// its authentication evidence. What a decision brings with it, a starter's
// requirements and a test's query, is written in the same commit.
//
// The pseudonym of each person who decides, and the words of a
// justification, are kept in the register's side store (words.go), where
// they can be erased; a record holds only the pseudonym and the digest.
//
// # Surfaces
//
// Four modules, each registered from its own files: `quilzo requirement`,
// `quilzo soa`, `quilzo control` and `quilzo population` with their
// operations on the agent interface (cmd/quilzo), the screens under
// /programme (internal/admin/programmescreen.go) and the read routes under
// /api/v1/requirements, /api/v1/soa, /api/v1/controls and
// /api/v1/populations (internal/api/programmeapi.go). The admin server runs
// the tests that are due on its timer.
//
// # Not here yet
//
// A replay reads the facts as the register held them at the run's commit,
// each named with the digest of the raw file it was read from; parsing
// those sealed files again is the importers'. Posture rows counted against
// populations, and the demonstration's data, are later themes'.
package programme
