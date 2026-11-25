// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package register is the security record of an organisation: its controls
// and the evidence for them, its risks and the decisions made about them,
// what it depends on and what went wrong.
//
// This file is the guide for whoever builds a security module on it. It
// says what the register is, how to define behaviour over a kind, how to
// write through Put, how to register a module's surfaces, and how to draw
// its screens with the security kit. Each part names the file that says
// more.
//
// # What it is
//
// The register is typed records in collections whose names begin sec_
// (Prefix), on the store ref "register" (Ref), which is never promoted to
// a site. Each kind is a Go struct whose field types and tags are its schema
// (kind.go, types.go, validate.go). The kinds are defined in files by what
// they hold:
//
//	kind_facts.go      Asset, Subject, Source, Observation, Link, Population, Extracted
//	kind_programme.go  Control, Requirement, Mapping, Scope, Applicability,
//	                   ControlTest, TestRun, Evidence
//	kind_decisions.go  Risk, Exception, Decision, RiskAppetite, MetricValue
//	kind_estate.go     Service, Vendor, AISystem, Incident, Policy, Acknowledgement
//	kind_evidence.go   RawFile, ColumnMap, PinnedKey: how evidence came in
//
// and an Approval is embedded in the record it decides, never filed apart.
// Facts that were collected (Observation), runs of a test (TestRun) and
// what a run shows of a control (Evidence) are three kinds, so a figure can
// be followed from the board's number to the members that were counted.
// What a model read out of a document is Extracted, which no figure,
// status or coverage reads; it becomes Evidence only when code finds the
// quote at its place in the sealed file or a person confirms it.
//
// Three rules are rules of the types, not of call sites:
//
//   - A person is a Subject's identifier (ID, 128 random bits, NewSubjectID),
//     never a name or an address. The map from pseudonym to person lives
//     outside the store, where it can be erased.
//   - Free text is a Text: the digest of words kept in an erasable side
//     store, never the words. A plain string field must say it is a label,
//     a slug, a host or an oid, and a label is one short visible line.
//   - A record's identifier is derived (id.go): the first 32 hexadecimal
//     characters of SHA-256 over the kind's collection, the source and the
//     natural key, framed and domain-separated, fixed for good. Two writers
//     of one fact write one record, and a run that finds nothing new writes
//     nothing.
//
// # Defining a kind, and behaviour over one
//
// A kind is a struct that implements Record (Kind, Key, Check) and is added
// by one call to define, beside it, in the file that declares it:
//
//	type Thing struct {
//		Name  string `json:"name" reg:"required,slug" about:"its machine name, which is its natural key"`
//		Owner ID     `json:"owner" reg:"required,ref=Subject" about:"who answers for it"`
//	}
//	func (Thing) Kind() Kind              { return KindThing }
//	func (t Thing) Key() (string, string) { return Local, t.Name }
//	func (Thing) Check() error            { return nil } // rules over more than one field
//	const KindThing Kind = "Thing"
//	var _ = define[Thing]("What a thing is, in one sentence.", ClassInternal)
//
// define reads the schema from the struct and panics on a kind declared
// wrongly, so a mistake fails the first test that runs. Its options say a
// kind is a decision that carries its approval (signed), is never changed
// once written (immutable), or holds a model's reading (unconfirmed). A
// kind that should be counted fast gives itself an index method filling a
// Row (index.go): two identifiers it points at, a moment, two counts, a
// state and a grade, in eighty bytes. A new kind needs no edit to any list:
// the screens, the command line, the API and the tests read Kinds().
//
// Behaviour over a kind (a control test, the lapse of an exception, a
// posture rule) is code in the module that owns it, reading the register
// through Get, List, Counts, Census and Index, and writing what it
// concludes through Put. Read the index for figures: Index().Rows(kind) is
// a sorted slice of rows, and Coverage (coverage.go) is how such a count is
// written, a pass over rows and never a score. Nothing reads the proposals
// ref to make a figure; the index cannot, because it is built from Ref.
//
// # Writing through Put
//
// Put is the one write path (put.go), in one order: the policy gate for
// each kind in the batch, the kind's field rules and its Check, the
// approval where the kind is a decision (Register.Approvals verifies its
// authentication evidence), unchanged records skipped, one commit for the
// batch, an audit entry and a Receipt whose digest is in that entry. A
// model never writes: an Actor of kind audit.KindAI is refused (ErrModel),
// as is one that is neither a person nor a service, and a statement about a
// control is a person's. An approval made alone is a team of one's: with
// anybody else eligible, the person who asked is not the one who agrees. On the command line a
// module writes like this:
//
//	r, by, err := registerWriter(root, caller) // cmd/quilzo/registercmd.go
//	rc, err := r.Put(by, "entra users, run of 24 Nov 2026 10:00", recs...)
//
// registerWriter wires the store's audit log, refuses to write while it
// cannot take an entry, and asks the policy as the caller. why is a line
// code writes. The errors are ErrRefused, ErrModel, ErrInvalid,
// ErrImmutable, ErrNotFound and ErrUnrecorded (written, and not recorded);
// registerError answers them with the command line's exits, 3 for a
// refusal and 4 for what is not there, and the API answers 403 and 404. A
// crew or a model
// proposes instead: Propose puts records on "register-proposals"
// (ProposalsRef, proposals.go), they wait in the one list of what waits
// (internal/waiting, quilzo approvals, the admin's Approvals) and on
// /register/proposals, and a person who did not propose them Accepts, with
// their own approval for a decision, or Rejects.
//
// The generic record surfaces refuse every sec_ name
// (collection.Reserved), and a test walks them; a module never writes the
// register any other way. Nor does a generic surface read it: one that
// reads whatever ref or commit it is told to asks Holds first, so the
// site's export refuses the register, and the history and a replica's ref
// ask about Area as the register's own surfaces do.
//
// # Registering a module's surfaces
//
// Every capability is reached four ways, and each surface has a
// registration a module calls from an init in a file of its own, so two
// modules built side by side edit no shared list. Each registration writes
// what it registered into this package's ledger (surface.go), under the
// module's name, and a test of the command line fails any module that is
// missing a surface and does not say why with Without.
//
//   - Command line and agent interface: cmd/quilzo/modules.go, registerCLI
//     with a cliModule: the command, its section and lines of the help, its
//     cmdSomething function (switch on args[0] for subcommands), its rows of
//     the privilege table and its area, the lines that read (each must
//     answer --json) and a line naming nothing (exit 4), and ops, which
//     registers its MCP operations, each with NeedsRole and Area. The tests
//     that read main.go's switch, the help and the tables read it too.
//   - Admin: internal/admin/modules.go, registerScreens: routes as method
//     expressions, and a menu entry with its section, its icon by name in
//     internal/icons, its page of the manual, the permission and the area it
//     is shown for, and its other names for Find. Templates are the
//     module's own files in internal/admin/assets.
//   - Content API: internal/api/modules.go, registerRoutes: read routes
//     under /api/v1/, each with its OpenAPI path item, and in a test file of
//     the module an entry in moduleExamples saying how each is tried.
//
// The register's own module is the example to copy:
// cmd/quilzo/registercmd.go (quilzo register kinds | list KIND | show ID |
// proposals, and the register_kinds, register_list and register_show
// operations), internal/admin/registerscreen.go (/register and below) and
// internal/api/registerapi.go (/api/v1/register/...). Each asks for view on
// Area, the compliance area's part of the policy, which a role over the
// site reaches only as administrator.
//
// # Drawing a screen with the security kit
//
// The values are internal/seckit's and the markup is the named templates
// of internal/admin/assets/seckit.html; a screen passes values and writes
// no figure of its own. A seckit.Figure is n of N of something named, made
// only by seckit.New from typed values, and refused without its sources,
// the moment its facts are from, a hash to check it against and its grade;
// a seckit.Badge is a word with an icon that has its own text alternative.
// The parts:
//
//	{{template "kit-header" .Header}}      the page's one h1, and its lead
//	{{template "kit-tiles" .Tiles}}        posture tiles: n of N, sources, age; no score
//	{{template "kit-table" .Table}}        a caption, scoped headings, rows of cells
//	{{template "kit-evidence" .Evidence}}  what shows how something stood
//	{{template "kit-badge" .Status}}       a status, never colour alone
//	{{template "kit-approval" .Approval}}  what is approved, its hash, who may approve
//	{{template "kit-timeline" .Events}}    what happened, when
//	{{template "kit-empty" .Empty}}        nothing to show, and what would
//	{{template "kit-errors" .Problems}}    the error summary at the top of a form
//	{{template "kit-field-error" .Problem}} the error beside its field
//	{{template "kit-live" .Said}}          an update, announced
//
// A figure's provenance is behind a disclosure a keyboard opens, never a
// hover. No part writes a script or a style attribute; the stylesheet's
// security kit section reflows to 320 pixels, moves nothing and draws
// borders in forced colours. Run a new screen's pages through internal/a11y
// in a test, as internal/admin/seckit_test.go runs every part.
//
// # Scale
//
// The probe (probe.go) makes the register one organisation is meant to
// reach, the same every time: ten thousand observations, a thousand
// controls and a hundred and fifty thousand test runs and pieces of
// evidence. Its index is 12.4 MB, under the bound of 15 MB per 150,000
// rows, and coverage over the thousand controls takes about 2 ms, under the
// bound of a second; both bounds are tests (scale_test.go), and
// BenchmarkCoverageMapIndex and BenchmarkCoverageTypedIndex compare the
// generic index with this one.
package register
