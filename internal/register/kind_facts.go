// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import "fmt"

// The kinds that hold what is known: where facts come from, what they are
// about, and the facts themselves. Nothing here is a judgement. A test reads
// these and a person decides on the result; see kind_programme.go and
// kind_decisions.go.

// Local is the source of a record somebody made in Quilzo, where no outside
// system gave it a key: a control, a risk, a scope.
const Local = "quilzo"

// AssetType is what sort of thing an asset is.
type AssetType string

// Values lists the asset types.
func (AssetType) Values() []string {
	return []string{"device", "application", "repository", "cloud-resource", "data-store", "network", "other"}
}

// Asset is a thing the organisation runs or holds that facts are about: a
// laptop, a repository, a cloud account.
type Asset struct {
	Source  ID        `json:"source" reg:"required,ref=Source" about:"the source that reported it"`
	Ref     string    `json:"ref" reg:"required,label" about:"its identifier in that source: a serial number, a host name, a cloud resource's ID"`
	Type    AssetType `json:"type" reg:"required" about:"what sort of thing it is"`
	Name    string    `json:"name,omitempty" reg:"label" about:"what people call it"`
	Owner   ID        `json:"owner,omitempty" reg:"ref=Subject" about:"who answers for it"`
	Service ID        `json:"service,omitempty" reg:"ref=Service" about:"the service it is part of"`
}

func (Asset) Kind() Kind              { return KindAsset }
func (a Asset) Key() (string, string) { return string(a.Source), string(a.Type) + "/" + a.Ref }
func (Asset) Check() error            { return nil }
func (a Asset) index(r *Row) {
	r.About, r.Via, r.State = a.Source.bytes(), a.Service.bytes(), ordinal(a.Type)
}

// KindAsset and the rest name the kinds. The define beside each is what
// makes the kind one the register has.
const KindAsset Kind = "Asset"

var _ = define[Asset]("A thing the organisation runs or holds that facts are about.", ClassInternal)

// SubjectType is what sort of person or account a subject is.
type SubjectType string

// Values lists the subject types.
func (SubjectType) Values() []string {
	return []string{"person", "account", "service-account", "agent"}
}

// Subject is a person or an account, under a pseudonym. The record holds
// nothing that names them: who the pseudonym belongs to is kept in a map
// outside the store, which can be erased, and after that the pseudonym is an
// identifier of nobody.
type Subject struct {
	Pseudonym ID          `json:"pseudonym" reg:"required" about:"the random identifier that stands for them; it is also this record's identifier"`
	Type      SubjectType `json:"type" reg:"required" about:"whether it is a person, an account, a service account or an agent"`
}

func (Subject) Kind() Kind              { return KindSubject }
func (s Subject) Key() (string, string) { return Local, string(s.Pseudonym) }
func (Subject) Check() error            { return nil }
func (s Subject) index(r *Row)          { r.State = ordinal(s.Type) }

// minted says the record's identifier is its pseudonym and not a hash of
// it: see NewSubjectID.
func (s Subject) minted() ID { return s.Pseudonym }

const KindSubject Kind = "Subject"

var _ = define[Subject]("A person or an account, under a pseudonym.", ClassRestricted)

// SourceType is how a source's facts arrive.
type SourceType string

// Values lists the source types.
func (SourceType) Values() []string {
	return []string{"connector", "ci", "import", "upload", "manual"}
}

// SourceBy is the kind of actor that made a source: a person, or a
// service (a connector's run, a pipeline, a tool that sends files).
type SourceBy string

// Values lists the kinds of actor a source may belong to.
func (SourceBy) Values() []string { return []string{"person", "service"} }

// Source is where facts come from: a connector to an identity provider, a
// pipeline that pushes results, an importer, a person uploading a file.
type Source struct {
	Name  string     `json:"name" reg:"required,slug" about:"its machine name, which is its natural key"`
	Type  SourceType `json:"type" reg:"required" about:"how its facts arrive"`
	Title string     `json:"title,omitempty" reg:"label" about:"what people call it"`
	Fresh int64      `json:"fresh" reg:"required,min=1" about:"how many seconds may pass between runs before its facts are stale"`
	Hosts []string   `json:"hosts,omitempty" reg:"host" about:"the only hosts it may connect to"`
	Grade Grade      `json:"grade" reg:"required" about:"the grade of the facts it yields"`
	// Write says the source holds a scope that can change the system it
	// reads. A source reads unless a person approved otherwise.
	Write    bool      `json:"write,omitempty" about:"it holds a scope that can change the system it reads"`
	Approval *Approval `json:"approval,omitempty" about:"the approval of its write scope"`
	// By is the kind of actor that made the source, and the only kind
	// whose facts are filed under it: a table a person uploads cannot
	// overwrite what a connector observed, because a connector's source is
	// a service's. Empty on a source made before this was recorded.
	By SourceBy `json:"by,omitempty" about:"the kind of actor that made it, and the only kind whose facts it takes"`
	// Owner is who answers for the source being fresh, and is mailed when
	// it is not.
	Owner ID `json:"owner,omitempty" reg:"ref=Subject" about:"who answers for it, and is told when it is stale"`
	// Recipe, Region and Params say what a connector runs: a recipe the
	// program ships, the region of the tool it reads, and the values that
	// recipe takes (an Entra tenant, a GitHub organisation), each name=value
	// and each checked by the recipe's own pattern before it is used.
	Recipe string   `json:"recipe,omitempty" reg:"slug" about:"the shipped recipe a connector runs"`
	Region string   `json:"region,omitempty" reg:"slug" about:"the region of the tool the recipe reads"`
	Params []string `json:"params,omitempty" reg:"label" about:"the values the recipe takes, each name=value"`
	// Repository and Workflow say which pipeline may push to a source of
	// type ci: a job whose platform-signed identity names that repository
	// and that workflow, and no other.
	Repository string `json:"repository,omitempty" reg:"label" about:"the repository whose pipeline pushes to it"`
	Workflow   string `json:"workflow,omitempty" reg:"label" about:"the workflow of that repository whose jobs push to it"`
}

func (Source) Kind() Kind              { return KindSource }
func (s Source) Key() (string, string) { return Local, s.Name }
func (s Source) Check() error {
	if s.Write && s.Approval == nil {
		return fmt.Errorf("a source reads only, unless its write scope carries an approval")
	}
	if s.Type == "connector" && len(s.Hosts) == 0 {
		return fmt.Errorf("a connector names the hosts it may connect to; with none it can reach nothing")
	}
	if s.Type == "connector" && s.Recipe == "" {
		return fmt.Errorf("a connector names the recipe it runs")
	}
	if s.Type == "ci" && (s.Repository == "" || s.Workflow == "") {
		return fmt.Errorf("a pipeline's source names the repository and the workflow whose jobs may push to it")
	}
	if s.Grade == GradeConnector && s.Type != "connector" || s.Grade == GradeCI && s.Type != "ci" {
		return fmt.Errorf("a source's facts are graded by how they arrive: a connector's are pulled, a pipeline's pushed")
	}
	return nil
}
func (s Source) index(r *Row) {
	r.N, r.State, r.Grade = clamp32(s.Fresh), ordinal(s.Type), ordinal(s.Grade)
	if s.Write {
		r.Flags |= FlagWrite
	}
}

const KindSource Kind = "Source"

var _ = define[Source]("Where facts come from, with how fresh they must be and what it may reach.", ClassInternal)

// Observation is the latest typed fact about one thing from one source:
// that an account has a second factor registered, that a disk is encrypted.
//
// There is one record per source, thing and fact. A new run that finds the
// same value writes nothing, so "last seen" is the source's run and not a
// field here, and the history of a fact is the history of its record's
// commits.
type Observation struct {
	Source ID     `json:"source" reg:"required,ref=Source" about:"the source that said it"`
	About  ID     `json:"about" reg:"required" about:"the asset or subject the fact is about"`
	Fact   string `json:"fact" reg:"required,slug" about:"the fact's name, such as mfa.registered"`
	Value  Scalar `json:"value" reg:"required" about:"what the source said: text, a number or a yes or no"`
	Grade  Grade  `json:"grade" reg:"required" about:"how the fact reached the record"`
	Raw    Digest `json:"raw,omitempty" about:"the sealed raw evidence the fact was read from"`
	// Place is where in the raw file the fact was read: a cell, a row, or
	// a JSON pointer. Taint says it was read from a part of the file that
	// a person opening it would not see.
	Place string `json:"place,omitempty" reg:"label" about:"where in the raw file it was read: a cell, a row or a JSON pointer"`
	Taint Taint  `json:"taint,omitempty" about:"the part of the file it was read from that a person opening it would not see"`
}

func (Observation) Kind() Kind { return KindObservation }
func (o Observation) Key() (string, string) {
	return string(o.Source), string(o.About) + "/" + o.Fact
}
func (Observation) Check() error { return nil }
func (o Observation) index(r *Row) {
	r.About, r.Via, r.Grade = o.About.bytes(), o.Source.bytes(), ordinal(o.Grade)
}

const KindObservation Kind = "Observation"

var _ = define[Observation]("The latest typed fact about one thing from one source.", ClassRestricted)

// LinkOn is the identifier two records were found to share.
type LinkOn string

// Values lists the identifiers a link may be made on. An e-mail address is
// never one of them: a link on people is made on the hash of their address,
// which a source reports in place of it, so the address is not kept here.
func (LinkOn) Values() []string {
	return []string{"serial", "hostname", "cloud-id", "upn", "email-hash"}
}

// Link says two records from two sources are the same thing, because they
// carry the same identifier, exactly. Code makes a link and nothing else
// does: a near match is not a match.
type Link struct {
	A     ID     `json:"a" reg:"required" about:"one of the two records; the lesser identifier"`
	B     ID     `json:"b" reg:"required" about:"the other record"`
	On    LinkOn `json:"on" reg:"required" about:"the identifier they share"`
	Match Digest `json:"match" reg:"required" about:"the digest of the shared identifier's value, which is not itself kept"`
}

func (Link) Kind() Kind { return KindLink }
func (l Link) Key() (string, string) {
	return Local, string(l.A) + "/" + string(l.B) + "/" + string(l.On)
}
func (l Link) Check() error {
	if l.A >= l.B {
		return fmt.Errorf("a link names two different records, the lesser identifier first, so one pair has one link")
	}
	return nil
}
func (l Link) index(r *Row) { r.About, r.Via, r.State = l.A.bytes(), l.B.bytes(), ordinal(l.On) }

const KindLink Kind = "Link"

var _ = define[Link]("Two records from two sources that are the same thing, by an exact identifier.", ClassRestricted)

// Population is a set that coverage is counted against: every member of
// staff, every laptop. It is the N of "n of N", so it says where N comes
// from and what would notice if that source were wrong.
type Population struct {
	Name   string `json:"name" reg:"required,slug" about:"its machine name, which is its natural key"`
	Title  string `json:"title,omitempty" reg:"label" about:"what people call it"`
	Source ID     `json:"source" reg:"required,ref=Source" about:"the source its members are read from"`
	Query  Digest `json:"query" reg:"required" about:"the digest of the typed query that selects its members"`
	Fresh  int64  `json:"fresh" reg:"required,min=1" about:"how many seconds old the count may be"`
	// Independent says the source is not the tool being measured. A
	// population drawn from the tool it measures is circular, and is
	// labelled so wherever it is shown.
	Independent bool   `json:"independent,omitempty" about:"the source is not the tool the population is used to measure"`
	CrossCheck  ID     `json:"cross_check,omitempty" reg:"ref=Source" about:"a second source the count is compared with"`
	Size        int64  `json:"size" reg:"min=0" about:"how many members it had when last counted"`
	Members     Digest `json:"members,omitempty" about:"the digest of its members when last counted"`
	// CrossQuery selects what the second source knows of, and the count
	// keeps both numbers and the disagreement between them as a number of
	// its own: members on either side the other side has no counterpart
	// for, by an exact link or the same record.
	CrossQuery  Digest `json:"cross_query,omitempty" about:"the digest of the typed query that selects what the cross-check source knows of"`
	CrossSize   int64  `json:"cross_size,omitempty" reg:"min=0" about:"how many the cross-check source knew of when last counted"`
	Unexplained int64  `json:"unexplained,omitempty" reg:"min=0" about:"how many, on either side, the other source has no counterpart for"`
	Counted     Time   `json:"counted,omitempty" about:"when it was last counted"`
	Commit      string `json:"commit,omitempty" reg:"oid" about:"the register commit it was last counted at"`
}

func (Population) Kind() Kind              { return KindPopulation }
func (p Population) Key() (string, string) { return Local, p.Name }
func (p Population) Check() error {
	if p.CrossCheck != "" && p.CrossCheck == p.Source {
		return fmt.Errorf("a population cannot be cross-checked against the source it is read from")
	}
	if (p.CrossCheck == "") != (p.CrossQuery == "") {
		return fmt.Errorf("a cross-check names the second source and the query that selects what it knows of, both or neither")
	}
	if p.CrossCheck == "" && (p.CrossSize != 0 || p.Unexplained != 0) {
		return fmt.Errorf("a population with one source has no second count to disagree with")
	}
	if p.Unexplained > p.Size+p.CrossSize {
		return fmt.Errorf("more are unexplained than the two sources hold between them")
	}
	return nil
}
func (p Population) index(r *Row) {
	r.About, r.Via, r.N, r.M = p.Source.bytes(), p.CrossCheck.bytes(), clamp32(p.Size), clamp32(p.Fresh)
	if p.Independent {
		r.Flags |= FlagIndependent
	}
}

const KindPopulation Kind = "Population"

var _ = define[Population]("A set that coverage is counted against, with where its count comes from.", ClassInternal)

// Verdict is what a check of an extracted value found.
type Verdict string

// Values lists the verdicts.
func (Verdict) Values() []string { return []string{"unchecked", "verified", "refuted"} }

// Extracted is a value a model read out of a document: an audit opinion, a
// report's period, a certificate's expiry. It records where in the sealed
// file the value was read and what checked it.
//
// It is never evidence. No figure, status or coverage reads this kind. A
// value here reaches the record as Evidence only when code has found the
// quote at its place in the raw file and parsed the value from it, or when
// a person confirms it.
type Extracted struct {
	Raw   Digest `json:"raw" reg:"required" about:"the sealed document it was read from"`
	Field string `json:"field" reg:"required,slug" about:"which value was looked for"`
	Value Scalar `json:"value" reg:"required" about:"the value as the model gave it"`
	Quote Text   `json:"quote" reg:"required" about:"the words quoted from the document, held as a digest"`
	Page  int64  `json:"page,omitempty" reg:"min=1" about:"the page the quote is on"`
	Start int64  `json:"start" reg:"min=0" about:"where the quote begins in the raw file, in bytes"`
	End   int64  `json:"end" reg:"min=0" about:"where the quote ends in the raw file, in bytes"`
	Route string `json:"route" reg:"required,slug" about:"the model route that read it, by its configured name"`
	// Span is what code found when it looked for the quote at its place;
	// Checker is what a second model, shown only that span, concluded.
	Span      Verdict   `json:"span" reg:"required" about:"whether code found the quote at its place in the raw file"`
	Checker   Verdict   `json:"checker,omitempty" about:"what the checker, shown only the located span, concluded"`
	Confirmed *Approval `json:"confirmed,omitempty" about:"a person's confirmation of the value"`
}

func (Extracted) Kind() Kind              { return KindExtracted }
func (e Extracted) Key() (string, string) { return string(e.Raw), e.Field }
func (e Extracted) Check() error {
	if e.End < e.Start {
		return fmt.Errorf("the quote ends before it begins")
	}
	return nil
}
func (e Extracted) index(r *Row) { r.State, r.Grade = ordinal(e.Span), ordinal(e.Checker) }

const KindExtracted Kind = "Extracted"

var _ = define[Extracted]("A value a model read out of a document, with where it was read. Never evidence.",
	ClassConfidential, unconfirmed)
