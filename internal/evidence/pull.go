// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"errors"
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/register"
)

// Evidence that was not brought as a file: a connector's pull and a
// pipeline's push.
//
// Both go the way a file goes, because the way a file goes is what makes a
// fact checkable: sealed by its hash before anything reads it, read by code,
// the list of what it yielded kept beside the seal, and written through Put
// in one commit. What differs is the grade, and the grade is never the
// file's to give. A connector's run is graded "connector" because this
// program fetched it itself, from the hosts its source allows, with a
// credential from the vault; a pipeline's push is graded "ci" because the
// job proved, with a token its platform signed, which repository and which
// workflow it is. Neither can be named on the command line or in an
// import: Collect and Push are the only ways in, and each is called by the
// module that did the fetching or checked the job's token.
//
// # A connector's run is one sealed document
//
// What a run read is kept as one JSON document (FormatPull): the manifest
// it ran with, and each page as the tool sent it, in the order read. Its
// digest is the raw digest of every fact the run yields, and each fact's
// place is a JSON pointer into it. The recipe that turns pages into facts
// is code in the module that runs it, registered here (RegisterPuller), so
// reading the sealed document again, as Verify does, gives the same facts
// or says why not.

// FormatPull is a connector's run, sealed as one document. It is not a
// format anybody names: FormatNamed does not know it, and Read refuses it
// unless it came through Collect.
const FormatPull Format = "pull"

// Puller reads the facts of one recipe's run out of the document the run
// sealed, writing them to to. It is given the document's bytes as they were
// sealed and nothing else.
type Puller func(doc []byte, to PullTo) error

// PullTo is what a puller writes facts to. Everything it is handed is
// treated as text from the tool: names are labels, facts are slugs, and a
// person's or an account's name goes into the subject map and never into a
// record.
type PullTo interface {
	// Asset is the asset the tool reports by its own identifier.
	Asset(typ register.AssetType, ref, name, place string) (register.ID, error)
	// Subject is the pseudonym of an account the tool names, by the name
	// the tool uses (a user principal name, a login, an address).
	Subject(name string, typ register.SubjectType, place string) (register.ID, error)
	// Observe is one fact about an asset or a subject.
	Observe(about register.ID, fact string, v register.Scalar, place string) error
	// Note is something the run should say in plain words: what it did
	// not read, and why.
	Note(format string, args ...any)
}

var pullers = map[string]Puller{}

// RegisterPuller adds the puller of a recipe, by the recipe's name. It is
// called from an init of the module that runs the recipe.
func RegisterPuller(recipe string, p Puller) {
	if _, taken := pullers[recipe]; taken {
		panic("evidence: the recipe " + recipe + " has two pullers")
	}
	pullers[recipe] = p
}

// pulled is what Read knows of a connector's run: the source it was run
// for, and how an account's name becomes its pseudonym.
type pulled struct {
	source   register.Source
	subjects func(name string, typ register.SubjectType) (register.ID, error)
}

// Workload is a pipeline's job as its platform's signed token named it.
type Workload struct {
	// Platform is the issuer the token came from.
	Platform string `json:"platform"`
	// Repository is the repository the job ran in: GitHub's repository
	// claim, GitLab's project_path.
	Repository string `json:"repository"`
	// Workflow is the file the job's workflow is defined in, as the
	// repository holds it: .github/workflows/evidence.yml.
	Workflow string `json:"workflow"`
	// Ref and Run are the branch or tag and the run, for the record.
	Ref string `json:"ref,omitempty"`
	Run string `json:"run,omitempty"`
}

// pushed is what Read knows of a pipeline's push: the source it is filed
// under and the job that pushed it.
type pushed struct {
	source register.Source
	job    Workload
}

// ErrNotTheirs is a fact brought under a source that belongs to another
// kind of actor, or a push from a job the source does not name.
var ErrNotTheirs = errors.New("the source does not take facts from whoever brought these")

// Collect seals and reads a connector's run, as by, and writes what it
// yields graded "connector". by is the service the run was made as; src is
// the connector's source as the register holds it; doc is the run's
// document, which its recipe's puller reads.
func (g *Ingester) Collect(by register.Actor, why string, src register.Source, doc []byte) (Result, error) {
	if by.Kind != audit.KindService {
		return Result{}, fmt.Errorf("%w: a connector's run is written by the service that ran it", ErrNotTheirs)
	}
	if src.Type != "connector" || src.Grade != register.GradeConnector {
		return Result{}, fmt.Errorf("%w: %s is not a connector's source", ErrNotTheirs, src.Name)
	}
	if pullers[src.Recipe] == nil {
		return Result{}, fmt.Errorf("%w: no recipe called %q is built into this program", ErrUnreadable,
			plaintext.Clip(src.Recipe, 40, "…"))
	}
	in := Input{Format: FormatPull, Body: doc, Source: src.Name}
	in.pull = &pulled{source: src, subjects: g.Reg.SubjectFor}
	return g.Ingest(by, why, in)
}

// Push seals and reads a file a pipeline pushed, as by, and writes what it
// yields graded "ci", under the pipeline's source. The job is what its
// platform's token said, checked by the caller; it must be the repository
// and the workflow the source names, and every repository the file names
// must be that repository.
func (g *Ingester) Push(by register.Actor, why string, in Input, src register.Source, job Workload) (Result, error) {
	if by.Kind != audit.KindService {
		return Result{}, fmt.Errorf("%w: a pipeline's push is written by the job, as a service", ErrNotTheirs)
	}
	if err := PushAllowed(src, job); err != nil {
		return Result{}, err
	}
	if in.Format == FormatPull {
		return Result{}, fmt.Errorf("%w: a pipeline pushes a file in a format it names", ErrUnreadable)
	}
	in.Source = src.Name
	in.Map = nil
	in.pipeline = &pushed{source: src, job: job}
	return g.Ingest(by, why, in)
}

// PushAllowed reports whether a job may push to a source: the source is a
// pipeline's, and names the job's repository and workflow exactly.
func PushAllowed(src register.Source, job Workload) error {
	if src.Type != "ci" || src.Grade != register.GradeCI {
		return fmt.Errorf("%w: %s is not a pipeline's source", ErrNotTheirs, src.Name)
	}
	if job.Repository == "" || !strings.EqualFold(job.Repository, src.Repository) {
		return fmt.Errorf("%w: %s takes pushes from %s, and this job ran in %s", ErrNotTheirs, src.Name,
			src.Repository, plaintext.Clip(orNone(job.Repository), 120, "…"))
	}
	if job.Workflow == "" || job.Workflow != src.Workflow {
		return fmt.Errorf("%w: %s takes pushes from the workflow %s, and this job ran %s", ErrNotTheirs, src.Name,
			src.Workflow, plaintext.Clip(orNone(job.Workflow), 120, "…"))
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "none named"
	}
	return s
}

// readPull is the reader of a connector's run: its recipe's puller, over
// the document as it was sealed.
func readPull(rd *reader) error {
	p := rd.in.pull
	if p == nil {
		return fmt.Errorf("%w: a connector's run is read only as the connector's own", ErrUnreadable)
	}
	read := pullers[p.source.Recipe]
	if read == nil {
		return fmt.Errorf("%w: no recipe called %q is built into this program", ErrUnreadable, p.source.Recipe)
	}
	return read(rd.in.Body, pullTo{rd})
}

func init() { readers[FormatPull] = readPull }

// pullTo is a reader as a puller writes to it.
type pullTo struct{ rd *reader }

func (p pullTo) Asset(typ register.AssetType, ref, name, place string) (register.ID, error) {
	return p.rd.asset(typ, ref, name, place)
}

func (p pullTo) Subject(name string, typ register.SubjectType, place string) (register.ID, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("%w: an account at %s has no name", ErrUnreadable, place)
	}
	if p.rd.in.pull == nil || p.rd.in.pull.subjects == nil {
		return "", fmt.Errorf("%w: this read cannot name an account", ErrUnreadable)
	}
	id, err := p.rd.in.pull.subjects(name, typ)
	if err != nil {
		return "", fmt.Errorf("the account at %s could not be given its pseudonym: %w", place, err)
	}
	if _, err := p.rd.add(register.Subject{Pseudonym: id, Type: typ}, place, "", "subject", string(typ)); err != nil {
		return "", err
	}
	return id, nil
}

func (p pullTo) Observe(about register.ID, fact string, v register.Scalar, place string) error {
	if s, ok := v.Value().(string); ok {
		v = register.TextValue(label(s))
	}
	return p.rd.observe(about, fact, v, place, "")
}

func (p pullTo) Note(format string, args ...any) { p.rd.note(format, args...) }

// checkPushed refuses a pushed file that names a repository other than the
// job's: a pipeline's facts are about its own repository.
func checkPushed(rd *reader) error {
	if rd.in.pipeline == nil {
		return nil
	}
	want := strings.ToLower(rd.in.pipeline.job.Repository)
	for _, id := range rd.order {
		a, ok := rd.records[id].rec.(register.Asset)
		if !ok || a.Type != "repository" {
			continue
		}
		if !sameRepository(a.Ref, want) {
			return fmt.Errorf("%w: the file names the repository %s, and the job that pushed it ran in %s", ErrNotTheirs,
				plaintext.Clip(a.Ref, 120, "…"), rd.in.pipeline.job.Repository)
		}
	}
	return nil
}

// sameRepository reports whether a repository a file names is the one a
// job ran in: owner/name itself, or an address of it on a code host.
func sameRepository(ref, want string) bool {
	ref = strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(ref)), "/"), ".git")
	if ref == want {
		return true
	}
	for _, host := range []string{"https://github.com/", "https://gitlab.com/", "git+https://github.com/",
		"git+https://gitlab.com/", "github.com/", "gitlab.com/"} {
		if strings.TrimPrefix(ref, host) == want && strings.HasPrefix(ref, host) {
			return true
		}
	}
	return false
}

// byOf is the kind of actor a source made by this kind belongs to.
func byOf(k audit.Kind) register.SourceBy {
	if k == audit.KindService {
		return "service"
	}
	return "person"
}
