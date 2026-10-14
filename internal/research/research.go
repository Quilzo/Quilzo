// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package research is a research project whose every claim can be checked.
//
// Researchers already use AI; what holds them back is not being able to
// trust what it gives them. Models invent citations, numbers in a report
// drift from the analysis that was run, and the plan an analysis followed
// is rewritten after the data was seen. Each of those is answered here by
// a record rather than a promise:
//
//   - A project's plan is registered before the data is analysed, signed
//     with the store's key, and any later change to it is an amendment kept
//     with who made it and why. A plan registered after the first analysis
//     says so.
//   - A computation is a script run in a box with no network, recorded by
//     the digests of its code, its inputs and its environment. The numbers
//     it produces are the ones its code wrote down, never ones a model
//     typed.
//   - A claim pins one of those numbers to the computation that produced
//     it. A report says {{name}} where a number goes, and the check flags
//     every number written in the prose instead.
//   - A source is a citation that resolved, in an open index, to a real
//     work; a sentence citing it must be supported by what the work says,
//     by the same test a chatbot's answers pass.
package research

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Project is one research question and what was done about it.
type Project struct {
	Name     string    `json:"name"`
	Question string    `json:"question"`
	By       string    `json:"by"`
	Created  time.Time `json:"created"`
	// Plan is the analysis plan: a draft until it is registered, then
	// changed only by an amendment.
	Plan Plan `json:"plan"`
	// Amendments are the changes to a registered plan, oldest first.
	Amendments []Amendment `json:"amendments,omitempty"`
	// DataSeen is when the first computation ran: from then on, a plan is
	// no longer written without knowing the data.
	DataSeen time.Time `json:"data_seen,omitempty"`
	// Claims are the numbers a report may state, each pinned to the
	// computation that produced it.
	Claims []Claim `json:"claims,omitempty"`
	// Sources are the works a report may cite.
	Sources []Source `json:"sources,omitempty"`
	// Report is the draft report, in the ledger's markup (see report.go).
	Report       string    `json:"report,omitempty"`
	ReportBy     string    `json:"report_by,omitempty"`
	ReportEdited time.Time `json:"report_edited,omitempty"`
}

// Plan is what will be analysed and how, written before it is.
type Plan struct {
	Text string `json:"text,omitempty"`
	// Digest is the SHA-256 of Text, set when it is registered and by every
	// amendment.
	Digest     string    `json:"digest,omitempty"`
	Registered time.Time `json:"registered,omitempty"`
	By         string    `json:"by,omitempty"`
	// BeforeData says no computation had run when it was registered.
	BeforeData bool `json:"before_data,omitempty"`
	// Signature is the store's signature over the registered digest, which
	// anybody holding the published keys can check.
	Signature *Signature `json:"signature,omitempty"`
}

// Signature is a signed statement over a digest.
type Signature struct {
	KeyID      string   `json:"key_id"`
	Ed25519    string   `json:"ed25519"`
	MLDSA      string   `json:"mldsa,omitempty"`
	Algorithms []string `json:"algorithms"`
}

// PlanContext is what a registered plan's signature is made under.
const PlanContext = "quilzo/research-plan/v1"

// Amendment is a change to a registered plan.
type Amendment struct {
	At   time.Time `json:"at"`
	By   string    `json:"by"`
	Why  string    `json:"why"`
	From string    `json:"from"`
	To   string    `json:"to"`
	// AfterData says the data had been analysed when the change was made.
	AfterData bool `json:"after_data,omitempty"`
}

// Registered reports whether the plan has been registered.
func (p Project) Registered() bool { return !p.Plan.Registered.IsZero() }

// Run is one computation.
type Run struct {
	ID      string    `json:"id"`
	Project string    `json:"project"`
	By      string    `json:"by"`
	Started time.Time `json:"started"`
	Took    string    `json:"took"`
	// Code is the script, by its path in the project and its digest.
	Code File `json:"code"`
	// Inputs are the files it was given, each by digest.
	Inputs []File `json:"inputs,omitempty"`
	// Environment is what ran it.
	Environment Environment `json:"environment"`
	Exit        int         `json:"exit"`
	Stopped     string      `json:"stopped,omitempty"`
	// Log is the start and the end of what it printed, and LogDigest the
	// SHA-256 of all of it.
	Log       string `json:"log,omitempty"`
	LogDigest string `json:"log_digest,omitempty"`
	// Outputs are the files it wrote, each by digest; Values the numbers
	// it wrote down.
	Outputs []File  `json:"outputs,omitempty"`
	Values  []Value `json:"values,omitempty"`
	// Rerun is the computation this one repeated, and Reproduced whether
	// it gave the same numbers and files from the same code and inputs.
	Rerun      string   `json:"rerun,omitempty"`
	Reproduced *bool    `json:"reproduced,omitempty"`
	Differs    []string `json:"differs,omitempty"`
}

// OK reports whether the computation finished cleanly.
func (r Run) OK() bool { return r.Exit == 0 && r.Stopped == "" }

// Reproduces says this re-run gave what the computation it repeated did,
// and DidNotReproduce that it did not.
func (r Run) Reproduces() bool { return r.Reproduced != nil && *r.Reproduced }

// DidNotReproduce: see Reproduces.
func (r Run) DidNotReproduce() bool { return r.Reproduced != nil && !*r.Reproduced }

// File is a file by its path and digest.
type File struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Bytes  int64  `json:"bytes"`
}

// Environment is what ran a computation.
type Environment struct {
	Interpreter string `json:"interpreter"`
	Version     string `json:"version"`
	Box         string `json:"box"`
	Quilzo      string `json:"quilzo,omitempty"`
}

// Digest is the environment's digest: the same interpreter, version and
// box give the same one.
func (e Environment) Digest() string {
	b, _ := json.Marshal(e)
	return sha(b)
}

// Value is a number a computation wrote down.
type Value struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit,omitempty"`
}

// Claim is a number a report may state, pinned to a computation.
type Claim struct {
	Name  string    `json:"name"`
	Run   string    `json:"run"`
	Value float64   `json:"value"`
	Unit  string    `json:"unit,omitempty"`
	By    string    `json:"by"`
	At    time.Time `json:"at"`
}

// Source is a work a report may cite: one that resolved.
type Source struct {
	// Key is how a report cites it: [@key].
	Key string `json:"key"`
	// ID is the identifier it was resolved from: doi:…, pmid:…, arxiv:…
	ID      string   `json:"id"`
	DOI     string   `json:"doi,omitempty"`
	Title   string   `json:"title"`
	Authors []string `json:"authors,omitempty"`
	Year    int      `json:"year,omitempty"`
	Venue   string   `json:"venue,omitempty"`
	URL     string   `json:"url,omitempty"`
	// Abstract is what the index holds of the work's own words.
	Abstract string `json:"abstract,omitempty"`
	// Passages are passages a person quoted from it, each with who quoted
	// it: what a citation may also rest on.
	Passages []Passage `json:"passages,omitempty"`
	// Resolver is the index it resolved in, and Resolved when.
	Resolver string    `json:"resolver"`
	Resolved time.Time `json:"resolved"`
	By       string    `json:"by"`
}

// Passage is text quoted from a source.
type Passage struct {
	Text string `json:"text"`
	By   string `json:"by"`
}

// Limits.
const (
	MaxQuestion = 1000
	MaxPlan     = 50_000
	MaxReport   = 200_000
	MaxPassage  = 4000
	MaxValues   = 200
	MaxSources  = 500
	MaxClaims   = 1000
)

var (
	reName  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	reValue = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
	reKey   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,39}$`)
	reRun   = regexp.MustCompile(`^r-[0-9]{8}-[0-9a-f]{8}$`)
)

// ValidName reports whether a project name is one.
func ValidName(s string) bool { return reName.MatchString(s) }

// ValidRunID reports whether a computation's identifier is one.
func ValidRunID(s string) bool { return reRun.MatchString(s) }

// ValidKey reports whether a citation key is one.
func ValidKey(s string) bool { return reKey.MatchString(s) }

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Digest is the SHA-256 of a text, as plans are digested.
func Digest(text string) string { return sha([]byte(text)) }

// ReadValues reads the numbers a computation wrote down: a JSON object of
// names to numbers, or to {"value": n, "unit": "…"}.
func ReadValues(b []byte) ([]Value, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, errors.New("values.json is an object of names to numbers")
	}
	if len(raw) > MaxValues {
		return nil, fmt.Errorf("a computation writes down at most %d values", MaxValues)
	}
	var out []Value
	for name, v := range raw {
		if !reValue.MatchString(name) {
			return nil, fmt.Errorf("%q is not a value's name: lower-case letters, digits and underscores", name)
		}
		val := Value{Name: name}
		var n float64
		if err := json.Unmarshal(v, &n); err != nil {
			var with struct {
				Value *float64 `json:"value"`
				Unit  string   `json:"unit"`
			}
			if err := json.Unmarshal(v, &with); err != nil || with.Value == nil {
				return nil, fmt.Errorf("%s is not a number, or {\"value\": n, \"unit\": \"…\"}", name)
			}
			n, val.Unit = *with.Value, strings.TrimSpace(with.Unit)
			if len(val.Unit) > 40 {
				return nil, fmt.Errorf("%s's unit is at most 40 characters", name)
			}
		}
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, fmt.Errorf("%s is not a finite number", name)
		}
		val.Value = n
		out = append(out, val)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Format writes a value as a report shows it: as precise as the number is,
// to at most six significant figures.
func Format(v float64, unit string) string {
	s := strconv.FormatFloat(v, 'g', 6, 64)
	if strings.ContainsAny(s, "e") {
		s = strconv.FormatFloat(v, 'f', -1, 64)
	}
	if unit != "" {
		if unit == "%" {
			return s + "%"
		}
		return s + " " + unit
	}
	return s
}

// Store keeps projects and their computations under a directory.
type Store struct {
	Dir string
	mu  sync.Mutex
}

func (s *Store) projectPath(name string) string {
	return filepath.Join(s.Dir, name, "project.json")
}

// Work is a project's folder of code and data.
func (s *Store) Work(name string) string { return filepath.Join(s.Dir, name, "work") }

// RunDir is where a computation's record and outputs are kept.
func (s *Store) RunDir(name, id string) string { return filepath.Join(s.Dir, name, "runs", id) }

// Load reads a project.
func (s *Store) Load(name string) (Project, error) {
	if !ValidName(name) {
		return Project{}, fmt.Errorf("%q is not a project's name", name)
	}
	b, err := os.ReadFile(s.projectPath(name))
	if os.IsNotExist(err) {
		return Project{}, fmt.Errorf("no research project called %q; quilzo research list", name)
	}
	if err != nil {
		return Project{}, err
	}
	var p Project
	if err := json.Unmarshal(b, &p); err != nil {
		return Project{}, fmt.Errorf("%s: %w", name, err)
	}
	return p, nil
}

// Create starts a project.
func (s *Store) Create(p Project) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidName(p.Name) {
		return fmt.Errorf("%q is not a project's name: lower-case letters, digits and hyphens", p.Name)
	}
	p.Question = strings.TrimSpace(p.Question)
	if p.Question == "" || len(p.Question) > MaxQuestion {
		return fmt.Errorf("a project starts from a question of at most %d characters", MaxQuestion)
	}
	if _, err := os.Stat(s.projectPath(p.Name)); err == nil {
		return fmt.Errorf("there is a research project called %s already", p.Name)
	}
	if err := os.MkdirAll(s.Work(p.Name), 0o700); err != nil {
		return err
	}
	return s.save(p)
}

// Change changes a project under the store's lock.
func (s *Store) Change(name string, f func(*Project) error) (Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.Load(name)
	if err != nil {
		return p, err
	}
	if err := f(&p); err != nil {
		return p, err
	}
	return p, s.save(p)
}

func (s *Store) save(p Project) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.projectPath(p.Name)), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(s.projectPath(p.Name), b, 0o600)
}

// List is every project, by name.
func (s *Store) List() ([]Project, error) {
	entries, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Project
	for _, e := range entries {
		if !e.IsDir() || !ValidName(e.Name()) {
			continue
		}
		p, err := s.Load(e.Name())
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// SaveRun keeps a computation's record.
func (s *Store) SaveRun(r Run) error {
	if !ValidRunID(r.ID) {
		return fmt.Errorf("%q is not a computation", r.ID)
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	dir := s.RunDir(r.Project, r.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, "run.json"), b, 0o600)
}

// LoadRun reads a computation's record.
func (s *Store) LoadRun(project, id string) (Run, error) {
	if !ValidName(project) || !ValidRunID(id) {
		return Run{}, fmt.Errorf("%q is not a computation of %q", id, project)
	}
	b, err := os.ReadFile(filepath.Join(s.RunDir(project, id), "run.json"))
	if os.IsNotExist(err) {
		return Run{}, fmt.Errorf("%s has no computation %s", project, id)
	}
	if err != nil {
		return Run{}, err
	}
	var r Run
	return r, json.Unmarshal(b, &r)
}

// Runs is every computation of a project, newest first.
func (s *Store) Runs(project string) ([]Run, error) {
	entries, err := os.ReadDir(filepath.Join(s.Dir, project, "runs"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Run
	for _, e := range entries {
		if !e.IsDir() || !ValidRunID(e.Name()) {
			continue
		}
		if r, err := s.LoadRun(project, e.Name()); err == nil {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	return out, nil
}

// SetPlan writes a draft plan, or amends a registered one with a reason.
func SetPlan(p *Project, text, by, why string, now time.Time) (*Amendment, error) {
	text = strings.TrimSpace(text)
	if text == "" || len(text) > MaxPlan {
		return nil, fmt.Errorf("a plan is between 1 and %d characters", MaxPlan)
	}
	if !p.Registered() {
		p.Plan.Text, p.Plan.By = text, by
		return nil, nil
	}
	why = strings.TrimSpace(why)
	if why == "" {
		return nil, errors.New("the plan is registered: changing it is an amendment, and an amendment says why (--why)")
	}
	if Digest(text) == p.Plan.Digest {
		return nil, errors.New("that is the plan as it stands")
	}
	a := Amendment{At: now.UTC(), By: by, Why: why, From: p.Plan.Digest, To: Digest(text),
		AfterData: !p.DataSeen.IsZero()}
	p.Plan.Text, p.Plan.Digest = text, a.To
	p.Amendments = append(p.Amendments, a)
	return &a, nil
}

// Register seals the plan: from now on it changes only by amendment.
func Register(p *Project, by string, now time.Time) error {
	switch {
	case p.Registered():
		return fmt.Errorf("the plan was registered on %s", p.Plan.Registered.Format("2 Jan 2006"))
	case strings.TrimSpace(p.Plan.Text) == "":
		return errors.New("there is no plan to register: write one first (quilzo research plan)")
	}
	p.Plan.Digest = Digest(p.Plan.Text)
	p.Plan.Registered, p.Plan.By = now.UTC(), by
	p.Plan.BeforeData = p.DataSeen.IsZero()
	return nil
}

// Pin makes a computation's value a claim, replacing one by the same name.
func Pin(p *Project, r Run, name, by string, now time.Time) (Claim, error) {
	if r.Project != p.Name {
		return Claim{}, fmt.Errorf("%s is a computation of %s, not of %s", r.ID, r.Project, p.Name)
	}
	if !r.OK() {
		return Claim{}, fmt.Errorf("%s did not finish cleanly, so nothing it wrote down is a claim", r.ID)
	}
	for _, v := range r.Values {
		if v.Name != name {
			continue
		}
		c := Claim{Name: name, Run: r.ID, Value: v.Value, Unit: v.Unit, By: by, At: now.UTC()}
		for i := range p.Claims {
			if p.Claims[i].Name == name {
				p.Claims[i] = c
				return c, nil
			}
		}
		if len(p.Claims) >= MaxClaims {
			return Claim{}, fmt.Errorf("a project holds at most %d claims", MaxClaims)
		}
		p.Claims = append(p.Claims, c)
		sort.Slice(p.Claims, func(i, j int) bool { return p.Claims[i].Name < p.Claims[j].Name })
		return c, nil
	}
	return Claim{}, fmt.Errorf("%s wrote down no value called %s", r.ID, name)
}

// AddSource adds a resolved work, replacing one with the same key.
func AddSource(p *Project, src Source) error {
	if !ValidKey(src.Key) {
		return fmt.Errorf("%q is not a citation key: lower-case letters, digits, hyphens and underscores", src.Key)
	}
	for i := range p.Sources {
		if p.Sources[i].Key == src.Key {
			if p.Sources[i].ID != src.ID {
				return fmt.Errorf("[@%s] already cites %s", src.Key, p.Sources[i].ID)
			}
			src.Passages = append(p.Sources[i].Passages, src.Passages...)
			p.Sources[i] = src
			return nil
		}
		if p.Sources[i].ID == src.ID {
			return fmt.Errorf("%s is already cited as [@%s]", src.ID, p.Sources[i].Key)
		}
	}
	if len(p.Sources) >= MaxSources {
		return fmt.Errorf("a project cites at most %d works", MaxSources)
	}
	p.Sources = append(p.Sources, src)
	sort.Slice(p.Sources, func(i, j int) bool { return p.Sources[i].Key < p.Sources[j].Key })
	return nil
}
