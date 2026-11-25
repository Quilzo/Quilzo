// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/connector"
	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/register"
)

// Recipe is one tool a connector's source can read: its manifest in the
// catalogue, the least privilege it needs, which refusals are a licence
// gap rather than a failure, and the code that reads facts from its pages.
type Recipe struct {
	Name string `json:"name"`
	Tool string `json:"tool"`
	// About is what it brings back, for a person choosing.
	About string `json:"about"`
	// Privilege is the least each credential needs, in a line each, which
	// is also what a credential holding more is refused for.
	Privilege []string `json:"privilege"`
	// Gaps are the endpoints whose 403 is the tool's licence or the
	// credential's reach saying no to one report, with what that means;
	// the rest of the run is read.
	Gaps map[string]string `json:"gaps,omitempty"`
	// Fresh is how often a source running it should report by default.
	Fresh time.Duration `json:"fresh"`
	// Verified says how the recipe was tested: against recorded responses,
	// since no live tenant was available.
	Verified string `json:"verified"`

	// check, when set, reads the endpoint first named by checks and
	// refuses the run if the credential holds more than the recipe needs.
	checks string
	check  func(records []map[string]string) error
	pull   func(r *Run, to evidence.PullTo) error
}

// verifiedFixtures is how every shipped recipe was tested.
const verifiedFixtures = "verified against recorded responses made from the tool's published documentation, " +
	"not against a live tenant; report problems"

var recipes = map[string]*Recipe{}

// define adds a recipe and its puller.
func define(r *Recipe) {
	all, err := connector.Catalogue()
	if err != nil {
		panic("sources: the catalogue: " + err.Error())
	}
	e, ok := all[r.Name]
	if !ok {
		panic("sources: no manifest in the catalogue for the recipe " + r.Name)
	}
	r.Tool, r.About, r.Verified = e.Tool, e.About, verifiedFixtures
	recipes[r.Name] = r
	pull := r.pull
	evidence.RegisterPuller(r.Name, func(doc []byte, to evidence.PullTo) error {
		run, err := ReadRun(doc, r.Name)
		if err != nil {
			return err
		}
		return pull(run, to)
	})
}

// Recipes is every recipe, by name.
func Recipes() []*Recipe {
	out := make([]*Recipe, 0, len(recipes))
	for _, r := range recipes {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RecipeNamed is one recipe.
func RecipeNamed(name string) (*Recipe, bool) {
	r, ok := recipes[name]
	return r, ok
}

// Entry is the recipe's catalogue entry: its regions, parameters and the
// credentials it needs.
func (r *Recipe) Entry() connector.Entry {
	all, _ := connector.Catalogue()
	return all[r.Name]
}

// Manifest is the recipe's manifest for a region and parameters, checked.
func (r *Recipe) Manifest(region string, params map[string]string) (connector.Manifest, error) {
	return r.Entry().With(region, params)
}

// Hosts are the hosts a manifest reaches: its own, and its token
// endpoint's. A source's list must be exactly these.
func Hosts(m connector.Manifest) []string {
	hosts := []string{strings.ToLower(m.Host)}
	if m.Auth.Token != nil && !strings.EqualFold(m.Auth.Token.Host, m.Host) {
		hosts = append(hosts, strings.ToLower(m.Auth.Token.Host))
	}
	sort.Strings(hosts)
	return hosts
}

// Credentials are the names of the credentials a manifest uses.
func Credentials(m connector.Manifest) []string {
	var names []string
	if m.Auth.Kind != connector.NoAuth {
		names = append(names, m.Auth.Secret)
	}
	if t := m.Auth.Token; t != nil {
		names = append(names, t.Client)
		if t.Refresh != "" {
			names = append(names, t.Refresh)
		}
	}
	sort.Strings(names)
	return names
}

// Run is the document a connector's run seals: what it ran and every page
// it read, as the tool sent it. Its digest is the raw digest of every fact
// the run yields.
//
// It holds no time: a run that reads what the last one read is the same
// document, sealed again, so it writes no fact and its seal says when it
// was last received, which is when the source last reported.
type Run struct {
	Recipe string `json:"recipe"`
	Source string `json:"source"`
	// Params are the recipe's parameters the run was made with: a tenant,
	// an organisation. Region is the tool's region.
	Region string            `json:"region,omitempty"`
	Params map[string]string `json:"params,omitempty"`
	// Manifest is the manifest as it ran, which holds the names of
	// credentials and never a credential.
	Manifest connector.Manifest `json:"manifest"`
	Pages    []RunPage          `json:"pages"`
	// Truncated says which endpoints a limit stopped, and why.
	Truncated map[string]string `json:"truncated,omitempty"`
}

// RunPage is one page a run read, or one the tool refused.
type RunPage struct {
	Endpoint string          `json:"endpoint"`
	Path     string          `json:"path"`
	Parent   string          `json:"parent,omitempty"`
	Status   int             `json:"status"`
	Body     json.RawMessage `json:"body,omitempty"`
}

// MaxRun is the largest run document read: the engine's ceiling on pages
// of its ceiling on a page would be far more than any directory, so the
// bound is the raw evidence store's own.
const MaxRun = evidence.MaxFile

// ReadRun reads a run's document, as a recipe's puller is given it: it
// must be the named recipe's, with a manifest that is still a reader.
func ReadRun(doc []byte, recipe string) (*Run, error) {
	if len(doc) > MaxRun {
		return nil, fmt.Errorf("%w: a run of %d bytes", evidence.ErrUnreadable, len(doc))
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	var r Run
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%w: the run is not a run's document: %v", evidence.ErrUnreadable, err)
	}
	if r.Recipe != recipe || r.Manifest.Name != recipe {
		return nil, fmt.Errorf("%w: the run is of the recipe %q, and is read as %s", evidence.ErrUnreadable, r.Recipe, recipe)
	}
	if err := r.Manifest.Validate(); err != nil {
		return nil, fmt.Errorf("%w: the run's manifest: %v", evidence.ErrUnreadable, err)
	}
	return &r, nil
}

// Read is what a run read of one endpoint: its records, with the place of
// each in the document, and whether the tool refused it.
type Read struct {
	Records []Record
	// Refused is the status of a page the tool refused, 0 when none was.
	Refused int
	// Parents are the keys a per-record endpoint was read for, each once,
	// in the order read.
	Parents []string
}

// Record is one mapped record, and where in the document it was read.
type Record struct {
	Fields map[string]string
	Place  string
}

// Endpoint is what the run read of one endpoint, each page mapped as the
// run's manifest maps it.
func (r *Run) Endpoint(name string) (Read, error) {
	var out Read
	seen := map[string]bool{}
	for i, p := range r.Pages {
		if p.Endpoint != name {
			continue
		}
		if p.Status < 200 || p.Status > 299 {
			out.Refused = p.Status
			continue
		}
		if !seen[p.Parent] {
			seen[p.Parent] = true
			out.Parents = append(out.Parents, p.Parent)
		}
		recs, err := connector.Records(r.Manifest, name, p.Body, p.Parent)
		if err != nil {
			return out, fmt.Errorf("%w: page %d: %v", evidence.ErrUnreadable, i, err)
		}
		for j, rec := range recs {
			out.Records = append(out.Records, Record{Fields: rec, Place: fmt.Sprintf("/pages/%d/body, record %d", i, j)})
		}
	}
	return out, nil
}

// Param is a parameter the run was made with.
func (r *Run) Param(name string) string { return r.Params[name] }

// yes is a mapped field as a yes or no, and whether it was one.
func yes(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// number is a mapped field as a number, and whether it was one.
func number(s string) (float64, bool) {
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return n, err == nil
}

// list is a mapped field that holds a list of plain values, split.
func list(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// facts writes facts about one thing, skipping a field the tool did not
// send rather than writing it as false.
type facts struct {
	to    evidence.PullTo
	about register.ID
	place string
	err   error
}

func (f *facts) yes(fact, field string) {
	if v, ok := yes(field); ok {
		f.set(fact, register.BoolValue(v))
	}
}

func (f *facts) bool(fact string, v bool) { f.set(fact, register.BoolValue(v)) }

func (f *facts) text(fact, v string) {
	if strings.TrimSpace(v) != "" {
		f.set(fact, register.TextValue(v))
	}
}

func (f *facts) number(fact string, v float64) { f.set(fact, register.NumberValue(v)) }

func (f *facts) set(fact string, v register.Scalar) {
	if f.err != nil {
		return
	}
	f.err = f.to.Observe(f.about, fact, v, f.place)
}

// gap records a report the tool's licence or the credential's reach does
// not include, as a fact about the tenant and a note in plain words.
func gap(to evidence.PullTo, about register.ID, what, why string, status int) error {
	to.Note("licence gap: %s answered %d, and is not read. %s", what, status, why)
	return to.Observe(about, "report."+what, register.TextValue("licence gap"), "/pages")
}

// errRefusedGrant is a credential that holds more than its recipe needs.
var errRefusedGrant = errors.New("the credential holds more than the recipe needs, and is not used")
