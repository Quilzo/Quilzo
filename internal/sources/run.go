// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/connector"
	"github.com/quilzo/quilzo/internal/egress"
	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/plaintext"
	"github.com/quilzo/quilzo/internal/register"
)

// Sources is the sources of one register: adding them, running a
// connector's, and how fresh each is.
type Sources struct {
	Reg   *register.Register
	Ing   *evidence.Ingester
	Vault *Vault
	// Client is how a connector reaches its tool. Nil is the program's
	// client for the sources purpose (internal/egress), which follows no
	// redirect; whichever it is, a request for a host the source does not
	// name is refused before it is sent.
	Client connector.Doer
	// Sleep is how a run waits out a rate limit, for tests. Nil waits.
	Sleep connector.Sleeper
	// Now is the clock, for tests. Nil is the system's.
	Now func() time.Time
}

// Open is the sources of a register, with its evidence ingester and vault.
func Open(reg *register.Register) *Sources {
	return &Sources{Reg: reg, Ing: evidence.New(reg), Vault: &Vault{Store: reg.Store}}
}

func (s *Sources) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

var (
	// ErrNotFound is a source the register does not hold.
	ErrNotFound = errors.New("no source by that name")
	// ErrEgress is a source whose hosts are not the hosts its recipe
	// reaches, or a request for a host the source does not name.
	ErrEgress = errors.New("the source reaches only the hosts it names")
)

// Source is a source by its name, and its identifier.
func (s *Sources) Source(name string) (register.Source, register.ID, error) {
	id, err := register.DeriveID(register.KindSource, register.Local, name)
	if err != nil {
		return register.Source{}, "", fmt.Errorf("%w: %q", ErrNotFound, plaintext.Clip(name, 40, "…"))
	}
	e, err := s.Reg.Get(id)
	if errors.Is(err, register.ErrNotFound) {
		return register.Source{}, "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return register.Source{}, "", err
	}
	src, ok := e.Record.(register.Source)
	if !ok {
		return register.Source{}, "", fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return src, id, nil
}

// Connector is what a person says when they add a connector's source.
type Connector struct {
	Name   string
	Title  string
	Recipe string
	Region string
	Params map[string]string
	// Fresh is how often it should report; zero is the recipe's own.
	Fresh time.Duration
	Owner register.ID
}

// Pipeline is what a person says when they add a pipeline's source.
type Pipeline struct {
	Name       string
	Title      string
	Repository string
	Workflow   string
	Fresh      time.Duration
	Owner      register.ID
}

// ConnectorSource is the source a person's description makes: its hosts
// are the ones its recipe reaches, and nothing they typed.
func ConnectorSource(c Connector) (register.Source, error) {
	rc, ok := RecipeNamed(c.Recipe)
	if !ok {
		return register.Source{}, fmt.Errorf("%w: no recipe called %q; the recipes are %s", register.ErrInvalid,
			plaintext.Clip(c.Recipe, 40, "…"), strings.Join(recipeNames(), ", "))
	}
	m, err := rc.Manifest(c.Region, c.Params)
	if err != nil {
		return register.Source{}, fmt.Errorf("%w: %v", register.ErrInvalid, err)
	}
	if c.Region == "" {
		c.Region = rc.Entry().Default
	}
	fresh := c.Fresh
	if fresh <= 0 {
		fresh = rc.Fresh
	}
	title := c.Title
	if title == "" {
		title = rc.Tool
	}
	var params []string
	for _, k := range sortedKeys(rc.Entry().Params) {
		params = append(params, k+"="+strings.ToLower(strings.TrimSpace(c.Params[k])))
	}
	src := register.Source{Name: c.Name, Type: "connector", Title: title, Fresh: int64(fresh / time.Second),
		Hosts: Hosts(m), Grade: register.GradeConnector, By: "service", Owner: c.Owner, Recipe: rc.Name,
		Region: c.Region, Params: params}
	return src, register.Validate(src)
}

// PipelineSource is the source of a pipeline a person describes.
func PipelineSource(p Pipeline) (register.Source, error) {
	fresh := p.Fresh
	if fresh <= 0 {
		fresh = 7 * 24 * time.Hour
	}
	title := p.Title
	if title == "" {
		title = "Pipeline of " + p.Repository
	}
	src := register.Source{Name: p.Name, Type: "ci", Title: title, Fresh: int64(fresh / time.Second),
		Grade: register.GradeCI, By: "service", Owner: p.Owner, Repository: strings.TrimSpace(p.Repository),
		Workflow: strings.TrimSpace(p.Workflow)}
	if !reRepository.MatchString(src.Repository) {
		return src, fmt.Errorf("%w: a repository is owner/name, or a GitLab group's path to it, not %q", register.ErrInvalid,
			plaintext.Clip(src.Repository, 80, "…"))
	}
	if !reWorkflow.MatchString(src.Workflow) {
		return src, fmt.Errorf("%w: a workflow is the path of its file in the repository, such as "+
			".github/workflows/evidence.yml or .gitlab-ci.yml, not %q", register.ErrInvalid, plaintext.Clip(src.Workflow, 80, "…"))
	}
	return src, register.Validate(src)
}

// Add writes a source, as by.
func (s *Sources) Add(by register.Actor, src register.Source) (register.Receipt, error) {
	if err := register.Validate(src); err != nil {
		return register.Receipt{}, err
	}
	return s.Reg.Put(by, label("source "+src.Name+" added, "+string(src.Type)), src)
}

// Collector is the service a connector's run writes as. It writes facts,
// the assets and accounts they are about, and the run's seal, and nothing
// else; may, when given, is the policy as whoever started the run, asked as
// well, so a run a person starts is no more than they may do.
func Collector(source string, may func(auth.Action, string) error) register.Actor {
	return register.Actor{Name: "source:" + source, Kind: audit.KindService, Verified: true,
		May: func(act auth.Action, resource string) error {
			for _, k := range []register.Kind{register.KindObservation, register.KindRawFile, register.KindAsset,
				register.KindSubject} {
				if spec, _ := register.SpecOf(string(k)); act == auth.ActEditDraft && resource == spec.Resource() {
					if may != nil {
						return may(act, resource)
					}
					return nil
				}
			}
			return fmt.Errorf("a connector's run writes facts, the assets and accounts they are about and its "+
				"seal, and not %s", resource)
		}}
}

// Report is what one run did.
type Report struct {
	Source string    `json:"source"`
	At     time.Time `json:"at"`
	// OK says the run read what it needed and wrote what it read.
	OK bool `json:"ok"`
	// Problem is why it did not, in plain words; nothing was written.
	Problem string `json:"problem,omitempty"`
	// Raw is the digest of the run's sealed document.
	Raw register.Digest `json:"raw,omitempty"`
	// Facts is how many records it read, and Written how many of them were
	// new or changed.
	Facts   int `json:"facts"`
	Written int `json:"written"`
	// Notes are what it says in plain words: licence gaps, limits.
	Notes    []string         `json:"notes,omitempty"`
	Requests int              `json:"requests"`
	Receipt  register.Receipt `json:"receipt,omitzero"`
}

// Run runs a connector's source once, as the collector, asking may (the
// policy as whoever started it, or nil for the server's own timer), and
// records what it did.
func (s *Sources) Run(ctx context.Context, name string, may func(auth.Action, string) error) (Report, error) {
	rep := Report{Source: name, At: s.now()}
	err := s.run(ctx, name, may, &rep)
	if err != nil {
		rep.Problem = err.Error()
	}
	if serr := s.saveAttempt(rep); serr != nil && err == nil {
		err = serr
	}
	return rep, err
}

func (s *Sources) run(ctx context.Context, name string, may func(auth.Action, string) error, rep *Report) error {
	src, _, err := s.Source(name)
	if err != nil {
		return err
	}
	if src.Type != "connector" {
		return fmt.Errorf("%s is a source of type %s, which is not run: its facts arrive by themselves", name, src.Type)
	}
	rc, ok := RecipeNamed(src.Recipe)
	if !ok {
		return fmt.Errorf("%s runs the recipe %q, which this program does not have", name, src.Recipe)
	}
	params, err := ParseParams(src.Params)
	if err != nil {
		return err
	}
	m, err := rc.Manifest(src.Region, params)
	if err != nil {
		return err
	}
	want := Hosts(m)
	have := lowered(src.Hosts)
	if !slices.Equal(want, have) {
		return fmt.Errorf("%w: %s may reach %s, and its recipe reaches %s; add it again to have the hosts its "+
			"recipe names", ErrEgress, name, strings.Join(have, ", "), strings.Join(want, ", "))
	}
	if may != nil {
		// Asked before the tool is, so a run nobody may make reads nothing.
		spec, _ := register.SpecOf(string(register.KindObservation))
		if err := may(auth.ActEditDraft, spec.Resource()); err != nil {
			return fmt.Errorf("%w: %v", register.ErrRefused, err)
		}
	}
	client := s.Client
	if client == nil {
		_, _, timeout := m.Limits()
		client = egress.Client("sources", timeout)
	}
	x, err := connector.NewSession(m, allowlist{inner: client, hosts: have}, s.Vault.secretsFor(name, m), s.Sleep)
	if err != nil {
		return err
	}
	x.Clock(s.now)
	var pages []RunPage
	x.Keep = func(p connector.Page) {
		pages = append(pages, RunPage{Endpoint: p.Endpoint, Path: p.Path, Parent: p.Parent, Status: p.Status,
			Body: json.RawMessage(p.Body)})
	}
	var names []string
	for _, e := range m.Endpoints {
		if e.Name != rc.checks {
			names = append(names, e.Name)
		}
	}
	if rc.check != nil {
		res, err := x.Run(ctx, rc.checks, connector.State{})
		if err != nil {
			return fmt.Errorf("the credential's own reach could not be read, so nothing else was: %w", err)
		}
		if err := rc.check(res.Records); err != nil {
			return err
		}
	}
	doc := Run{Recipe: rc.Name, Source: name, Region: src.Region, Params: params, Manifest: m,
		Truncated: map[string]string{}}
	var failed []string
	for _, rd := range x.All(ctx, names, nil) {
		if rd.Err != nil {
			var he *connector.HTTPError
			if errors.As(rd.Err, &he) && he.Status == http.StatusForbidden && rc.Gaps[rd.Endpoint] != "" {
				continue
			}
			failed = append(failed, rd.Err.Error())
			continue
		}
		if rd.Result.Truncated != "" {
			doc.Truncated[rd.Endpoint] = rd.Result.Truncated
			rep.Notes = append(rep.Notes, rd.Endpoint+": "+rd.Result.Truncated)
		}
	}
	rep.Requests = x.Requests
	if len(failed) > 0 {
		sort.Strings(failed)
		return fmt.Errorf("the run did not read everything, so nothing was written: %s", strings.Join(failed, "; "))
	}
	if len(doc.Truncated) == 0 {
		doc.Truncated = nil
	}
	doc.Pages = pages
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	s.Ing.Now = s.now
	res, err := s.Ing.Collect(Collector(name, may), label(name+" run of "+rep.At.Format("2 Jan 2006 15:04")), src, body)
	if res.Batch != nil {
		rep.Raw, rep.Facts, rep.Notes = res.Batch.Digest, len(res.Batch.Facts), append(rep.Notes, res.Batch.Notes...)
	}
	if err != nil {
		return err
	}
	rep.Receipt, rep.Written, rep.OK = res.Receipt, len(res.Receipt.Written), true
	return nil
}

// ParseParams reads a source's parameters, each name=value.
func ParseParams(in []string) (map[string]string, error) {
	out := map[string]string{}
	for _, p := range in {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("%q is not a parameter: name=value", plaintext.Clip(p, 60, "…"))
		}
		out[k] = v
	}
	return out, nil
}

// allowlist is a client that sends a request only to a host the source
// names, over https.
type allowlist struct {
	inner connector.Doer
	hosts []string
}

func (a allowlist) Do(req *http.Request) (*http.Response, error) {
	host := strings.ToLower(req.URL.Hostname())
	if req.URL.Scheme != "https" || !slices.Contains(a.hosts, host) || req.URL.Port() != "" {
		return nil, fmt.Errorf("%w: a request for %s was not sent; this source reaches %s", ErrEgress,
			plaintext.Clip(req.URL.Scheme+"://"+req.URL.Host, 120, "…"), strings.Join(a.hosts, ", "))
	}
	return a.inner.Do(req)
}

// Attempt is what the last run of a source did, kept beside the store:
// operational, not evidence. The evidence of a run is its seal.
type Attempt = Report

func (s *Sources) attemptPath(name string) string {
	return filepath.Join(s.Reg.Store.Root(), "sources", "runs", name+".json")
}

func (s *Sources) saveAttempt(r Report) error {
	if !reName.MatchString(r.Source) {
		return nil
	}
	r.Receipt = register.Receipt{}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.attemptPath(r.Source)), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(s.attemptPath(r.Source), append(b, '\n'), 0o600)
}

// LastAttempt is what the last run of a source did, if it was run here.
func (s *Sources) LastAttempt(name string) (*Report, error) {
	if !reName.MatchString(name) {
		return nil, nil
	}
	b, err := os.ReadFile(s.attemptPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("the record of %s's last run is unreadable: %w", name, err)
	}
	return &r, nil
}

func recipeNames() []string {
	var out []string
	for _, r := range Recipes() {
		out = append(out, r.Name)
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func lowered(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	sort.Strings(out)
	return out
}

// label is code's own words as a label holds them.
func label(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > register.MaxLabel {
		s = plaintext.Clip(s, register.MaxLabel-len("…"), "…")
	}
	return s
}
