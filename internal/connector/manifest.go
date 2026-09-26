// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package connector reads a company's tools without becoming the way in.
//
// One file per tool, describing where it lives, how it authenticates, which
// endpoints to read, how they paginate and which fields to keep. No code per
// tool, no plugin to load, nothing executed. A new integration is a file
// somebody can review in five minutes.
//
// # Why a connector is the part to design as though it were already breached
//
// Between 9 and 17 August 2025, the cluster tracked as UNC6395 used OAuth
// tokens stolen from one chat-widget vendor's integration to query Salesforce
// in more than 700 organisations, over ten days, and combed the results for
// AWS keys, Snowflake tokens and passwords sitting in support-case text.
// Nobody's Salesforce was broken into. The integration was the way in, and
// the integration had tokens to everybody.
//
// That is not an argument against connectors; a security product that cannot
// read the estate it is securing is an empty database. It is an argument that
// this is the highest-value component in the building and has to be built
// like it. Five things follow from that, and they are the reason this is a
// manifest rather than a directory of plugins.
//
// # A connector is data
//
// Airbyte's low-code work established the useful fact: API connectors are
// small variations on a handful of problems — a few authentication styles and
// four pagination strategies. What is left, once those are named, is
// configuration. So there is no expression language here, no template that
// evaluates, and no plugin binary. A manifest that could execute is a
// supply-chain foothold with a friendly name, and reviewing one would mean
// reviewing a program.
//
// # A manifest declares one host and cannot exceed it
//
// Including on the way back. Cursor pagination hands the server the next URL,
// which means a compromised or malicious upstream chooses where the next
// request goes — a server-controlled redirect into a network that trusts this
// process. Most implementations follow it because that is what the API told
// them to do. Here a next URL whose host is not the declared one ends the
// page loop and is reported.
//
// # A connector reads
//
// Only GET, from a closed set. A connector that can send an arbitrary body is
// one that can change the system it was pointed at, and "read-only
// integration" then means whatever the manifest happens to say today.
//
// # Every field it may keep is written down
//
// Reads names the source paths this endpoint is allowed to touch, and the
// mapping may not refer to anything outside it. The Drift attackers harvested
// support-case text — a field no integration needed and every integration
// could see. A connector here brings back what it declared and nothing else,
// so the question "what does this have access to" is answered by reading four
// lines rather than by reasoning about an API's scopes.
//
// # The secret is a name
//
// The manifest holds the name of a credential, never a credential. Validate
// refuses one that looks like a secret, because the way this goes wrong is
// somebody pasting a token in to test it and committing the file.
package connector

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Bounds that apply to every connector, whatever its manifest says.
//
// Ceilings rather than defaults: a manifest may ask for less and cannot ask
// for more. A pull with no limit against an API that paginates in a loop is
// an infinite pull, and the first anybody hears of it is the disk.
const (
	// MaxPages is the hard ceiling on pages in one run.
	MaxPages = 1000
	// MaxRecords is the hard ceiling on records in one run.
	MaxRecords = 200000
	// MaxBody is the largest response body that will be read.
	MaxBody = 32 << 20
	// MaxTimeout is the longest a single request may take.
	MaxTimeout = 2 * time.Minute
	// DefaultTimeout is what a manifest gets if it says nothing.
	DefaultTimeout = 30 * time.Second
)

// AuthKind is how a tool expects to be asked.
type AuthKind string

const (
	// NoAuth is a public endpoint. Rare and worth stating rather than
	// leaving as the default that happens when a field is forgotten.
	NoAuth AuthKind = "none"
	// Bearer is Authorization: Bearer <secret>.
	Bearer AuthKind = "bearer"
	// HeaderKey is a named header carrying the secret: X-Api-Key and the
	// several dozen spellings of it.
	HeaderKey AuthKind = "header"
	// Basic is HTTP basic with a named user and a secret password.
	Basic AuthKind = "basic"
)

// AuthKinds lists them.
func AuthKinds() []AuthKind { return []AuthKind{NoAuth, Bearer, HeaderKey, Basic} }

func (a AuthKind) known() bool {
	for _, x := range AuthKinds() {
		if x == a {
			return true
		}
	}
	return false
}

// Auth says how to authenticate, without saying what the credential is.
type Auth struct {
	Kind AuthKind `json:"kind"`
	// Secret is the name of a credential held elsewhere. Never a credential.
	Secret string `json:"secret,omitempty"`
	// Header is the header name for HeaderKey.
	Header string `json:"header,omitempty"`
	// User is the username for Basic, which is not a secret and is useful to
	// see in a review.
	User string `json:"user,omitempty"`
}

// PageKind is how a tool hands over the next page.
//
// Four, which is what the whole field turns out to need.
type PageKind string

const (
	// OnePage is an endpoint that returns everything. The zero value, so
	// the common case needs no configuration and a forgotten field cannot
	// silently mean something else.
	OnePage PageKind = ""
	// Cursor is an opaque token in the body, passed back as a parameter.
	Cursor PageKind = "cursor"
	// NextURL is a whole URL in the body. The dangerous one: see the package
	// comment on why its host is checked.
	NextURL PageKind = "next-url"
	// Offset counts records: ?offset=0&limit=100.
	Offset PageKind = "offset"
	// PageNumber counts pages: ?page=1&per_page=100.
	PageNumber PageKind = "page"
)

// PageKinds lists them.
func PageKinds() []PageKind {
	return []PageKind{OnePage, Cursor, NextURL, Offset, PageNumber}
}

func (p PageKind) known() bool {
	// "none" spelled out is accepted as well as the empty default, because a
	// manifest author who wrote it deliberately should not be told it is
	// wrong.
	if p == "none" {
		return true
	}
	for _, x := range PageKinds() {
		if x == p {
			return true
		}
	}
	return false
}

// one reports whether this strategy returns everything in one request.
func (p PageKind) one() bool { return p == OnePage || p == "none" }

// Pagination describes one strategy.
type Pagination struct {
	Kind PageKind `json:"kind"`
	// From is the path in the response body to the cursor or next URL.
	From string `json:"from,omitempty"`
	// Param is the query parameter the cursor or offset goes back in.
	Param string `json:"param,omitempty"`
	// Size is how many records to ask for, and SizeParam what to call it.
	Size      int    `json:"size,omitempty"`
	SizeParam string `json:"size_param,omitempty"`
	// Start is the first value for a page counter, because some APIs count
	// from one and some from zero and guessing wrong silently skips a page
	// or repeats one.
	Start int `json:"start,omitempty"`
}

// Produces is what an endpoint's records become.
type Produces string

const (
	// Identities become workforce records: people, devices, service accounts.
	Identities Produces = "identity"
	// Events become telemetry.
	Events Produces = "event"
)

// Endpoint is one thing to read from a tool.
type Endpoint struct {
	Name string `json:"name"`
	// Path is the absolute path on the manifest's host. Never a URL.
	Path  string            `json:"path"`
	Query map[string]string `json:"query,omitempty"`

	Produces Produces   `json:"produces"`
	Page     Pagination `json:"page,omitempty"`

	// Records is the path to the array of records in the body. Empty means
	// the body is the array.
	Records string `json:"records,omitempty"`

	// Reads names every source path this endpoint may touch.
	//
	// The reviewable answer to "what does this have access to". Map may not
	// refer to anything outside it, and Validate refuses a manifest where it
	// does — so the list cannot drift out of date without the connector
	// failing to load.
	Reads []string `json:"reads"`

	// Map is target field to source path.
	Map map[string]string `json:"map"`

	// Since is the query parameter for an incremental pull, and Watermark
	// the source path whose highest value is remembered for next time.
	Since     string `json:"since,omitempty"`
	Watermark string `json:"watermark,omitempty"`
}

// Manifest is one tool.
type Manifest struct {
	// Name is the issuer every record from this tool is qualified with.
	//
	// The same string telemetry.ID and workforce use, so a person seen
	// through this tool and the same person seen through another are a join
	// rather than a guess.
	Name string `json:"name"`
	// Tool is what a person calls it: "Kandji MDM".
	Tool string `json:"tool"`
	// Host is exactly one hostname. No scheme, no path, no wildcard.
	Host string `json:"host"`

	Auth      Auth       `json:"auth"`
	Endpoints []Endpoint `json:"endpoints"`

	// Limits a manifest may lower and may not raise.
	Pages   int           `json:"pages,omitempty"`
	Records int           `json:"records,omitempty"`
	Timeout time.Duration `json:"timeout,omitempty"`

	// Note is for whoever reviews this next.
	Note string `json:"note,omitempty"`
}

// secretish is what a pasted credential looks like.
var secretish = []string{
	"bearer ", "basic ", "sk-", "sk_live", "pk_live", "ghp_", "gho_", "ghs_",
	"github_pat_", "xoxb-", "xoxp-", "xapp-", "aws_secret", "akia",
	"-----begin", "eyj", "glpat-", "npm_", "shpat_", "sq0csp",
}

// looksSecret reports what makes a string look like a credential, or empty.
func looksSecret(s string) string {
	low := strings.ToLower(strings.TrimSpace(s))
	for _, p := range secretish {
		if strings.HasPrefix(low, p) {
			return p
		}
	}
	// A name is short and a token is not. Forty characters with no space is
	// not a name anybody chose.
	if len(low) > 40 && !strings.ContainsAny(low, " ") {
		return "forty characters with no spaces"
	}
	return ""
}

// Validate refuses a manifest that could be more than a reader.
func (m Manifest) Validate() error {
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("a connector needs a name, which becomes the " +
			"issuer on every record it produces")
	}
	if m.Name != strings.ToLower(m.Name) ||
		strings.ContainsAny(m.Name, " :/\\") {
		return fmt.Errorf(
			"%q is not usable as an issuer. Lowercase, no spaces and no "+
				"colon: it is half of every identifier this tool "+
				"contributes", m.Name)
	}
	if strings.TrimSpace(m.Tool) == "" {
		return fmt.Errorf("%s does not say what tool it reads, and a review "+
			"of a connector starts with knowing that", m.Name)
	}
	if err := checkHost(m.Host); err != nil {
		return fmt.Errorf("%s: %w", m.Name, err)
	}
	if err := m.Auth.validate(m.Name); err != nil {
		return err
	}
	if m.Pages < 0 || m.Pages > MaxPages {
		return fmt.Errorf("%s asks for %d pages; the ceiling is %d",
			m.Name, m.Pages, MaxPages)
	}
	if m.Records < 0 || m.Records > MaxRecords {
		return fmt.Errorf("%s asks for %d records; the ceiling is %d",
			m.Name, m.Records, MaxRecords)
	}
	if m.Timeout < 0 || m.Timeout > MaxTimeout {
		return fmt.Errorf("%s asks for a %s timeout; the ceiling is %s",
			m.Name, m.Timeout, MaxTimeout)
	}
	if len(m.Endpoints) == 0 {
		return fmt.Errorf("%s reads nothing", m.Name)
	}
	seen := map[string]bool{}
	for _, e := range m.Endpoints {
		if seen[e.Name] {
			return fmt.Errorf("%s has two endpoints called %q",
				m.Name, e.Name)
		}
		seen[e.Name] = true
		if err := e.validate(m.Name); err != nil {
			return err
		}
	}
	return nil
}

// checkHost refuses anything that is not one ordinary hostname.
func checkHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("no host")
	}
	if strings.Contains(host, "://") || strings.Contains(host, "/") {
		return fmt.Errorf(
			"%q is a URL. A host is a host: the scheme is always https and "+
				"the path belongs to an endpoint", host)
	}
	if strings.ContainsAny(host, "*?") {
		return fmt.Errorf(
			"%q has a wildcard. The declared host is what every request is "+
				"checked against, including the next URL a server hands "+
				"back, and a wildcard makes that check a formality", host)
	}
	if strings.Contains(host, "@") {
		return fmt.Errorf(
			"%q carries userinfo, which is a credential in a field that is "+
				"read as a hostname", host)
	}
	if strings.Contains(host, ":") {
		return fmt.Errorf("%q carries a port; the port is 443", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		return fmt.Errorf(
			"%q is an address rather than a name. A connector pointed at a "+
				"literal address is the shape of a request aimed inside the "+
				"network, and there is no certificate for it either", host)
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") ||
		strings.HasSuffix(lower, ".local") ||
		strings.HasSuffix(lower, ".internal") {
		return fmt.Errorf(
			"%q is a local name. A connector reads a company's tools over "+
				"the internet; pointing one at the machine it runs on is "+
				"how a reader becomes a way to reach the inside", host)
	}
	if _, err := url.Parse("https://" + host); err != nil {
		return fmt.Errorf("%q is not a hostname: %w", host, err)
	}
	if !strings.Contains(host, ".") {
		return fmt.Errorf(
			"%q has no dot, so it resolves against the local search domain "+
				"and means something different on every machine", host)
	}
	return nil
}

func (a Auth) validate(name string) error {
	if !a.Kind.known() {
		return fmt.Errorf("%s: %q is not a way to authenticate", name, a.Kind)
	}
	if a.Kind == NoAuth {
		if a.Secret != "" {
			return fmt.Errorf(
				"%s names a secret and authenticates with none", name)
		}
		return nil
	}
	if strings.TrimSpace(a.Secret) == "" {
		return fmt.Errorf("%s does not name a credential", name)
	}
	if why := looksSecret(a.Secret); why != "" {
		return fmt.Errorf(
			"%s appears to hold a credential rather than the name of one "+
				"(%s). The manifest is a file that gets committed, and the "+
				"way this goes wrong is somebody pasting a token in to test "+
				"it", name, why)
	}
	if a.Kind == HeaderKey && strings.TrimSpace(a.Header) == "" {
		return fmt.Errorf("%s authenticates with a header and does not say "+
			"which", name)
	}
	if a.Kind == Basic && strings.TrimSpace(a.User) == "" {
		return fmt.Errorf("%s uses basic auth and names no user", name)
	}
	if a.Header != "" && strings.ContainsAny(a.Header, "\r\n: ") {
		return fmt.Errorf(
			"%s: %q is not a header name. A line break in one ends the "+
				"header and starts another", name, a.Header)
	}
	return nil
}

func (e Endpoint) validate(tool string) error {
	where := tool + "/" + e.Name
	if strings.TrimSpace(e.Name) == "" {
		return fmt.Errorf("%s has an endpoint with no name", tool)
	}
	if err := checkPath(e.Path); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if e.Produces != Identities && e.Produces != Events {
		return fmt.Errorf("%s produces %q, which is not identity or event",
			where, e.Produces)
	}
	if !e.Page.Kind.known() {
		return fmt.Errorf("%s paginates by %q, which is not a strategy here",
			where, e.Page.Kind)
	}
	if err := e.Page.validate(where); err != nil {
		return err
	}
	if len(e.Map) == 0 {
		return fmt.Errorf("%s maps nothing, so it returns empty records",
			where)
	}
	if len(e.Reads) == 0 {
		return fmt.Errorf(
			"%s does not say what it reads. That list is the reviewable "+
				"answer to what this connector has access to, and without "+
				"it the answer is whatever the API returns", where)
	}
	allowed := map[string]bool{}
	for _, r := range e.Reads {
		if strings.TrimSpace(r) == "" {
			return fmt.Errorf("%s declares an empty read", where)
		}
		allowed[r] = true
	}
	var undeclared []string
	for target, source := range e.Map {
		if strings.TrimSpace(target) == "" {
			return fmt.Errorf("%s maps something to an unnamed field", where)
		}
		if !allowed[source] {
			undeclared = append(undeclared, source)
		}
	}
	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		return fmt.Errorf(
			"%s maps %s, which it does not declare under reads. The "+
				"declaration is what makes a review possible, so it is "+
				"checked rather than trusted", where,
			strings.Join(undeclared, ", "))
	}
	if e.Watermark != "" && !allowed[e.Watermark] {
		return fmt.Errorf("%s remembers %s and does not declare reading it",
			where, e.Watermark)
	}
	if e.Since != "" && e.Watermark == "" {
		return fmt.Errorf(
			"%s pulls incrementally with %s and names nothing to remember, "+
				"so every run asks for everything since the same moment",
			where, e.Since)
	}
	for k, v := range e.Query {
		if strings.ContainsAny(k+v, "\r\n") {
			return fmt.Errorf("%s: a query parameter contains a line break",
				where)
		}
	}
	return nil
}

func checkPath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf(
			"%q is not an absolute path. A connector builds its URL from the "+
				"declared host and this; anything else is a way to reach a "+
				"different host", p)
	}
	if strings.Contains(p, "://") || strings.HasPrefix(p, "//") {
		return fmt.Errorf("%q is a URL, not a path", p)
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("%q walks upwards", p)
	}
	if strings.ContainsAny(p, "\r\n") {
		return fmt.Errorf("a path contains a line break")
	}
	return nil
}

func (p Pagination) validate(where string) error {
	if p.Size < 0 || p.Size > MaxRecords {
		return fmt.Errorf("%s asks for %d records a page", where, p.Size)
	}
	if p.Kind.one() {
		return nil
	}
	switch p.Kind {
	case Cursor, NextURL:
		if strings.TrimSpace(p.From) == "" {
			return fmt.Errorf("%s paginates by %s and does not say where "+
				"the next one comes from", where, p.Kind)
		}
		if p.Kind == Cursor && strings.TrimSpace(p.Param) == "" {
			return fmt.Errorf("%s has a cursor and nowhere to put it", where)
		}
	case Offset, PageNumber:
		if strings.TrimSpace(p.Param) == "" {
			return fmt.Errorf("%s counts %s and does not name the parameter",
				where, p.Kind)
		}
		if p.Size <= 0 {
			return fmt.Errorf(
				"%s counts %s with no page size. The counter then advances "+
					"by a number this program guessed, which silently skips "+
					"records or repeats them", where, p.Kind)
		}
	}
	return nil
}

// Limits returns the bounds this manifest runs under, after the ceilings.
func (m Manifest) Limits() (pages, records int, timeout time.Duration) {
	pages, records, timeout = MaxPages, MaxRecords, DefaultTimeout
	if m.Pages > 0 && m.Pages < pages {
		pages = m.Pages
	}
	if m.Records > 0 && m.Records < records {
		records = m.Records
	}
	if m.Timeout > 0 && m.Timeout <= MaxTimeout {
		timeout = m.Timeout
	}
	return pages, records, timeout
}

// Endpoint returns one by name.
func (m Manifest) Endpoint(name string) (Endpoint, bool) {
	for _, e := range m.Endpoints {
		if e.Name == name {
			return e, true
		}
	}
	return Endpoint{}, false
}

// Reach describes what this connector can touch, for a review.
func (m Manifest) Reach() string {
	var fields []string
	for _, e := range m.Endpoints {
		fields = append(fields, e.Reads...)
	}
	sort.Strings(fields)
	return fmt.Sprintf(
		"%s reads https://%s over %d endpoint(s), keeping %d declared "+
			"field(s), and can reach nothing else",
		m.Name, m.Host, len(m.Endpoints), len(dedupe(fields)))
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
