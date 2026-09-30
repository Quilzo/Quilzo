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
	"regexp"
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
	// OAuthClient exchanges a client ID and secret for an access token that
	// lasts an hour: the OAuth client-credentials grant, which is how Vanta
	// is read.
	OAuthClient AuthKind = "oauth-client"
	// OAuthRefresh exchanges a long-lived refresh token for an access token:
	// how Zoho, and so every ManageEngine cloud product, is read.
	OAuthRefresh AuthKind = "oauth-refresh"
)

// AuthKinds lists them.
func AuthKinds() []AuthKind {
	return []AuthKind{NoAuth, Bearer, HeaderKey, Basic, OAuthClient,
		OAuthRefresh}
}

// oauth reports whether a kind obtains its token from a token endpoint.
func (a AuthKind) oauth() bool { return a == OAuthClient || a == OAuthRefresh }

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
	// Scheme is the word before the token in Authorization, for the tools
	// that do not spell it Bearer: Zoho's is Zoho-oauthtoken.
	Scheme string `json:"scheme,omitempty"`
	// Token is where an OAuth kind gets its access token. Secret then names
	// the client secret.
	Token *TokenEndpoint `json:"token,omitempty"`
}

// TokenEndpoint is the one place other than Host a connector may send a
// request, and the one request that is not a GET.
//
// Declared rather than discovered. OAuth metadata discovery would let the
// tool say where its token endpoint is, and the token request is the one
// carrying the client secret — the credential that can mint every other.
type TokenEndpoint struct {
	// Host is exactly one hostname, checked as Host is. For Zoho it is not
	// the API's host: accounts.zoho.eu issues tokens for
	// mdm.manageengine.eu.
	Host string `json:"host"`
	Path string `json:"path"`
	// Client names the credential holding the client ID.
	Client string `json:"client"`
	// Refresh names the credential holding the refresh token, for
	// oauth-refresh.
	Refresh string `json:"refresh,omitempty"`
	// Scopes are what the token is asked for or, for a refresh token, what
	// it was granted with. Every one must be a read scope: a connector that
	// holds a token able to write holds more than it declared, whatever its
	// endpoints say.
	Scopes []string `json:"scopes"`
	// Body is how the request is encoded: "form", the OAuth default, or
	// "json", which is what Vanta documents.
	Body string `json:"body,omitempty"`
}

// Rate is what the tool allows, declared so a run stays inside it rather
// than discovering it from a 429.
//
// A daily budget matters more than the others. KnowBe4 allows 2,000 requests
// a day plus one per licensed seat; a connector that spends them all at 9am
// leaves the console's own reports failing until tomorrow, and the error
// lands on somebody who never heard of this program.
type Rate struct {
	PerSecond int `json:"per_second,omitempty"`
	PerMinute int `json:"per_minute,omitempty"`
	PerDay    int `json:"per_day,omitempty"`
}

// Spacing is the least time between two requests.
func (r Rate) Spacing() time.Duration {
	var d time.Duration
	if r.PerSecond > 0 {
		d = time.Second / time.Duration(r.PerSecond)
	}
	if r.PerMinute > 0 {
		if m := time.Minute / time.Duration(r.PerMinute); m > d {
			d = m
		}
	}
	return d
}

// Each makes an endpoint run once per record of another: the apps on each
// device, the recipients of each phishing test.
//
// One level only. An endpoint read for each record of an endpoint that is
// itself read for each record is a multiplication nobody sees in review, and
// it is how a nightly pull becomes a million requests.
type Each struct {
	// Of is the endpoint whose records this is read for.
	Of string `json:"of"`
	// Key is a mapped field of those records. It replaces {key} in Path.
	Key string `json:"key"`
	// When and WithinDays read only the records whose When field is a time
	// within that many days: the phishing tests of the last quarter rather
	// than of the last six years.
	When       string `json:"when,omitempty"`
	WithinDays int    `json:"within_days,omitempty"`
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
	// More is a path to a flag saying whether there is another page. Vanta
	// hands back a cursor on its last page as well, so without this every
	// read ends with one request that returns nothing.
	More string `json:"more,omitempty"`
}

// Produces is what an endpoint's records become.
type Produces string

const (
	// Identities become workforce records: people, devices, service accounts.
	Identities Produces = "identity"
	// Events become telemetry.
	Events Produces = "event"
	// Training is an enrolment in a course, and whether it was finished.
	Training Produces = "training"
	// Phishing is one person's result in one simulated phishing test.
	Phishing Produces = "phishing"
	// Policy is one person's acceptance, or not, of one policy.
	Policy Produces = "policy"
	// Software is one application installed on one device.
	Software Produces = "software"
	// Vulnerability is one weakness or missing patch on one device.
	Vulnerability Produces = "vulnerability"
	// Control is one check a compliance tool ran, and its outcome.
	Control Produces = "control"
)

// ProducesKinds lists what an endpoint's records may become.
func ProducesKinds() []Produces {
	return []Produces{Identities, Events, Training, Phishing, Policy,
		Software, Vulnerability, Control}
}

func (p Produces) known() bool {
	for _, x := range ProducesKinds() {
		if x == p {
			return true
		}
	}
	return false
}

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

	// Explode is an array inside each record whose elements are the records
	// wanted: Endpoint Central lists computers, each holding its own
	// vulnerabilities. The enclosing record is reachable from an element's
	// paths as ^, so ^.resource_id says which computer a vulnerability is on.
	Explode string `json:"explode,omitempty"`

	// Single says the response is one record rather than an array of them:
	// a device's details, a computer's asset summary.
	Single bool `json:"single,omitempty"`

	// Rate is a stricter pace for this endpoint than the tool's. Endpoint
	// Central allows 120 calls a minute in general and 30 to its
	// vulnerability report, and going over either locks the client out for
	// five minutes.
	Rate Rate `json:"rate,omitempty"`

	// Accept is the media type to ask for, for the tools that version their
	// responses by it — Endpoint Central answers some paths only when asked
	// for application/softwareInfo.v1+json. Empty is application/json.
	Accept string `json:"accept,omitempty"`

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

	// Each, when set, reads this endpoint once per record of another.
	Each *Each `json:"each,omitempty"`
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
	Rate      Rate       `json:"rate,omitempty"`

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
	if m.Rate.PerSecond < 0 || m.Rate.PerMinute < 0 || m.Rate.PerDay < 0 {
		return fmt.Errorf("%s declares a negative rate", m.Name)
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
	for _, e := range m.Endpoints {
		if err := m.checkEach(e); err != nil {
			return err
		}
	}
	return nil
}

// checkEach refuses a per-record endpoint that could reach further than its
// review suggests.
func (m Manifest) checkEach(e Endpoint) error {
	where := m.Name + "/" + e.Name
	holes := strings.Count(e.Path, "{")
	if e.Each == nil {
		if holes > 0 || strings.Contains(e.Path, "}") {
			return fmt.Errorf("%s has a placeholder in its path and is not "+
				"read for each record of anything", where)
		}
		return nil
	}
	if holes != 1 || strings.Count(e.Path, "{key}") != 1 {
		return fmt.Errorf("%s is read for each %s and its path does not "+
			"hold exactly one {key}", where, e.Each.Of)
	}
	if e.Each.Of == e.Name {
		return fmt.Errorf("%s is read for each record of itself", where)
	}
	if _, ok := e.Map["parent"]; ok {
		return fmt.Errorf("%s maps a field called parent, which a "+
			"per-record endpoint fills with the key it was read for", where)
	}
	parent, ok := m.Endpoint(e.Each.Of)
	if !ok {
		return fmt.Errorf("%s is read for each record of %q, which this "+
			"connector does not have", where, e.Each.Of)
	}
	if parent.Each != nil {
		return fmt.Errorf(
			"%s is read for each record of %s, which is itself read for "+
				"each record of %s. One level: a nested fan-out multiplies "+
				"in a way nobody sees in a review", where, parent.Name,
			parent.Each.Of)
	}
	if _, ok := parent.Map[e.Each.Key]; !ok {
		return fmt.Errorf("%s puts %s/%s in its path, which that endpoint "+
			"does not map", where, parent.Name, e.Each.Key)
	}
	if e.Each.WithinDays < 0 {
		return fmt.Errorf("%s: a negative window", where)
	}
	if (e.Each.WithinDays > 0) != (e.Each.When != "") {
		return fmt.Errorf("%s: a window needs both a field and a number of "+
			"days", where)
	}
	if e.Each.When != "" {
		if _, ok := parent.Map[e.Each.When]; !ok {
			return fmt.Errorf("%s windows on %s/%s, which that endpoint "+
				"does not map", where, parent.Name, e.Each.When)
		}
	}
	if e.Since != "" {
		return fmt.Errorf("%s is read per record and incrementally; the "+
			"checkpoint would be one number for every parent", where)
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
	if a.Scheme != "" {
		if a.Kind != Bearer && !a.Kind.oauth() {
			return fmt.Errorf("%s names a scheme and authenticates with %s, "+
				"which does not use one", name, a.Kind)
		}
		if !reScheme.MatchString(a.Scheme) {
			return fmt.Errorf("%s: %q is not an authorization scheme", name,
				a.Scheme)
		}
	}
	if !a.Kind.oauth() {
		if a.Token != nil {
			return fmt.Errorf("%s declares a token endpoint and "+
				"authenticates with %s, which does not use one", name, a.Kind)
		}
		return nil
	}
	return a.Token.validate(name, a.Kind)
}

var reScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,31}$`)

func (t *TokenEndpoint) validate(name string, kind AuthKind) error {
	if t == nil {
		return fmt.Errorf("%s authenticates with %s and does not say where "+
			"its token comes from", name, kind)
	}
	if err := checkHost(t.Host); err != nil {
		return fmt.Errorf("%s token endpoint: %w", name, err)
	}
	if err := checkPath(t.Path); err != nil {
		return fmt.Errorf("%s token endpoint: %w", name, err)
	}
	if strings.ContainsAny(t.Path, "?#{}") {
		return fmt.Errorf("%s: the token path is a path; a query on it "+
			"would carry parameters nobody declared", name)
	}
	for label, v := range map[string]string{"client": t.Client,
		"refresh": t.Refresh} {
		if v == "" {
			continue
		}
		if why := looksSecret(v); why != "" {
			return fmt.Errorf("%s: the %s field appears to hold a "+
				"credential rather than the name of one (%s)", name, label,
				why)
		}
	}
	if strings.TrimSpace(t.Client) == "" {
		return fmt.Errorf("%s does not name the credential holding its "+
			"client ID", name)
	}
	if kind == OAuthRefresh && strings.TrimSpace(t.Refresh) == "" {
		return fmt.Errorf("%s refreshes a token and does not name the "+
			"credential holding it", name)
	}
	if kind == OAuthClient && t.Refresh != "" {
		return fmt.Errorf("%s names a refresh token and uses the client "+
			"credentials grant, which has none", name)
	}
	if t.Body != "" && t.Body != "form" && t.Body != "json" {
		return fmt.Errorf("%s: a token request is sent as form or json, "+
			"not %q", name, t.Body)
	}
	if len(t.Scopes) == 0 {
		return fmt.Errorf(
			"%s does not say what its token may do. The scopes are the "+
				"answer to what this credential can reach, and a token "+
				"whose scopes nobody wrote down can reach whatever the "+
				"application was granted", name)
	}
	for _, sc := range t.Scopes {
		if err := readScope(sc); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// readScope refuses a scope that could do more than read.
//
// By its spelling, because that is what every vendor this reads uses:
// vanta-api.all:read, MDMOnDemand.MDMInventory.READ,
// DesktopCentralCloud.Inventory.READ. A scope that does not end by saying
// read is one this cannot vouch for, and a connector holding a token able
// to write holds more than its endpoints declare.
func readScope(sc string) error {
	low := strings.ToLower(strings.TrimSpace(sc))
	if low == "" || strings.ContainsAny(low, " \t\r\n") {
		return fmt.Errorf("%q is not a scope", sc)
	}
	if !strings.HasSuffix(low, ":read") && !strings.HasSuffix(low, ".read") {
		return fmt.Errorf(
			"%q is not a read scope. A connector reads, so its token asks "+
				"for reading and nothing else", sc)
	}
	for _, w := range []string{"write", "update", "delete", "create",
		"admin", "manage", "upload"} {
		if strings.Contains(low, w) {
			return fmt.Errorf("%q says %s, which is not reading", sc, w)
		}
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
	if !e.Produces.known() {
		return fmt.Errorf("%s produces %q, which is not something this "+
			"program can hold", where, e.Produces)
	}
	if word := forbiddenIn(e.Path, forbiddenPath); word != "" {
		return fmt.Errorf(
			"%s reads %s, and a path about %s is refused whatever the "+
				"token's scope allows. ManageEngine's inventory scope reaches "+
				"BitLocker recovery keys and firmware passwords; a read "+
				"permission is not a reason to hold them", where, e.Path,
			word)
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
	if e.Accept != "" && !reAccept.MatchString(e.Accept) {
		return fmt.Errorf("%s: %q is not a media type to ask for", where,
			e.Accept)
	}
	if e.Rate.PerSecond < 0 || e.Rate.PerMinute < 0 || e.Rate.PerDay != 0 {
		return fmt.Errorf("%s: an endpoint's rate is a pace, per second or "+
			"per minute; the day's budget belongs to the tool", where)
	}
	if e.Single && (e.Explode != "" || !e.Page.Kind.one()) {
		return fmt.Errorf("%s is one record, so it neither pages nor "+
			"explodes", where)
	}
	if e.Explode != "" && strings.HasPrefix(e.Explode, "^") {
		return fmt.Errorf("%s explodes %s, which is outside the record",
			where, e.Explode)
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
		if word := forbidden(r); word != "" {
			return fmt.Errorf("%s declares reading %s. A field about %s "+
				"is refused: nothing this program does with a workforce "+
				"needs one", where, r, word)
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

var reHeader = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// reAccept is one media type, of the kind APIs version by.
var reAccept = regexp.MustCompile(`^application/[A-Za-z0-9.+-]{1,64}$`)

// What no connector reads, in a path or in a field.
//
// Every one of these is something a read scope reaches in a tool this was
// built for. Endpoint Central's inventory scope includes BitLocker recovery
// keys; MDM Plus's includes firmware passwords and every device's location
// history. A workforce reconciliation needs none of it, and a copy held here
// is a copy somebody can take from here.

// forbiddenPath is matched anywhere in a path: an endpoint about any of
// these is refused outright.
var forbiddenPath = []string{
	"password", "passcode", "passphrase", "recoverykey", "recovery_key",
	"recovery-key", "privatekey", "private_key", "secret", "credential",
	"location",
}

// forbiddenField is matched against the end of each segment of a field's
// path, separators ignored. The end, because that is where a name says what
// a value is: admin_password is a password, passwordManager is whether one
// is installed, passcode_present is whether a phone has one — the posture
// facts this is here to read. And location alone is an office in KnowBe4;
// ip_location is where somebody was sitting when they clicked.
var forbiddenField = []string{
	"password", "passwd", "passphrase", "secret", "recoverykey",
	"recoverykeys", "privatekey", "credential", "credentials", "latitude",
	"longitude", "geolocation", "iplocation",
}

// forbidden returns the word that rules a field out, or empty.
func forbidden(field string) string {
	for _, seg := range splitPath(field) {
		norm := strings.NewReplacer("_", "", "-", "", " ", "").
			Replace(strings.ToLower(seg))
		for _, w := range forbiddenField {
			if strings.HasSuffix(norm, w) {
				return w
			}
		}
	}
	return ""
}

func forbiddenIn(s string, words []string) string {
	low := strings.ToLower(s)
	for _, w := range words {
		if strings.Contains(low, w) {
			return w
		}
	}
	return ""
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
		if h, ok := strings.CutPrefix(p.From, "header:"); ok &&
			!reHeader.MatchString(h) {
			return fmt.Errorf("%s: %q is not a header name", where, h)
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
	token := ""
	if m.Auth.Token != nil {
		token = fmt.Sprintf(", gets a token from https://%s%s with %s",
			m.Auth.Token.Host, m.Auth.Token.Path,
			strings.Join(m.Auth.Token.Scopes, " "))
	}
	return fmt.Sprintf(
		"%s reads https://%s over %d endpoint(s), keeping %d declared "+
			"field(s)%s, and can reach nothing else",
		m.Name, m.Host, len(m.Endpoints), len(dedupe(fields)), token)
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
