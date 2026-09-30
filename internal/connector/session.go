// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// A session is one sitting with one tool: one access token, one pace, one
// budget, shared by every endpoint read in it.
//
// # Why the token belongs to the session and not to the request
//
// Vanta issues one live token per application. Asking for a new one revokes
// the old one at once, so two pulls that each fetch their own token take
// turns logging each other out, and each sees a 401 it did not cause. Zoho
// caps how many access tokens a refresh token may mint in a window. Both say
// the same thing: get a token once, use it until it is nearly spent, and
// fetch another only when it has been refused.
//
// # Why the budget is counted here
//
// Rate limits in a manifest are the tool's, not this program's: KnowBe4
// allows four requests a second, fifty a minute and 2,000 a day plus one per
// seat, and the day is shared with the console's own reports. Every request
// spends from it — a retry, a token exchange, a page — because each one is a
// request the tool counts.

// ErrBudget is a session that has spent what it was given.
var ErrBudget = errors.New("the request budget for this tool is spent")

// Session reads one tool.
type Session struct {
	m     Manifest
	c     Doer
	s     Secrets
	sleep Sleeper
	now   func() time.Time

	// Budget is how many more requests may be sent. Negative is no limit.
	Budget int
	// Requests counts every request sent, token exchanges and retries
	// included, because the tool counts them.
	Requests int

	last    time.Time
	static  string
	token   string
	expires time.Time
}

// NewSession checks the manifest and fetches a static credential. An OAuth
// token is fetched on the first request that needs one, not here, so a
// session that turns out to have nothing to read costs the tool nothing.
func NewSession(m Manifest, c Doer, s Secrets, sleep Sleeper) (*Session,
	error) {

	if err := m.Validate(); err != nil {
		return nil, err
	}
	if sleep == nil {
		sleep = realSleep
	}
	x := &Session{m: m, c: c, s: s, sleep: sleep, now: time.Now, Budget: -1}
	if m.Auth.Kind != NoAuth && !m.Auth.Kind.oauth() {
		got, err := x.secret(m.Auth.Secret)
		if err != nil {
			return nil, err
		}
		x.static = got
	}
	return x, nil
}

func (x *Session) secret(name string) (string, error) {
	got, err := x.s.Secret(name)
	if err != nil {
		return "", fmt.Errorf("%s: %w", x.m.Name, err)
	}
	if strings.TrimSpace(got) == "" {
		return "", fmt.Errorf(
			"the credential named %q is empty. An empty credential "+
				"produces an authentication failure that reads exactly "+
				"like a revoked token", name)
	}
	return got, nil
}

// spend takes one request from the budget and keeps the declared pace: the
// tool's, or the endpoint's where that is stricter.
func (x *Session) spend(ctx context.Context, e *Endpoint) error {
	if x.Budget == 0 {
		return ErrBudget
	}
	gap := x.m.Rate.Spacing()
	if e != nil && e.Rate.Spacing() > gap {
		gap = e.Rate.Spacing()
	}
	if gap > 0 && !x.last.IsZero() {
		if wait := gap - x.now().Sub(x.last); wait > 0 {
			if err := x.sleep(ctx, wait); err != nil {
				return err
			}
		}
	}
	x.last = x.now()
	x.Requests++
	if x.Budget > 0 {
		x.Budget--
	}
	return nil
}

// credential is what goes in the request: the static secret, or a current
// access token.
func (x *Session) credential(ctx context.Context) (string, error) {
	if !x.m.Auth.Kind.oauth() {
		return x.static, nil
	}
	if x.token != "" && x.now().Before(x.expires) {
		return x.token, nil
	}
	return x.exchange(ctx)
}

// MaxTokenBody is the most a token response may be. A token is a few
// hundred bytes; anything the size of a page is not a token response.
const MaxTokenBody = 64 << 10

// reToken is what an access token may contain. It goes into a header, and a
// line break in one would end that header and begin another the tool chose.
var reToken = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)

// usableToken is reToken and a length a token can have.
func usableToken(s string) bool {
	return len(s) >= 8 && len(s) <= 4096 && reToken.MatchString(s)
}

// exchange asks the declared token endpoint for an access token.
//
// The only request a connector sends that is not a GET, and the only one
// carrying the client secret. So it goes to one declared host and path, with
// no redirect followed (egress.Client refuses them), and nothing from the
// response is repeated in an error except the OAuth error code — a token
// endpoint that echoes its request would otherwise put the secret in a log.
func (x *Session) exchange(ctx context.Context) (string, error) {
	t := x.m.Auth.Token
	clientSecret, err := x.secret(x.m.Auth.Secret)
	if err != nil {
		return "", err
	}
	clientID, err := x.secret(t.Client)
	if err != nil {
		return "", err
	}
	fields := map[string]string{
		"client_id": clientID, "client_secret": clientSecret,
	}
	switch x.m.Auth.Kind {
	case OAuthClient:
		fields["grant_type"] = "client_credentials"
		fields["scope"] = strings.Join(t.Scopes, " ")
	case OAuthRefresh:
		refresh, rerr := x.secret(t.Refresh)
		if rerr != nil {
			return "", rerr
		}
		fields["grant_type"] = "refresh_token"
		fields["refresh_token"] = refresh
	}

	var body []byte
	contentType := "application/x-www-form-urlencoded"
	if t.Body == "json" {
		contentType = "application/json"
		body, err = json.Marshal(fields)
		if err != nil {
			return "", err
		}
	} else {
		form := url.Values{}
		for k, v := range fields {
			form.Set(k, v)
		}
		body = []byte(form.Encode())
	}

	if err := x.spend(ctx, nil); err != nil {
		return "", err
	}
	_, _, timeout := x.m.Limits()
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	target := (&url.URL{Scheme: "https", Host: t.Host, Path: t.Path}).String()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, target,
		bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "quilzo-connector")
	res, err := x.c.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s token endpoint: %w", x.m.Name, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, MaxTokenBody+1))
	if err != nil {
		return "", err
	}
	if len(raw) > MaxTokenBody {
		return "", fmt.Errorf("%s token endpoint returned more than %d "+
			"bytes, which is not a token", x.m.Name, MaxTokenBody)
	}
	var got struct {
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
		Error       string          `json:"error"`
	}
	_ = json.Unmarshal(raw, &got)
	code := oauthCode(got.Error)
	if res.StatusCode == http.StatusTooManyRequests {
		return "", fmt.Errorf(
			"%s token endpoint is limiting requests. Tools allow few token "+
				"exchanges — Vanta five a minute — so something else may be "+
				"asking for tokens with the same client", x.m.Name)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 || code != "" {
		// Zoho answers 200 with {"error": "invalid_code"}, so the body is
		// read on success too.
		why := fmt.Sprintf("answered %d", res.StatusCode)
		if code != "" {
			why += " (" + code + ")"
		}
		return "", fmt.Errorf("%s token endpoint %s. The client ID, secret "+
			"or refresh token was refused, or the application lacks the "+
			"declared scopes", x.m.Name, why)
	}
	if !usableToken(got.AccessToken) {
		return "", fmt.Errorf("%s token endpoint answered without a usable "+
			"access token", x.m.Name)
	}
	life := time.Hour
	if secs, ok := seconds(got.ExpiresIn); ok && secs > 0 {
		life = time.Duration(secs) * time.Second
	}
	// A minute early, so a token does not expire between being checked and
	// arriving; never less than half its life, for a tool issuing short ones.
	margin := time.Minute
	if margin > life/2 {
		margin = life / 2
	}
	x.token, x.expires = got.AccessToken, x.now().Add(life-margin)
	return x.token, nil
}

// oauthCode keeps an OAuth error code if it looks like one and drops it
// otherwise, because the field is the tool's to fill and ends up in a log.
func oauthCode(s string) string {
	if len(s) > 64 {
		return ""
	}
	for _, r := range s {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return ""
		}
	}
	return s
}

// seconds reads expires_in, which tools send as a number or as a string.
func seconds(raw json.RawMessage) (int64, bool) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// forget drops the access token, after the tool refused it.
func (x *Session) forget() { x.token, x.expires = "", time.Time{} }

// Run reads one endpoint to the end, or to a limit.
func (x *Session) Run(ctx context.Context, name string, from State) (Result,
	error) {

	var out Result
	e, ok := x.m.Endpoint(name)
	if !ok {
		return out, fmt.Errorf("%s has no endpoint called %q", x.m.Name, name)
	}
	if e.Each != nil {
		return out, fmt.Errorf("%s/%s is read for each record of %s; read "+
			"that first and pass its records to RunEach", x.m.Name, e.Name,
			e.Each.Of)
	}
	maxPages, maxRecords, _ := x.m.Limits()
	highest, err := x.pages(ctx, e, x.m.first(e, from), from.Watermark,
		&out, maxPages, maxRecords, nil)
	if err != nil {
		return out, err
	}
	// The checkpoint moves only when the run saw everything. A watermark
	// past records nobody read is a gap that never reports itself.
	if out.Complete() {
		out.Watermark = highest
	}
	return out, nil
}

// reKey is what a value from one tool may be before it goes into the path
// of a request to that tool. It came from the tool's own response, so it is
// the tool's to choose — and a key of "../admin" or "1?limit=1000000" would
// be the tool choosing what this reads next.
var reKey = regexp.MustCompile(`^[A-Za-z0-9._:~-]{1,128}$`)

// RunEach reads a per-record endpoint once for each of the parent records.
//
// Each record comes back with "parent" set to the key it was read for, so an
// app can be tied to its device and a result to its phishing test without
// the tool having to say so in the body.
func (x *Session) RunEach(ctx context.Context, name string,
	parents []map[string]string) (Result, error) {

	var out Result
	e, ok := x.m.Endpoint(name)
	if !ok {
		return out, fmt.Errorf("%s has no endpoint called %q", x.m.Name, name)
	}
	if e.Each == nil {
		return out, fmt.Errorf("%s/%s is not read per record", x.m.Name,
			e.Name)
	}
	var cutoff time.Time
	if e.Each.WithinDays > 0 {
		cutoff = x.now().AddDate(0, 0, -e.Each.WithinDays)
	}
	seen := map[string]bool{}
	var keys []string
	for _, p := range parents {
		key := p[e.Each.Key]
		if !reKey.MatchString(key) {
			// Counted rather than dropped in silence: a key that could
			// not be used is a parent whose children nobody read.
			out.Skipped++
			continue
		}
		if !cutoff.IsZero() {
			when, ok := parseTime(p[e.Each.When])
			if !ok || when.Before(cutoff) {
				continue
			}
		}
		if !seen[key] {
			seen[key] = true
			keys = append(keys, key)
		}
	}
	maxPages, maxRecords, _ := x.m.Limits()
	for _, key := range keys {
		child := e
		child.Path = strings.Replace(e.Path, "{key}", url.PathEscape(key), 1)
		if _, err := x.pages(ctx, child, x.m.first(child, State{}), "", &out,
			maxPages, maxRecords, map[string]string{"parent": key}); err != nil {
			return out, err
		}
		if out.Truncated != "" {
			break
		}
	}
	return out, nil
}

// single is the one record a Single endpoint returns.
func single(body any, path string) ([]any, error) {
	target := body
	if path != "" {
		found, ok := lookupNode(body, path)
		if !ok {
			return nil, fmt.Errorf("no %s in the response", path)
		}
		target = found
	}
	if _, ok := target.(map[string]any); !ok {
		return nil, fmt.Errorf("%s is not one record", orBody(path))
	}
	return []any{target}, nil
}

// explode turns each record's inner array into records of their own, each
// able to reach the record it came from as ^.
//
// An element that is not an object is skipped: a list of strings where a
// list of vulnerabilities was expected is a change of shape, and a record
// made from it would be a record with nothing in it.
func explode(records []any, path string) []any {
	var out []any
	for _, rec := range records {
		inner, ok := lookupNode(rec, path)
		if !ok {
			continue
		}
		arr, ok := inner.([]any)
		if !ok {
			continue
		}
		for _, el := range arr {
			obj, ok := el.(map[string]any)
			if !ok {
				continue
			}
			merged := make(map[string]any, len(obj)+1)
			for k, v := range obj {
				merged[k] = v
			}
			merged["^"] = rec
			out = append(out, merged)
		}
	}
	return out
}

// parseTime reads the timestamps tools write.
func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339,
		"2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	// Epoch milliseconds, which is how ManageEngine writes a time.
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil && ms > 1e11 {
		return time.UnixMilli(ms).UTC(), true
	}
	return time.Time{}, false
}

// pages follows one endpoint's pages from start, appending to out.
func (x *Session) pages(ctx context.Context, e Endpoint, next *url.URL,
	highest string, out *Result, maxPages, maxRecords int,
	stamp map[string]string) (string, error) {

	_, _, timeout := x.m.Limits()
	for {
		if out.Pages >= maxPages {
			out.Truncated = fmt.Sprintf(
				"stopped after %d page(s); there may be more", maxPages)
			return highest, nil
		}
		body, header, err := x.fetchPage(ctx, next, e, timeout, out)
		if errors.Is(err, ErrBudget) {
			out.Truncated = "the request budget for " + x.m.Name + " is " +
				"spent; the rest is read on the next run"
			return highest, nil
		}
		if err != nil {
			return highest, err
		}
		var records []any
		if e.Single {
			records, err = single(body, e.Records)
		} else {
			records, err = recordsIn(body, e.Records)
		}
		if err != nil {
			return highest, fmt.Errorf("%s/%s page %d: %w", x.m.Name, e.Name,
				out.Pages+1, err)
		}
		fetched := len(records)
		if e.Explode != "" {
			records = explode(records, e.Explode)
		}
		for _, rec := range records {
			if len(out.Records) >= maxRecords {
				out.Truncated = fmt.Sprintf(
					"stopped after %d record(s); there may be more",
					maxRecords)
				break
			}
			mapped := apply(e, rec)
			for k, v := range stamp {
				mapped[k] = v
			}
			out.Records = append(out.Records, mapped)
			if e.Watermark != "" {
				if v := At(rec, e.Watermark); v > highest {
					highest = v
				}
			}
		}
		out.Pages++
		if out.Truncated != "" {
			return highest, nil
		}
		advance, err := x.m.next(e, next, body, header, fetched)
		if err != nil {
			return highest, err
		}
		if advance == nil {
			return highest, nil
		}
		next = advance
	}
}

// fetchPage gets one page, honouring rate limits and replacing a refused
// access token once.
func (x *Session) fetchPage(ctx context.Context, u *url.URL, e Endpoint,
	timeout time.Duration, out *Result) (any, http.Header, error) {

	reauthed := false
	for attempt := 1; ; attempt++ {
		credential, err := x.credential(ctx)
		if err != nil {
			return nil, nil, err
		}
		if err := x.spend(ctx, &e); err != nil {
			return nil, nil, err
		}
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			u.String(), nil)
		if err != nil {
			cancel()
			return nil, nil, err
		}
		accept := "application/json"
		if e.Accept != "" {
			accept = e.Accept
		}
		req.Header.Set("Accept", accept)
		req.Header.Set("User-Agent", "quilzo-connector")
		x.m.Auth.decorate(req, credential)

		res, err := x.c.Do(req)
		if err != nil {
			cancel()
			return nil, nil, fmt.Errorf("%s/%s: %w", x.m.Name, e.Name, err)
		}
		status := res.StatusCode
		if status == http.StatusUnauthorized && x.m.Auth.Kind.oauth() &&
			!reauthed {
			// Once. Another process holding the same Vanta client may have
			// fetched a token, which revoked this one; a second refusal
			// after a fresh token is a real one.
			res.Body.Close()
			cancel()
			x.forget()
			reauthed = true
			attempt--
			continue
		}
		if status == http.StatusTooManyRequests ||
			(status >= 500 && status < 600) {
			wait := backoff(res, attempt)
			res.Body.Close()
			cancel()
			if attempt >= MaxAttempts {
				return nil, nil, fmt.Errorf(
					"%s/%s answered %d %d times. A tool limiting for this "+
						"long is one to come back to on the next scheduled "+
						"run", x.m.Name, e.Name, status, attempt)
			}
			out.Waited += wait
			if serr := x.sleep(ctx, wait); serr != nil {
				return nil, nil, serr
			}
			continue
		}
		if status < 200 || status > 299 {
			res.Body.Close()
			cancel()
			return nil, nil, fmt.Errorf("%s/%s answered %d", x.m.Name,
				e.Name, status)
		}

		body, err := io.ReadAll(io.LimitReader(res.Body, MaxBody+1))
		res.Body.Close()
		cancel()
		if err != nil {
			return nil, nil, err
		}
		if len(body) > MaxBody {
			return nil, nil, fmt.Errorf(
				"%s/%s returned more than %d bytes in one page. A reader "+
					"with no ceiling is a way to fill a disk from outside",
				x.m.Name, e.Name, MaxBody)
		}
		parsed, err := decode(body)
		if err != nil {
			return nil, nil, fmt.Errorf("%s/%s: %w", x.m.Name, e.Name, err)
		}
		return parsed, res.Header, nil
	}
}

// decode parses a body keeping every number exactly as the tool wrote it.
//
// ManageEngine identifies a device as 9007199254741001, which is past 2^53.
// A float64 holds the even numbers up there and rounds the odd ones to a
// neighbour, so parsed the ordinary way that device's apps are requested
// with its neighbour's identifier — a different device's software, filed
// under this one, with nothing anywhere reporting it.
func decode(body []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("the response holds more than one JSON value")
	}
	return parsed, nil
}

// Shape fetches one page and returns the parsed body and the names of the
// response headers, for an author working out what a tool returns.
//
// Deliberately one page, and the header names without their values: a
// cursor may arrive in a header (KnowBe4's replacement for page numbers is
// not yet documented), and seeing that a header exists is what an author
// needs. Key fills {key} for a per-record endpoint.
func (x *Session) Shape(ctx context.Context, name, key string) (any,
	[]string, error) {

	e, ok := x.m.Endpoint(name)
	if !ok {
		return nil, nil, fmt.Errorf("%s has no endpoint called %q", x.m.Name,
			name)
	}
	if e.Each != nil {
		if !reKey.MatchString(key) {
			return nil, nil, fmt.Errorf("%s/%s is read for each %s; name "+
				"one with --key", x.m.Name, e.Name, e.Each.Of)
		}
		e.Path = strings.Replace(e.Path, "{key}", url.PathEscape(key), 1)
	}
	_, _, timeout := x.m.Limits()
	var out Result
	body, header, err := x.fetchPage(ctx, x.m.first(e, State{}), e, timeout,
		&out)
	if err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(header))
	for k := range header {
		names = append(names, k)
	}
	sortStrings(names)
	return body, names, nil
}

// Read is one endpoint's outcome in a call to All.
type Read struct {
	Endpoint string
	Result   Result
	Err      error
	// Asked is whether the caller named this endpoint. A parent read only
	// because a per-record endpoint needed its records is not.
	Asked bool
}

// All reads the named endpoints, or every endpoint when none is named, each
// parent before the endpoints read for its records.
//
// A per-record endpoint whose parent failed is reported as not read rather
// than as empty, and one whose parent stopped short is marked incomplete:
// the apps of the first three hundred devices are not the apps of the
// estate, and a result that did not say so would read as though they were.
func (x *Session) All(ctx context.Context, names []string,
	from map[string]State) []Read {

	asked := map[string]bool{}
	for _, n := range names {
		asked[n] = true
	}
	all := len(names) == 0
	needed := map[string]bool{}
	for _, e := range x.m.Endpoints {
		if all || asked[e.Name] {
			needed[e.Name] = true
			if e.Each != nil {
				needed[e.Each.Of] = true
			}
		}
	}
	var out []Read
	parents := map[string]Result{}
	for _, e := range x.m.Endpoints {
		if e.Each != nil || !needed[e.Name] {
			continue
		}
		res, err := x.Run(ctx, e.Name, from[e.Name])
		if err == nil {
			parents[e.Name] = res
		}
		out = append(out, Read{Endpoint: e.Name, Result: res, Err: err,
			Asked: all || asked[e.Name]})
	}
	for _, e := range x.m.Endpoints {
		if e.Each == nil || !needed[e.Name] {
			continue
		}
		parent, ok := parents[e.Each.Of]
		if !ok {
			out = append(out, Read{Endpoint: e.Name, Asked: true,
				Err: fmt.Errorf("%s/%s was not read, because reading %s "+
					"failed", x.m.Name, e.Name, e.Each.Of)})
			continue
		}
		res, err := x.RunEach(ctx, e.Name, parent.Records)
		if err == nil && !parent.Complete() && res.Truncated == "" {
			res.Truncated = fmt.Sprintf("read for the %d %s that were "+
				"fetched; that read stopped short (%s)", len(parent.Records),
				e.Each.Of, parent.Truncated)
		}
		out = append(out, Read{Endpoint: e.Name, Result: res, Err: err,
			Asked: true})
	}
	return out
}
