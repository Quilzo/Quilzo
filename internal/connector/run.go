// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package connector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Pulling pages, and the four places a pull goes wrong quietly.
//
// # The next URL is chosen by the server
//
// Cursor and next-URL pagination hand the upstream control of where the next
// request goes. A compromised tool, or one whose response somebody can
// influence, answers with a URL pointing somewhere else — a metadata service,
// an internal admin endpoint, a host that will accept the credential this
// request is carrying. Every implementation that follows it is doing what the
// API told it to. Here the host is checked against the manifest's declared
// one and a mismatch ends the run with a finding rather than a redirect.
//
// # Rate limits are not standardised, whatever a blog says
//
// The RateLimit header field work is still an Internet-Draft
// (draft-ietf-httpapi-ratelimit-headers-11, 23 May 2026) and its syntax has
// changed under it: the current form is a structured field with r and t
// parameters, not the limit/remaining/reset spelling most articles describe.
// Building on it would be building on something that moved twice.
//
// So the order here is: Retry-After first, because it is RFC 9110 and every
// vendor that says anything at all says that; then the draft's RateLimit, on
// a best-effort basis, accepting both spellings; then exponential backoff
// with jitter. The jitter is not politeness — a fleet of connectors that all
// back off by exactly the same amount comes back at exactly the same moment.
//
// # A checkpoint that advances on a partial failure loses data silently
//
// The watermark moves only when a page has been fully read and its records
// handed over. Advancing it on the way in means a failure half way through
// leaves a checkpoint past records nobody saw, and the next run starts after
// them. Nothing reports an error; the records are simply not there.
//
// # Everything a tool returns was typed by somebody
//
// A display name, a device name, a note field: all of it is written by users
// of that tool, some of whom are the people being investigated. Records come
// back as strings and go nowhere near a model's context without the isolation
// internal/agent applies to stored content.

// Doer is the HTTP client. An interface so a test drives the real loop
// against a real server rather than a mock of the loop.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// State is what a previous run remembered.
type State struct {
	// Watermark is the highest value seen for the endpoint's watermark path.
	Watermark string `json:"watermark,omitempty"`
	// At is when that run finished.
	At time.Time `json:"at,omitempty"`
}

// Result is what one run produced.
type Result struct {
	// Records are the mapped records, in the order the tool returned them.
	Records []map[string]string `json:"records"`
	Pages   int                 `json:"pages"`
	// Watermark is the new checkpoint, set only if every page was read.
	Watermark string `json:"watermark,omitempty"`
	// Truncated says a limit stopped the run rather than the data running
	// out — so the caller knows the absence of later records means nothing.
	Truncated string `json:"truncated,omitempty"`
	// Waited is how long was spent honouring rate limits, which is the
	// number that explains a slow run.
	Waited time.Duration `json:"waited,omitempty"`
}

// Complete reports whether the run saw everything there was.
func (r Result) Complete() bool { return r.Truncated == "" }

// Secrets supplies a credential by name. The manifest never holds one.
type Secrets interface {
	Secret(name string) (string, error)
}

// MapFunc is a fixed credential, for a caller that has already fetched one.
type MapFunc map[string]string

// Secret implements Secrets.
func (m MapFunc) Secret(name string) (string, error) {
	v, ok := m[name]
	if !ok {
		return "", fmt.Errorf("no credential called %q", name)
	}
	return v, nil
}

// Sleeper is how a run waits, injectable so a test does not.
type Sleeper func(context.Context, time.Duration) error

func realSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Run reads one endpoint to the end, or to a limit.
func Run(ctx context.Context, m Manifest, name string, c Doer, s Secrets,
	from State, sleep Sleeper) (Result, error) {

	var out Result
	if err := m.Validate(); err != nil {
		return out, err
	}
	e, ok := m.Endpoint(name)
	if !ok {
		return out, fmt.Errorf("%s has no endpoint called %q", m.Name, name)
	}
	if sleep == nil {
		sleep = realSleep
	}
	credential := ""
	if m.Auth.Kind != NoAuth {
		got, err := s.Secret(m.Auth.Secret)
		if err != nil {
			return out, fmt.Errorf("%s: %w", m.Name, err)
		}
		if strings.TrimSpace(got) == "" {
			return out, fmt.Errorf(
				"the credential named %q is empty. An empty credential "+
					"produces an authentication failure that reads exactly "+
					"like a revoked token", m.Auth.Secret)
		}
		credential = got
	}
	maxPages, maxRecords, timeout := m.Limits()

	next := m.first(e, from)
	highest := from.Watermark
	for page := 0; ; page++ {
		if page >= maxPages {
			out.Truncated = fmt.Sprintf(
				"stopped after %d page(s); there may be more", maxPages)
			break
		}
		body, retry, err := fetchPage(ctx, next, m, e, credential, c, timeout,
			sleep, &out)
		if err != nil {
			return out, err
		}
		if retry {
			page--
			continue
		}

		records, err := recordsIn(body, e.Records)
		if err != nil {
			return out, fmt.Errorf("%s/%s page %d: %w", m.Name, e.Name,
				page+1, err)
		}
		for _, rec := range records {
			if len(out.Records) >= maxRecords {
				out.Truncated = fmt.Sprintf(
					"stopped after %d record(s); there may be more",
					maxRecords)
				break
			}
			out.Records = append(out.Records, apply(e, rec))
			if e.Watermark != "" {
				if v := At(rec, e.Watermark); v > highest {
					highest = v
				}
			}
		}
		out.Pages = page + 1
		if out.Truncated != "" {
			break
		}

		advance, why, err := m.next(e, next, body, page, len(records))
		if err != nil {
			return out, err
		}
		if why != "" {
			out.Truncated = why
			break
		}
		if advance == nil {
			break
		}
		next = advance
	}

	// The checkpoint moves only when the run saw everything. A watermark
	// past records nobody read is a gap that never reports itself.
	if out.Complete() {
		out.Watermark = highest
	}
	return out, nil
}

// first builds the opening URL.
func (m Manifest) first(e Endpoint, from State) *url.URL {
	u := &url.URL{Scheme: "https", Host: m.Host, Path: e.Path}
	q := u.Query()
	for k, v := range e.Query {
		q.Set(k, v)
	}
	if e.Page.SizeParam != "" && e.Page.Size > 0 {
		q.Set(e.Page.SizeParam, strconv.Itoa(e.Page.Size))
	}
	switch e.Page.Kind {
	case Offset:
		q.Set(e.Page.Param, strconv.Itoa(e.Page.Start))
	case PageNumber:
		start := e.Page.Start
		if start == 0 {
			start = 1
		}
		q.Set(e.Page.Param, strconv.Itoa(start))
	}
	if e.Since != "" && from.Watermark != "" {
		q.Set(e.Since, from.Watermark)
	}
	u.RawQuery = q.Encode()
	return u
}

// next decides where the following page is, or why there is not one.
func (m Manifest) next(e Endpoint, current *url.URL, body any, page,
	got int) (*url.URL, string, error) {

	if got == 0 || e.Page.Kind.one() {
		return nil, "", nil
	}
	switch e.Page.Kind {
	case Cursor:
		cursor := At(body, e.Page.From)
		if cursor == "" {
			return nil, "", nil
		}
		u := *current
		q := u.Query()
		q.Set(e.Page.Param, cursor)
		u.RawQuery = q.Encode()
		return &u, "", nil

	case NextURL:
		raw := At(body, e.Page.From)
		if raw == "" {
			return nil, "", nil
		}
		u, err := url.Parse(raw)
		if err != nil {
			return nil, "", fmt.Errorf(
				"%s/%s returned %q as the next page, which is not a URL",
				m.Name, e.Name, raw)
		}
		if !u.IsAbs() {
			// A relative next is the tool's own path, which is fine: the
			// host comes from the manifest either way.
			joined := current.ResolveReference(u)
			joined.Scheme, joined.Host = "https", m.Host
			return joined, "", nil
		}
		if !sameHost(u.Host, m.Host) || u.Scheme != "https" {
			// The whole reason this strategy is named separately. A tool
			// that answers with somewhere else is a tool choosing where a
			// request carrying its credential goes next.
			return nil, "", fmt.Errorf(
				"%s/%s handed back %s as the next page, and this connector "+
					"declared %s. A next URL is chosen by the server, so "+
					"following it would let the tool aim a request that "+
					"carries its own credential at a host nobody approved",
				m.Name, e.Name, u.Scheme+"://"+u.Host, m.Host)
		}
		return u, "", nil

	case Offset:
		u := *current
		q := u.Query()
		at, _ := strconv.Atoi(q.Get(e.Page.Param))
		if got < e.Page.Size {
			return nil, "", nil
		}
		q.Set(e.Page.Param, strconv.Itoa(at+e.Page.Size))
		u.RawQuery = q.Encode()
		return &u, "", nil

	case PageNumber:
		u := *current
		q := u.Query()
		at, _ := strconv.Atoi(q.Get(e.Page.Param))
		if got < e.Page.Size {
			return nil, "", nil
		}
		q.Set(e.Page.Param, strconv.Itoa(at+1))
		u.RawQuery = q.Encode()
		return &u, "", nil
	}
	return nil, "", nil
}

func sameHost(got, want string) bool {
	if h, _, err := splitPort(got); err == nil {
		got = h
	}
	return strings.EqualFold(strings.TrimSuffix(got, "."),
		strings.TrimSuffix(want, "."))
}

func splitPort(h string) (string, string, error) {
	i := strings.LastIndex(h, ":")
	if i < 0 || strings.Contains(h[i:], "]") {
		return h, "", fmt.Errorf("no port")
	}
	return h[:i], h[i+1:], nil
}

// MaxAttempts bounds retries of one page.
//
// Four. A tool that is rate limiting for longer than a few minutes is a tool
// to come back to on the next scheduled run, and a connector that keeps
// trying turns one busy afternoon into a queue somebody has to drain.
const MaxAttempts = 4

// fetchPage gets one page, honouring rate limits. The bool says to try again.
func fetchPage(ctx context.Context, u *url.URL, m Manifest, e Endpoint,
	credential string, c Doer, timeout time.Duration, sleep Sleeper,
	out *Result) (any, bool, error) {

	for attempt := 1; ; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
			u.String(), nil)
		if err != nil {
			cancel()
			return nil, false, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "quilzo-connector")
		m.Auth.decorate(req, credential)

		res, err := c.Do(req)
		if err != nil {
			cancel()
			return nil, false, fmt.Errorf("%s/%s: %w", m.Name, e.Name, err)
		}
		status := res.StatusCode
		if status == http.StatusTooManyRequests ||
			(status >= 500 && status < 600) {
			wait := backoff(res, attempt)
			res.Body.Close()
			cancel()
			if attempt >= MaxAttempts {
				return nil, false, fmt.Errorf(
					"%s/%s answered %d %d times. A tool limiting for this "+
						"long is one to come back to on the next scheduled "+
						"run", m.Name, e.Name, status, attempt)
			}
			out.Waited += wait
			if serr := sleep(ctx, wait); serr != nil {
				return nil, false, serr
			}
			continue
		}
		if status < 200 || status > 299 {
			res.Body.Close()
			cancel()
			return nil, false, fmt.Errorf("%s/%s answered %d", m.Name,
				e.Name, status)
		}

		body, err := io.ReadAll(io.LimitReader(res.Body, MaxBody+1))
		res.Body.Close()
		cancel()
		if err != nil {
			return nil, false, err
		}
		if len(body) > MaxBody {
			return nil, false, fmt.Errorf(
				"%s/%s returned more than %d bytes in one page. A reader "+
					"with no ceiling is a way to fill a disk from outside",
				m.Name, e.Name, MaxBody)
		}
		var parsed any
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, false, fmt.Errorf("%s/%s: %w", m.Name, e.Name, err)
		}
		return parsed, false, nil
	}
}

func (a Auth) decorate(req *http.Request, credential string) {
	switch a.Kind {
	case Bearer:
		req.Header.Set("Authorization", "Bearer "+credential)
	case HeaderKey:
		req.Header.Set(a.Header, credential)
	case Basic:
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.
			EncodeToString([]byte(a.User+":"+credential)))
	}
}

// backoff decides how long to wait before trying a page again.
func backoff(res *http.Response, attempt int) time.Duration {
	if d, ok := retryAfter(res.Header.Get("Retry-After")); ok {
		return cap(d)
	}
	if d, ok := rateLimitReset(res.Header.Get("RateLimit")); ok {
		return cap(d)
	}
	// Vendor spellings, which is what most of the installed base emits.
	for _, h := range []string{"X-RateLimit-Reset", "X-Rate-Limit-Reset"} {
		if secs, err := strconv.Atoi(res.Header.Get(h)); err == nil &&
			secs > 0 && secs < 3600 {
			return cap(time.Duration(secs) * time.Second)
		}
	}
	base := time.Duration(1<<uint(attempt-1)) * time.Second
	// Jitter, because a fleet that backs off by exactly the same amount
	// comes back at exactly the same moment.
	return cap(base + time.Duration(rand.N(int64(base/2)+1)))
}

func cap(d time.Duration) time.Duration {
	switch {
	case d < 0:
		return time.Second
	case d > 2*time.Minute:
		return 2 * time.Minute
	default:
		return d
	}
}

// retryAfter parses RFC 9110 section 10.2.3: seconds, or an HTTP date.
func retryAfter(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second, true
	}
	if when, err := http.ParseTime(v); err == nil {
		return time.Until(when), true
	}
	return 0, false
}

// rateLimitReset reads the draft RateLimit field, in both spellings it has
// had. Best effort on purpose: it is a draft, it has changed, and a
// connector that depended on it would break when it changes again.
func rateLimitReset(v string) (time.Duration, bool) {
	if strings.TrimSpace(v) == "" {
		return 0, false
	}
	for _, part := range strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ';'
	}) {
		k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if k != "t" && k != "reset" {
			continue
		}
		if secs, err := strconv.Atoi(strings.Trim(strings.TrimSpace(val),
			`"`)); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second, true
		}
	}
	return 0, false
}

// recordsIn finds the array of records in a response body.
func recordsIn(body any, path string) ([]any, error) {
	target := body
	if path != "" {
		found, ok := lookupNode(body, path)
		if !ok {
			// Absent, not empty. A tool that renamed results in a minor
			// release would otherwise report an estate with nothing in it,
			// and a connector that returns no records and no error is
			// indistinguishable from a company that has no laptops.
			return nil, fmt.Errorf(
				"no %s in the response. A tool that changed its shape "+
					"returns zero records rather than an error, which reads "+
					"as an estate with nothing in it", path)
		}
		if found == nil {
			// Present and null: this page has nothing, which several APIs
			// spell this way and which is not a change of shape.
			return nil, nil
		}
		target = found
	}
	if target == nil {
		return nil, nil
	}
	arr, ok := target.([]any)
	if !ok {
		return nil, fmt.Errorf("%s is not an array of records",
			orBody(path))
	}
	return arr, nil
}

func orBody(path string) string {
	if path == "" {
		return "the response body"
	}
	return path
}

// apply maps one source record to the fields the endpoint declared.
//
// Only the declared fields. Whatever else the tool returned is not copied,
// not stored and not logged — which is the difference between a connector
// that reads four fields and one that happens to ask for four.
func apply(e Endpoint, rec any) map[string]string {
	out := make(map[string]string, len(e.Map))
	targets := make([]string, 0, len(e.Map))
	for t := range e.Map {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	for _, t := range targets {
		if v := At(rec, e.Map[t]); v != "" {
			out[t] = v
		}
	}
	return out
}

// Shape fetches one page and returns the parsed body, for an author working
// out what a tool returns.
//
// Deliberately separate from Run and deliberately one page. It exists so that
// `connect probe` can show the shape of a response; the caller is expected to
// print paths rather than values, because an author needs to know a tool
// returns user.email and does not need a page of somebody's staff list in
// their terminal's history.
func Shape(ctx context.Context, m Manifest, name string, c Doer,
	s Secrets) (any, error) {

	if err := m.Validate(); err != nil {
		return nil, err
	}
	e, ok := m.Endpoint(name)
	if !ok {
		return nil, fmt.Errorf("%s has no endpoint called %q", m.Name, name)
	}
	credential := ""
	if m.Auth.Kind != NoAuth {
		got, err := s.Secret(m.Auth.Secret)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", m.Name, err)
		}
		credential = got
	}
	_, _, timeout := m.Limits()
	var out Result
	body, _, err := fetchPage(ctx, m.first(e, State{}), m, e, credential, c,
		timeout, realSleep, &out)
	return body, err
}
