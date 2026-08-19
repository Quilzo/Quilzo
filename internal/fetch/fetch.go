// Package fetch retrieves things from the internet without becoming a way to
// reach the inside of the network.
//
// # The bug this is built to not have
//
// "Import from a URL" is server-side request forgery with a friendly label. The
// server makes a request the user chose, from inside the network, with whatever
// the server can reach. On a cloud instance that includes the metadata endpoint
// at 169.254.169.254, which hands out credentials.
//
// The usual defence is to resolve the hostname, check the address against a
// deny list, and then make the request. Craft CMS shipped exactly that and it
// was bypassed, because the check and the request are two separate DNS lookups.
// An attacker returns a public address for the first and 169.254.169.254 for
// the second — DNS rebinding — and the validated address is not the one dialled.
//
// The fix is not a better list. It is to stop separating the check from the
// connection:
//
//	dialer.Control = func(network, address string, _ syscall.RawConn) error
//
// Control runs after the address is resolved and before the socket connects,
// with the exact address being dialled. There is no second lookup to poison,
// because there is no second lookup. Every connection this package makes goes
// through it, including the ones made for redirects, which is the other place
// validation is normally forgotten.
//
// # What else is refused
//
// Only https. A plain http URL is an unauthenticated channel where a network
// position rewrites what the site imports, and the whole point of importing is
// that the result gets published.
//
// Userinfo (https://user@host/) is refused rather than stripped, because
// parsers disagree about which part is the host and disagreeing is how a filter
// and a fetcher end up looking at different strings.
//
// Redirects are followed at most twice and revalidated each time. Not following
// them at all was tempting, but every CDN in existence redirects once, and a
// rule a correct source cannot satisfy is a rule people work around.
package fetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Limits bound what a fetch may cost. Zero values take the defaults.
type Limits struct {
	// MaxBytes caps the response body. A fetch with no ceiling is a way to
	// exhaust disk with one request.
	MaxBytes int64
	// Timeout bounds the whole exchange, not just the connection: a server
	// that sends one byte a second would otherwise hold the request open
	// indefinitely.
	Timeout time.Duration
	// MaxRedirects is how many hops are allowed. Each one is revalidated.
	MaxRedirects int
}

func (l Limits) withDefaults() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = 32 << 20 // 32 MiB
	}
	if l.Timeout <= 0 {
		l.Timeout = 20 * time.Second
	}
	if l.MaxRedirects < 0 {
		l.MaxRedirects = 0
	} else if l.MaxRedirects == 0 {
		l.MaxRedirects = 2
	}
	return l
}

// Result is what came back.
type Result struct {
	URL         string
	FinalURL    string
	Status      int
	ContentType string
	Body        []byte
	SHA256      string
	// Truncated says the body hit the ceiling. Reported rather than silently
	// returning a partial file, because a truncated PDF that validates is worse
	// than a refused one.
	Truncated bool
}

// blocked lists the address ranges a fetch may never reach.
//
// Named individually rather than as "not public", because the interesting ones
// each have a story and a reader should be able to see why each is here.
var blocked = []struct {
	cidr string
	why  string
}{
	{"0.0.0.0/8", "this host"},
	{"10.0.0.0/8", "private (RFC 1918)"},
	{"100.64.0.0/10", "carrier-grade NAT (RFC 6598)"},
	{"127.0.0.0/8", "loopback — the server itself"},
	{"169.254.0.0/16", "link-local, which is where cloud metadata lives"},
	{"172.16.0.0/12", "private (RFC 1918)"},
	{"192.0.0.0/24", "IETF protocol assignments"},
	{"192.0.2.0/24", "documentation"},
	{"192.168.0.0/16", "private (RFC 1918)"},
	{"198.18.0.0/15", "benchmarking"},
	{"198.51.100.0/24", "documentation"},
	{"203.0.113.0/24", "documentation"},
	{"224.0.0.0/4", "multicast"},
	{"240.0.0.0/4", "reserved"},
	{"255.255.255.255/32", "broadcast"},

	{"::/128", "unspecified"},
	{"::1/128", "loopback — the server itself"},
	{"64:ff9b::/96", "NAT64, which translates back to v4"},
	{"100::/64", "discard"},
	{"2001:db8::/32", "documentation"},
	{"fc00::/7", "unique local — the v6 private range"},
	{"fe80::/10", "link-local"},
	{"ff00::/8", "multicast"},
}

var blockedNets = func() []*net.IPNet {
	out := make([]*net.IPNet, 0, len(blocked))
	for _, b := range blocked {
		_, n, err := net.ParseCIDR(b.cidr)
		if err != nil {
			panic("fetch: bad CIDR " + b.cidr)
		}
		out = append(out, n)
	}
	return out
}()

// CheckIP reports why an address is refused, or empty if it is allowed.
//
// Exported so the reason can be surfaced to whoever pasted the URL. "Blocked"
// with no explanation makes people assume the tool is broken and go looking for
// a way around it.
func CheckIP(ip net.IP) string {
	if ip == nil {
		return "the address could not be parsed"
	}
	// An IPv4-mapped v6 address is a v4 target, so unmap it and let the v4
	// ranges below decide. This is why there is no ::ffff:0:0/96 entry in the
	// list: net.ParseCIDR normalises that prefix to a 4-byte network, which
	// truncates the /96 mask to its last four bytes — all zeroes — leaving
	// 0.0.0.0/0. The entry looked like it blocked v4-mapped addresses and in
	// fact blocked the entire IPv4 internet. A test asserting that a public
	// address is reachable is what caught it.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for i, n := range blockedNets {
		if n.Contains(ip) {
			return fmt.Sprintf("%s is %s", ip, blocked[i].why)
		}
	}
	return ""
}

// Client fetches URLs.
type Client struct {
	Limits Limits
	// Resolver is swappable so the tests can return a hostile answer without
	// needing a hostile DNS server.
	Resolver func(ctx context.Context, host string) ([]net.IP, error)
	// UserAgent identifies the fetch. Sites block anonymous fetchers, and a
	// blank agent is also a way to fetch things nobody can attribute.
	UserAgent string
}

// New returns a Client with the defaults.
func New() *Client {
	return &Client{Limits: Limits{}.withDefaults(),
		UserAgent: "quilzo/1 (+content import)"}
}

// GetWithToken is Get with a bearer credential attached.
//
// Separate from Get rather than a field on Client, because a credential that
// lives on the client is one that gets sent to whatever the next call happens
// to be pointed at — and this client follows redirects. Passing it per call
// keeps "which host receives this token" a decision at the call site.
//
// The redirect handling in Get revalidates every hop against the same address
// rules, so a peer cannot redirect a credentialed fetch onto the metadata
// endpoint. Go's own client drops the Authorization header across hosts.
func (c *Client) GetWithToken(ctx context.Context, raw, token string) (*Result, error) {
	return c.get(ctx, raw, func(req *http.Request) {
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Accept", "application/json")
	})
}

// ValidateURL checks a URL before anything is dialled.
//
// This is the cheap first pass, and it is deliberately *not* the security
// boundary — that is Control, below. Doing it here as well means an obviously
// wrong URL gets a useful message rather than a connection error.
func ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("that is not a URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("only https is allowed, not %q. Imported content "+
			"gets published, and over plain http anyone on the path chooses "+
			"what you publish", u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("a URL with credentials in it is refused. " +
			"Parsers disagree about which part of user@host is the host, and " +
			"a filter and a fetcher reading it differently is the bug")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("the URL has no host")
	}
	// A literal address skips DNS, so check it here too — Control will check it
	// again, but saying so now is a better error.
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if why := CheckIP(ip); why != "" {
			return nil, fmt.Errorf("refusing to fetch: %s", why)
		}
	}
	return u, nil
}

// Get fetches a URL.
func (c *Client) Get(ctx context.Context, raw string) (*Result, error) {
	return c.get(ctx, raw, nil)
}

// get is Get with a hook that decorates the request, so GetWithToken adds a
// header without a second copy of the address checks, the redirect
// revalidation and the body ceiling. Two copies of those is one copy that
// stops being revalidated.
func (c *Client) get(ctx context.Context, raw string, decorate func(*http.Request)) (*Result, error) {
	lim := c.Limits.withDefaults()
	u, err := ValidateURL(raw)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()

	client, err := c.httpClient(lim)
	if err != nil {
		return nil, err
	}
	hops := 0
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		hops++
		if hops > lim.MaxRedirects {
			return fmt.Errorf("too many redirects (%d); the source keeps "+
				"forwarding", hops)
		}
		if _, err := ValidateURL(req.URL.String()); err != nil {
			return fmt.Errorf("redirect to %s refused: %w", req.URL, err)
		}
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "*/*")
	if decorate != nil {
		decorate(req)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, unwrapDialError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d", u, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, lim.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", u, err)
	}
	if int64(len(body)) > lim.MaxBytes {
		return nil, fmt.Errorf("%s is larger than the %d byte limit", u, lim.MaxBytes)
	}

	sum := sha256.Sum256(body)
	return &Result{
		URL:         raw,
		FinalURL:    resp.Request.URL.String(),
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
		SHA256:      hex.EncodeToString(sum[:]),
	}, nil
}

// httpClient builds a client whose every connection passes the address check.
//
// One constructor for every request this package makes, so a method added later
// cannot quietly get an unchecked dialer.
func (c *Client) httpClient(lim Limits) (*http.Client, error) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("refusing to dial %q", address)
			}
			ip := net.ParseIP(host)
			if why := CheckIP(ip); why != "" {
				return fmt.Errorf("refusing to connect: %s", why)
			}
			return nil
		},
	}
	if c.Resolver != nil {
		dialer.Resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, fmt.Errorf("no resolver")
			},
		}
	}

	transport := &http.Transport{
		DialContext:           c.dialContext(dialer),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DisableKeepAlives:     true,
		// One connection per fetch. Pooling would let a later fetch reuse a
		// socket opened for an earlier host, and the address that was validated
		// belongs to the first request.
		MaxIdleConns: 0,
	}

	return &http.Client{Transport: transport}, nil
}

// dialContext wires the resolver override in, when there is one.
func (c *Client) dialContext(d *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	if c.Resolver == nil {
		return d.DialContext
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := c.Resolver(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("%s does not resolve", host)
		}
		// Every answer is checked, not just the first. A resolver returning one
		// public address and one internal one is the whole trick, and taking
		// the first would make the refusal depend on ordering.
		for _, ip := range ips {
			if why := CheckIP(ip); why != "" {
				return nil, fmt.Errorf("refusing to connect: %s", why)
			}
		}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
}

// unwrapDialError surfaces the refusal rather than the transport's wrapper,
// which buries it under "dial tcp: connect: ...".
func unwrapDialError(err error) error {
	msg := err.Error()
	if i := strings.Index(msg, "refusing to "); i >= 0 {
		return fmt.Errorf("%s", msg[i:])
	}
	return err
}

// PostForm sends a form to a URL, with the same connect-time address validation
// as Get.
//
// Separate from Get rather than a parameter on it, because the two have
// genuinely different risk: a POST to an attacker-chosen address can act rather
// than merely read. The same Control hook covers both, so there is no second
// path for somebody to forget.
func (c *Client) PostForm(ctx context.Context, raw string, form url.Values,
	username, password string) (*Result, error) {

	lim := c.Limits.withDefaults()
	u, err := ValidateURL(raw)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()

	client, err := c.httpClient(lim)
	if err != nil {
		return nil, err
	}
	// Redirects are not followed on a POST. A redirected form submission
	// replays the body — including a client secret — to wherever the redirect
	// points, and a token endpoint has no legitimate reason to redirect.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(),
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	if username != "" {
		req.SetBasicAuth(username, password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, unwrapDialError(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, lim.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	// A non-200 body is returned rather than discarded: OAuth error responses
	// are 400 with the reason inside, and swallowing them leaves the caller
	// with "it failed".
	return &Result{
		URL: raw, FinalURL: u.String(),
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
	}, nil
}

// Post sends raw bytes, with the same connect-time address validation as Get.
//
// A third method rather than options on the others, and all three build their
// client from one constructor — so the check cannot be missed by adding a
// method, which is the way a defence like this normally gets a hole.
func (c *Client) Post(ctx context.Context, raw string, body []byte,
	contentType string) (*Result, error) {

	lim := c.Limits.withDefaults()
	u, err := ValidateURL(raw)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()

	client, err := c.httpClient(lim)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(),
		bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, unwrapDialError(err)
	}
	defer resp.Body.Close()

	out, err := io.ReadAll(io.LimitReader(resp.Body, lim.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d: %s", u, resp.StatusCode,
			strings.TrimSpace(string(out[:min(len(out), 200)])))
	}
	return &Result{URL: raw, FinalURL: u.String(), Body: out,
		ContentType: resp.Header.Get("Content-Type")}, nil
}

// PostSigned sends a body with caller-supplied headers, through the same
// connect-time address check as everything else here.
//
// Used for webhooks, where the headers carry a signature the receiver checks.
// The status is returned rather than turned into an error, because a webhook
// caller needs to distinguish a 4xx that will never succeed from a 5xx worth
// retrying — and an error type cannot carry that without being unwrapped.
func (c *Client) PostSigned(ctx context.Context, raw string, body []byte,
	headers map[string]string) (*Result, error) {

	lim := c.Limits.withDefaults()
	u, err := ValidateURL(raw)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, lim.Timeout)
	defer cancel()

	client, err := c.httpClient(lim)
	if err != nil {
		return nil, err
	}
	// Redirects are not followed. A redirected webhook replays a signed body to
	// wherever the redirect points, and a receiver has no reason to redirect.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(),
		bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, unwrapDialError(err)
	}
	defer resp.Body.Close()
	// The response body is read and discarded up to a small limit, so a
	// receiver cannot make this hold memory by answering with a stream.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	return &Result{URL: raw, FinalURL: u.String(), Status: resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type")}, nil
}
