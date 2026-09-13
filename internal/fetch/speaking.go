// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package fetch

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/quilzo/quilzo/internal/egress"
)

// Clients for the callers that speak their own protocol.
//
// # Why this is here and not another egress.Client
//
// Five surfaces in this program talk to something over HTTP without going
// through Get: the assistant posts to a model, the Telegram bot calls the Bot
// API and long-polls it, the exporter posts spans to a collector, and the
// timestamp client posts an RFC 3161 request to an authority. None of them can
// use Get, because Get is a GET and these are POSTs of protocol-specific
// bodies. All five built their client with egress.Client, which enforces the
// deployment's network mode and nothing else.
//
// The mode is the wrong half on its own. Two things were missing from every
// one of them.
//
// # Redirects
//
// Go's default client follows up to ten, to wherever it is sent, and none of
// these four protocols redirect: an authority answers a timestamp request, a
// collector answers 200, the Bot API answers JSON. Following one is all risk
// and no function — and for Telegram the risk is concrete, because the bot
// token is a path segment, so a redirect hands the credential to whoever the
// redirect names. Go strips the Authorization header across hosts; it cannot
// strip a URL.
//
// So these clients refuse redirects outright. That is a rule a correct server
// can always satisfy, which is the test this package applies elsewhere before
// refusing something.
//
// # The check and the connection, again
//
// internal/otlp and internal/assist both resolve their endpoint, check every
// address it answers with, and then hand the URL to a client that resolves it
// again. That is the Craft CMS bug this package's doc comment opens with,
// reproduced twice: the address that was checked is not the address that is
// dialled, and a resolver that answers differently the second time is the
// whole trick.
//
// Their checks were good — every answer examined rather than the first — and
// they were in the wrong place. The rule now runs in Control, on the address
// being connected to, with no second lookup to poison. What each of them
// decided about where its endpoint may be does not change; only when it is
// enforced does.

// Reach decides whether one address may be connected to, and says why not.
//
// A function rather than a flag because these five do not want the same
// answer. An authority is a public service and has no business on a private
// address; a collector is usually a process on the same machine and has no
// business on the public internet. A single rule would be wrong for one of
// them, and the wrong rule gets turned off.
type Reach func(net.IP) string

// Public is the rule Get uses: no loopback, no private range, no metadata
// endpoint, nothing reserved.
func Public(ip net.IP) string { return CheckIP(ip) }

// OnThisNetwork permits this machine and the network it is on, and nothing
// else — the rule for a model or a collector an operator runs themselves.
//
// Link-local is refused even though it is not routable off the network,
// because 169.254.169.254 is on it and hands out credentials. "Somewhere
// nearby" is the description of a local endpoint; the metadata service is not
// a thing an operator means by it, and it is exactly what somebody would aim
// a configuration setting at.
func OnThisNetwork(ip net.IP) string {
	if ip == nil {
		return "the address could not be parsed"
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Sprintf("%s is link-local, which is where cloud metadata "+
			"lives, and not somewhere a local endpoint is run", ip)
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return ""
	}
	return fmt.Sprintf("%s is public, and only this machine and the network "+
		"it is on are permitted here", ip)
}

// Anywhere permits every address, leaving only the deployment's network mode.
//
// For the case where the operator has said in as many words that this
// connection leaves the machine — a hosted model, a collector elsewhere. It
// is a named value rather than a nil Reach so that a call site says which of
// the two it meant, and so that "no rule" cannot happen by leaving an
// argument out.
func Anywhere(net.IP) string { return "" }

// Speaking returns a client for a caller that makes its own requests.
//
// Every connection it opens is checked against reach at the moment it is
// dialled and against the deployment's network mode, and it follows no
// redirects.
func Speaking(purpose string, reach Reach, timeout time.Duration) *http.Client {
	if reach == nil {
		// Refusing everything, rather than allowing it. A caller that forgot
		// the argument gets a connection error naming this line, which is a
		// bug report; the other way round is a client with no rule at all and
		// no symptom.
		reach = func(net.IP) string {
			return "this client was built with no address rule, which is a " +
				"mistake in the caller rather than a property of the address"
		}
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("refusing to dial %q", address)
			}
			if why := reach(net.ParseIP(host)); why != "" {
				return fmt.Errorf("refusing to connect: %s", why)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// The mode first, so an isolated deployment's refusal names
				// the feature that wanted the connection rather than an
				// address it was never going to reach.
				if err := egress.Allowed(purpose, addr); err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, addr)
			},
			MaxIdleConns:        16,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf(
				"%s redirected to %s, and this is not a protocol that "+
					"redirects. Following it would send the request, and "+
					"anything in its URL, somewhere the configuration does "+
					"not name", via[len(via)-1].URL.Host, req.URL)
		},
	}
}
