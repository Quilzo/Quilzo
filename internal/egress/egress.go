// Package egress is the one place this program reaches the network from.
//
// # Why it exists
//
// A deployment on a classified or otherwise isolated network has to be able to
// state, and show, that this process opens no connection off the host. Before
// this package it could not: internal/fetch was the main path, and assist,
// telegram, otlp and timestamp each built their own http.Client. Six places,
// no list of them, and no way to answer "what would this talk to" except by
// reading all of it and hoping.
//
// That is the difference between a claim and evidence. NIST SP 800-53 CM-7
// asks for least functionality -- the functions and ports actually needed,
// and no others -- and SC-7 asks for a boundary that is audited. Neither is
// satisfiable by a program whose network use is discovered by grep.
//
// # What it does
//
// Every outbound connection is dialled through here, tagged with the feature
// that wanted it. In Offline mode the dial is refused before a packet is sent,
// and the refusal names the feature and what stops working -- because the
// failure mode that matters is not a blocked connection, it is somebody
// spending an afternoon on a timeout with no idea which part of the program is
// unhappy.
//
// The purposes are a closed list, and a test walks the source to check that
// nothing constructs a client outside this package. A boundary that a new
// feature can quietly step over is a boundary for exactly as long as nobody
// adds a feature.
//
// # What it is not
//
// It is not a firewall and does not pretend to be. It governs this process.
// Loopback is permitted in Offline mode, because a connection that does not
// leave the host is not egress -- and because a local model or a local
// identity provider is a normal part of an isolated deployment. A proxy
// listening on loopback could forward off-host, and nothing here would know.
// The host's own controls are the boundary; this is the part of it this
// program can be held to.
package egress

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Mode is how much of the network this process may reach.
type Mode string

const (
	// Open is the ordinary default: federation delivers, webhooks fire,
	// timestamps are fetched.
	Open Mode = "open"
	// Offline refuses every connection that would leave the host.
	Offline Mode = "offline"
)

// Purpose is a reason this program opens a connection.
//
// Closed, and each carries what stops working without it. A purpose exists so
// that a refusal can say something useful and so that the report below can be
// exhaustive rather than a list somebody maintained by hand.
type Purpose struct {
	// Name is the identifier used in configuration and in reports.
	Name string
	// What the connection is for, in a sentence somebody deciding whether to
	// allow it can act on.
	What string
	// Without says what happens in Offline mode, so the consequence is
	// visible before the mode is turned on rather than discovered after.
	Without string
}

// Purposes is every reason this program has to reach the network.
//
// A closed list for the same reason the webhook event types and the privilege
// table are closed: an unlisted one is a capability nobody reviewed, and the
// review is the point.
var Purposes = []Purpose{
	{
		Name: "federation",
		What: "delivering activities to followers' inboxes, and fetching a " +
			"remote actor's public key so their delivery can be verified",
		Without: "this site federates with nobody. Followers on other servers " +
			"stop receiving posts, and activities arriving here cannot be " +
			"verified because their sender's key cannot be fetched",
	},
	{
		Name:    "webhook",
		What:    "notifying an endpoint that something was published or proposed",
		Without: "webhooks are not delivered. Nothing is queued or retried",
	},
	{
		Name: "timestamp",
		What: "asking a time-stamping authority to attest that a value existed " +
			"at a moment (RFC 3161)",
		Without: "audit heads carry no third-party time. They are still " +
			"signed, and the date on them is this machine's own word",
	},
	{
		Name: "anchor",
		What: "publishing an audit head where the operator cannot alter it",
		Without: "heads are not anchored. Rewriting history stays detectable " +
			"against a head somebody else holds and is no longer provable " +
			"against one nobody controls",
	},
	{
		Name: "assistant",
		What: "sending a prompt to a language model over HTTP",
		Without: "the writing assistant is unavailable. A model reachable on " +
			"loopback still works, which is the usual arrangement here",
	},
	{
		Name:    "chat",
		What:    "polling and replying on Telegram, Slack or Discord",
		Without: "the chat surfaces are unavailable, including the Mini App",
	},
	{
		Name:    "telemetry",
		What:    "exporting traces and metrics to an OTLP collector",
		Without: "nothing is exported. A collector on loopback still receives",
	},
	{
		Name: "import",
		What: "fetching a page or an image the operator asked to import",
		Without: "importing by URL is refused. Importing from a file is not " +
			"affected, which is how content arrives on an isolated network",
	},
}

// Lookup returns a purpose by name.
func Lookup(name string) (Purpose, bool) {
	for _, p := range Purposes {
		if p.Name == name {
			return p, true
		}
	}
	return Purpose{}, false
}

var (
	mu      sync.RWMutex
	mode    = Open
	refused = map[string]int{}
)

// SetMode fixes how much of the network this process may reach.
//
// Called once at startup. Not enforced as once -- a test needs to set it back
// -- but a program that changed it while running would be one whose boundary
// depends on when you asked.
func SetMode(m Mode) error {
	switch m {
	case Open, Offline:
	default:
		return fmt.Errorf("%q is not a network mode; it is open or offline", m)
	}
	mu.Lock()
	defer mu.Unlock()
	mode = m
	return nil
}

// Current reports the mode.
func Current() Mode {
	mu.RLock()
	defer mu.RUnlock()
	return mode
}

// Refusals reports what has been refused and how often, by purpose.
//
// Counted because the useful question on an isolated network is not "is it
// offline" but "what has been trying to leave" -- a feature quietly failing
// every five minutes is a misconfiguration somebody should be told about
// rather than a boundary working as intended.
func Refusals() map[string]int {
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[string]int, len(refused))
	for k, v := range refused {
		out[k] = v
	}
	return out
}

// ResetRefusals clears the counters, for tests.
func ResetRefusals() {
	mu.Lock()
	defer mu.Unlock()
	refused = map[string]int{}
}

// Blocked is returned when a dial is refused by the mode rather than by the
// network. Distinguished so a caller can tell a policy decision from an
// outage, and say so.
type Blocked struct {
	Purpose Purpose
	Address string
}

func (b *Blocked) Error() string {
	return fmt.Sprintf(
		"this deployment is offline, so %s cannot reach %s.\n"+
			"  What it was for: %s.\n"+
			"  Without it: %s.\n"+
			"  Allow it with `quilzo config set network.mode open`, or leave "+
			"it refused deliberately",
		b.Purpose.Name, b.Address, b.Purpose.What, b.Purpose.Without)
}

// Dial opens a connection for a purpose, or refuses it.
func Dial(ctx context.Context, purpose, network, address string) (net.Conn, error) {
	p, known := Lookup(purpose)
	if !known {
		// An unlisted purpose is a capability nobody reviewed. Refused in
		// every mode, because the alternative is that adding a caller adds an
		// unreviewed way off the host.
		return nil, fmt.Errorf(
			"%q is not a declared network purpose, so this connection is "+
				"refused. Add it to egress.Purposes with what it is for and "+
				"what stops working without it", purpose)
	}

	if Current() == Offline && !isLocal(address) {
		mu.Lock()
		refused[purpose]++
		mu.Unlock()
		return nil, &Blocked{Purpose: p, Address: address}
	}
	var d net.Dialer
	d.Timeout = 15 * time.Second
	return d.DialContext(ctx, network, address)
}

// Allowed reports whether a connection to this address may be made, without
// making it.
//
// For a caller that already has its own dialler and its own address rules --
// internal/fetch does, and they answer a different question -- so that the
// mode is checked without giving up the checks that were there.
func Allowed(purpose, address string) error {
	p, known := Lookup(purpose)
	if !known {
		return fmt.Errorf(
			"%q is not a declared network purpose, so this connection is "+
				"refused. Add it to egress.Purposes with what it is for and "+
				"what stops working without it", purpose)
	}
	if Current() == Offline && !isLocal(address) {
		mu.Lock()
		refused[purpose]++
		mu.Unlock()
		return &Blocked{Purpose: p, Address: address}
	}
	return nil
}

// Client returns an HTTP client whose connections go through Dial.
//
// The only sanctioned way to construct one in this program. A test walks the
// source to check nothing else does.
func Client(purpose string, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return Dial(ctx, purpose, network, addr)
			},
			// Kept modest and explicit rather than inherited from the
			// default: an isolated deployment should not be holding idle
			// connections it is not allowed to open.
			MaxIdleConns:        16,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

// isLocal reports whether an address stays on this host.
//
// Loopback only. Not private ranges: 10.0.0.0/8 is somebody else's machine on
// the same network, and on an isolated network that is exactly the reach an
// operator is trying to bound.
func isLocal(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Report is what a deployment shows an auditor: every way this program can
// reach the network, and whether it may.
func Report() string {
	m := Current()
	counts := Refusals()

	var b []byte
	b = append(b, fmt.Sprintf("network mode: %s\n\n", m)...)
	if m == Offline {
		b = append(b, "Every connection that would leave this host is refused "+
			"before a packet is\nsent. Loopback is permitted: a connection "+
			"that does not leave the host is not\negress, and a local model "+
			"or identity provider is a normal part of an\nisolated "+
			"deployment. A proxy listening on loopback could forward "+
			"off-host,\nand nothing here would know -- the host's own "+
			"controls are the boundary, and\nthis is the part of it this "+
			"program can be held to.\n\n"...)
	}

	names := make([]string, 0, len(Purposes))
	byName := map[string]Purpose{}
	for _, p := range Purposes {
		names = append(names, p.Name)
		byName[p.Name] = p
	}
	sort.Strings(names)

	for _, name := range names {
		p := byName[name]
		state := "permitted"
		if m == Offline {
			state = "refused"
		}
		b = append(b, fmt.Sprintf("  %-11s %s\n", name, state)...)
		b = append(b, fmt.Sprintf("    for:     %s\n", p.What)...)
		if m == Offline {
			b = append(b, fmt.Sprintf("    without: %s\n", p.Without)...)
			if n := counts[name]; n > 0 {
				b = append(b, fmt.Sprintf(
					"    refused: %d attempt(s) — something is still trying, "+
						"which is a\n             misconfiguration rather "+
						"than the boundary working\n", n)...)
			}
		}
		b = append(b, '\n')
	}
	return string(b)
}
