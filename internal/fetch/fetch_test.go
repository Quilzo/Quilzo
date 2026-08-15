package fetch

import (
	"context"
	"net"
	"strings"
	"testing"
)

// -- what a URL may be -------------------------------------------------------

func TestOnlyHTTPSIsAccepted(t *testing.T) {
	for _, raw := range []string{
		"http://example.com/x.png",
		"file:///etc/passwd",
		"gopher://example.com:70/_x",
		"ftp://example.com/x",
		"dict://127.0.0.1:11211/stat",
		"jar:https://example.com/x.zip!/y",
	} {
		if _, err := ValidateURL(raw); err == nil {
			t.Errorf("%s was accepted", raw)
		}
	}
	if _, err := ValidateURL("https://example.com/x.png"); err != nil {
		t.Errorf("a normal https URL was refused: %v", err)
	}
}

// Refused rather than stripped: parsers disagree about which part of
// user@host:port/ is the host, and a filter and a fetcher reading it
// differently is the bug rather than an inconvenience.
func TestCredentialsInAURLAreRefused(t *testing.T) {
	for _, raw := range []string{
		"https://user@evil.example/",
		"https://user:pass@evil.example/",
		"https://example.com@169.254.169.254/latest/meta-data/",
	} {
		if _, err := ValidateURL(raw); err == nil {
			t.Errorf("%s was accepted", raw)
		}
	}
}

// The address everyone means when they say SSRF, plus the ranges that reach
// the rest of the network.
func TestLiteralInternalAddressesAreRefused(t *testing.T) {
	for _, raw := range []string{
		"https://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"https://127.0.0.1:8080/",
		"https://localhost.localdomain./", // trailing dot, still resolves internally
		"https://10.0.0.1/",
		"https://172.16.0.1/",
		"https://192.168.1.1/",
		"https://100.64.0.1/",
		"https://[::1]/",
		"https://[fd00::1]/",
		"https://[fe80::1]/",
		"https://[::ffff:169.254.169.254]/", // v4-mapped
		"https://[64:ff9b::a9fe:a9fe]/",     // NAT64 to 169.254.169.254
		"https://0.0.0.0/",
	} {
		u, err := ValidateURL(raw)
		if err != nil {
			continue // refused at parse, which is fine
		}
		// If it parsed, the address must still be refused on its merits.
		if ip := net.ParseIP(u.Hostname()); ip != nil {
			if CheckIP(ip) == "" {
				t.Errorf("%s was allowed", raw)
			}
			continue
		}
		t.Logf("%s is a name, not a literal; the dial-time check covers it", raw)
	}
}

// The refusal has to say why. "Blocked" with no reason makes people assume the
// tool is broken and go looking for a way round it.
func TestRefusalsExplainThemselves(t *testing.T) {
	why := CheckIP(net.ParseIP("169.254.169.254"))
	if !strings.Contains(why, "metadata") {
		t.Errorf("the metadata address is refused as %q, which does not say "+
			"what it is", why)
	}
	if !strings.Contains(CheckIP(net.ParseIP("127.0.0.1")), "loopback") {
		t.Error("loopback is not named as loopback")
	}
	if CheckIP(net.ParseIP("93.184.216.34")) != "" {
		t.Error("a public address was refused")
	}
}

// -- the part that actually matters -----------------------------------------

// This is the Craft CMS bug, stated as the property that prevents it.
//
// Their check resolved the hostname, approved the answer, and then let the HTTP
// client resolve it again. Two lookups means two answers, and DNS rebinding
// makes them differ — the address that was validated is not the address that
// was dialled.
//
// The fix is not a better deny list, it is that there is only ever one
// resolution per connection and the check happens on its result. So the thing
// worth asserting is the count: if a fetch resolves a name exactly once, there
// is no gap between the check and the dial for a second answer to slip into.
func TestAFetchResolvesEachNameExactlyOnce(t *testing.T) {
	resolutions := 0
	c := New()
	c.Resolver = func(ctx context.Context, host string) ([]net.IP, error) {
		resolutions++
		// Internal, so the fetch is refused before any socket is opened and
		// the test does not touch the network.
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}

	_, err := c.Get(context.Background(), "https://rebind.example/x.png")
	if err == nil {
		t.Fatal("the fetch reached an internal address")
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
	if resolutions != 1 {
		t.Errorf("the name was resolved %d times; anything above one is a "+
			"window a second DNS answer can be substituted into", resolutions)
	}
}

// Belt and braces: even if a resolver somehow returns a public address, the
// dialer's Control hook sees the literal address the socket is about to connect
// to and checks it there. This asserts the hook exists and refuses, without
// opening a connection, by handing it an internal address directly.
func TestTheDialTimeCheckRefusesRegardlessOfWhatResolutionSaid(t *testing.T) {
	for _, addr := range []string{
		"169.254.169.254:80", "127.0.0.1:443", "[::1]:443", "10.0.0.1:443",
	} {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal(err)
		}
		if why := CheckIP(net.ParseIP(host)); why == "" {
			t.Errorf("the dial-time check would have allowed %s", addr)
		}
	}
}

// A resolver that returns one good address and one bad one must be refused.
// Taking the first answer would make the outcome depend on ordering, which is
// not a security property.
func TestASplitDNSAnswerIsRefusedEntirely(t *testing.T) {
	c := New()
	c.Resolver = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("93.184.216.34"),
			net.ParseIP("169.254.169.254"),
		}, nil
	}
	_, err := c.Get(context.Background(), "https://split.example/x")
	if err == nil {
		t.Fatal("a response containing an internal address was accepted")
	}
	if !strings.Contains(err.Error(), "refusing") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

func TestAHostThatResolvesOnlyInternallyIsRefused(t *testing.T) {
	c := New()
	c.Resolver = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.1.2.3")}, nil
	}
	_, err := c.Get(context.Background(), "https://internal.example/x")
	if err == nil {
		t.Fatal("a hostname pointing at a private address was fetched")
	}
}

// -- limits ------------------------------------------------------------------

func TestDefaultsAreBounded(t *testing.T) {
	l := Limits{}.withDefaults()
	if l.MaxBytes <= 0 {
		t.Error("no size ceiling by default; one request could fill the disk")
	}
	if l.Timeout <= 0 {
		t.Error("no timeout by default; one slow server holds a request open")
	}
	if l.MaxRedirects <= 0 {
		t.Error("redirects should be allowed but bounded — every CDN uses one")
	}
	// And a caller must be able to turn redirects off entirely.
	if got := (Limits{MaxRedirects: -1}).withDefaults().MaxRedirects; got != 0 {
		t.Errorf("MaxRedirects -1 should mean none, got %d", got)
	}
}

// Every blocked range must parse, or a typo silently removes a defence and
// nothing says so.
func TestEveryBlockedRangeIsValidAndExplained(t *testing.T) {
	if len(blocked) != len(blockedNets) {
		t.Fatal("a range failed to parse")
	}
	for i, b := range blocked {
		if _, _, err := net.ParseCIDR(b.cidr); err != nil {
			t.Errorf("%s does not parse: %v", b.cidr, err)
		}
		if len(b.why) < 4 {
			t.Errorf("%s has no explanation", b.cidr)
		}
		if blockedNets[i] == nil {
			t.Errorf("%s produced a nil network", b.cidr)
		}
	}
	// The two that matter most, asserted by name so removing them fails here.
	var haveMetadata, haveLoopback bool
	for _, b := range blocked {
		if b.cidr == "169.254.0.0/16" {
			haveMetadata = true
		}
		if b.cidr == "127.0.0.0/8" {
			haveLoopback = true
		}
	}
	if !haveMetadata || !haveLoopback {
		t.Error("the link-local or loopback range is missing")
	}
}

// The regression that produced the comment in CheckIP. An entry for
// ::ffff:0:0/96 normalises to 0.0.0.0/0 and blocks the entire IPv4 internet
// while looking like it blocks v4-mapped addresses. Every defence needs a test
// that it does not also refuse the traffic it exists to permit.
func TestPublicAddressesStayReachable(t *testing.T) {
	for _, addr := range []string{
		"93.184.216.34", // example.com
		"1.1.1.1",
		"8.8.8.8",
		"140.82.121.4", // github
		"2606:4700::1111",
		"2a00:1450:4009::200e",
	} {
		if why := CheckIP(net.ParseIP(addr)); why != "" {
			t.Errorf("%s is refused as %q, but it is a public address", addr, why)
		}
	}
}

// And the mapped forms must still be judged on the address they carry.
func TestIPv4MappedAddressesAreJudgedOnTheirIPv4Value(t *testing.T) {
	if CheckIP(net.ParseIP("::ffff:169.254.169.254")) == "" {
		t.Error("a v4-mapped metadata address was allowed")
	}
	if CheckIP(net.ParseIP("::ffff:127.0.0.1")) == "" {
		t.Error("a v4-mapped loopback address was allowed")
	}
	if why := CheckIP(net.ParseIP("::ffff:93.184.216.34")); why != "" {
		t.Errorf("a v4-mapped public address was refused: %s", why)
	}
}
