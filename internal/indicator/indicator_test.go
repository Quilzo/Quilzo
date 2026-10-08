// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package indicator

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/telemetry"
)

var now = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func must(t *testing.T, k Kind, v string) Indicator {
	t.Helper()
	i, err := New(k, v, "feed", "", time.Time{}, time.Time{}, now)
	if err != nil {
		t.Fatalf("%s %q: %v", k, v, err)
	}
	return i
}

func event(at time.Time, obs ...telemetry.Observable) telemetry.Event {
	return telemetry.Event{Time: at, Received: at, Source: "proxy",
		Actor:       telemetry.ID{Issuer: "okta", Value: "dana"},
		Observables: obs}
}

func ob(k telemetry.ObservableKind, v string) telemetry.Observable {
	return telemetry.Observable{Kind: k, Value: v}
}

func ids(hits []Hit) string {
	var out []string
	for _, h := range hits {
		out = append(out, h.Indicator.Value)
	}
	return strings.Join(out, " ")
}

// The things feeds carry that are never indicators, each refused for what
// it is.
func TestSomeThingsAreNeverIndicators(t *testing.T) {
	for value, k := range map[string]Kind{
		"10.0.0.5": IP, "192.168.1.1": IP, "127.0.0.1": IP, "0.0.0.0": IP,
		"169.254.1.1": IP, "fe80::1": IP, "::1": IP, "224.0.0.1": IP,
		"::ffff:10.0.0.5": IP, "not-an-address": IP,
		"com": Domain, "localhost": Domain, "github.io": Domain,
		"amazonaws.com": Domain, "co.uk": Domain, "1.2.3.4": Domain,
		"bad domain.example": Domain, "": Domain,
		"d41d8cd98f00b204e9800998ecf8427e":                                 Hash,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": Hash,
		"da39a3ee5e6b4b0d3255bfef95601890afd80709":                         Hash,
		"abc123": Hash, "zz39a3ee5e6b4b0d3255bfef95601890afd80709": Hash,
		"https://evil.example/": URL, "https://evil.example": URL,
		"ftp://evil.example/x": URL, "javascript:alert(1)": URL,
		"nobody": Email, "a@localhost": Email,
	} {
		if got, err := Normalise(k, value); err == nil {
			t.Errorf("%s %q was accepted as %q", k, value, got)
		}
	}
	// What is under a shared domain is somebody's, and is accepted.
	for value, k := range map[string]Kind{
		"evil.github.io": Domain, "bucket-7.s3.amazonaws.com": Domain,
		"203.0.113.9": IP, "2001:db8::1": IP,
	} {
		if _, err := Normalise(k, value); err != nil {
			t.Errorf("%s %q was refused: %v", k, value, err)
		}
	}
}

// Written so it cannot be clicked, and in any case: one stored form.
func TestOneIndicatorHasOneForm(t *testing.T) {
	for in, want := range map[string]string{
		"Evil[.]Example.":                     "evil.example",
		"hxxps://Evil[.]example/a/B?x=1#frag": "https://evil.example/a/B?x=1",
		"https://user:pw@evil.example/a":      "https://evil.example/a",
		"203[.]0[.]113[.]9":                   "203.0.113.9",
		"::ffff:203.0.113.9":                  "203.0.113.9",
		"2001:0DB8:0000::0001":                "2001:db8::1",
		"ABCDEF0123456789ABCDEF0123456789":    "abcdef0123456789abcdef0123456789",
		"Billing[@]Evil[.]Example":            "billing@evil.example",
	} {
		k, ok := Guess(in)
		if !ok {
			t.Errorf("%q: no kind guessed", in)
			continue
		}
		got, err := Normalise(k, in)
		if err != nil || got != want {
			t.Errorf("%q as %s: %q %v, want %q", in, k, got, err, want)
		}
	}
	a, b := must(t, Domain, "Evil[.]example"), must(t, Domain, "evil.example.")
	if a.ID != b.ID {
		t.Error("the same domain written two ways is two indicators")
	}
	if must(t, IP, "203.0.113.9").ID == must(t, Domain, "evil.example").ID {
		t.Error("different indicators share an identifier")
	}
}

func TestAnIndicatorHasAnAuthorAndAnEnd(t *testing.T) {
	if _, err := New(IP, "203.0.113.9", " ", "", time.Time{}, time.Time{}, now); err == nil {
		t.Error("an indicator from nobody")
	}
	i := must(t, IP, "203.0.113.9")
	if got := i.Until.Sub(now); got != DefaultLife {
		t.Errorf("with no end stated it is believed for %s", got)
	}
	far, _ := New(IP, "203.0.113.9", "feed", "", time.Time{},
		now.Add(10*MaxLife), now)
	if far.Until.Sub(now) != MaxLife {
		t.Errorf("an end ten years off was kept as %s", far.Until.Sub(now))
	}
	if _, err := New(IP, "203.0.113.9", "feed", "", time.Time{},
		now.Add(-time.Hour), now); err == nil {
		t.Error("an indicator that had already lapsed was stored, where " +
			"it would never match and read as cover")
	}
	if !i.Live(now) || i.Live(i.Until) {
		t.Error("live at the wrong moments")
	}
}

// True positives, and the near misses beside each.
func TestMatchingFindsWhatIsNamedAndNotWhatResemblesIt(t *testing.T) {
	s := NewSet([]Indicator{must(t, IP, "203.0.113.9"),
		must(t, Domain, "evil.example"), must(t, Hash,
			"ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"),
		must(t, URL, "https://files.example/drop.bin"),
		must(t, Email, "billing@lookalike.example")})
	for name, c := range map[string]struct {
		o    telemetry.Observable
		want string
	}{
		"the address":          {ob(telemetry.ObservableIP, "203.0.113.9"), "203.0.113.9"},
		"the address, mapped":  {ob(telemetry.ObservableIP, "::ffff:203.0.113.9"), "203.0.113.9"},
		"the next address":     {ob(telemetry.ObservableIP, "203.0.113.90"), ""},
		"the domain":           {ob(telemetry.ObservableDomain, "Evil.Example."), "evil.example"},
		"a name under it":      {ob(telemetry.ObservableHostname, "cdn.a.evil.example"), "evil.example"},
		"a name ending in it":  {ob(telemetry.ObservableDomain, "notevil.example"), ""},
		"a name containing it": {ob(telemetry.ObservableDomain, "evil.example.org"), ""},
		"its parent":           {ob(telemetry.ObservableDomain, "example"), ""},
		"a URL on the domain":  {ob(telemetry.ObservableURL, "http://x.evil.example/a?b"), "evil.example"},
		"a URL on the address": {ob(telemetry.ObservableURL, "http://203.0.113.9:8080/a"), "203.0.113.9"},
		"the URL":              {ob(telemetry.ObservableURL, "HTTPS://Files.Example/drop.bin#x"), "https://files.example/drop.bin"},
		"another path":         {ob(telemetry.ObservableURL, "https://files.example/drop.bin2"), ""},
		"the hash, upper case": {ob(telemetry.ObservableHash, "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"), "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
		"the sender":           {ob(telemetry.ObservableEmail, "Billing@Lookalike.example"), "billing@lookalike.example"},
		"another sender":       {ob(telemetry.ObservableEmail, "billing@lookalike.example.org"), ""},
		// The right value in the wrong kind of field is not a match: an
		// address that appears as a file name is a file name.
		"an address as a file": {ob(telemetry.ObservableFile, "203.0.113.9"), ""},
	} {
		if got := ids(s.Match(event(now, c.o))); got != c.want {
			t.Errorf("%s: matched %q, want %q", name, got, c.want)
		}
	}
	// Never in the message: anybody can get a string logged.
	e := event(now)
	e.Message = "connection to 203.0.113.9 and evil.example refused"
	e.Raw = map[string]string{"note": "203.0.113.9"}
	if hits := s.Match(e); len(hits) != 0 {
		t.Errorf("matched on free text: %s", ids(hits))
	}
	// Once per indicator per event, however many fields carry it.
	if hits := s.Match(event(now, ob(telemetry.ObservableIP, "203.0.113.9"),
		ob(telemetry.ObservableIP, "203.0.113.9"))); len(hits) != 1 {
		t.Errorf("%d hits for one indicator in one event", len(hits))
	}
}

// An indicator is about a span of time. An event after it lapsed is about
// whoever holds the address now.
func TestAnEventOutsideWhatWasClaimedIsNotAMatch(t *testing.T) {
	i, _ := New(IP, "203.0.113.9", "feed", "", now.Add(-30*24*time.Hour),
		now.Add(10*24*time.Hour), now)
	s := NewSet([]Indicator{i})
	hit := ob(telemetry.ObservableIP, "203.0.113.9")
	for name, c := range map[string]struct {
		at   time.Time
		want int
	}{
		"last week, before it was known here": {now.Add(-7 * 24 * time.Hour), 1},
		"today":                               {now, 1},
		"before the campaign":                 {now.Add(-40 * 24 * time.Hour), 0},
		"after it lapsed":                     {now.Add(11 * 24 * time.Hour), 0},
	} {
		if got := len(s.Match(event(c.at, hit))); got != c.want {
			t.Errorf("%s: %d match(es), want %d", name, got, c.want)
		}
	}
}

func TestTheSameIndicatorFromTwoFeedsIsOneWithTwoSources(t *testing.T) {
	s := NewSet(nil)
	a, _ := New(IP, "203.0.113.9", "feed-a", "", time.Time{}, now.Add(24*time.Hour), now)
	b, _ := New(IP, "203.0.113.9", "feed-b", "Qakbot C2", time.Time{}, now.Add(72*time.Hour), now)
	if !s.Add(a) || s.Add(b) || s.Add(b) {
		t.Fatal("new and known are the wrong way round")
	}
	got, _ := s.Get(a.ID)
	if s.Len() != 1 || strings.Join(got.Sources, ",") != "feed-a,feed-b" ||
		!got.Until.Equal(b.Until) || got.Note != "Qakbot C2" {
		t.Errorf("%+v", got)
	}
	if !s.Remove(a.ID) || s.Remove(a.ID) || s.Len() != 0 {
		t.Error("remove")
	}
	if len(s.Match(event(now, ob(telemetry.ObservableIP, "203.0.113.9")))) != 0 {
		t.Error("a removed indicator still matches")
	}
}

const bundle = `{"type":"bundle","id":"bundle--1","objects":[
 {"type":"indicator","name":"Qakbot C2","pattern_type":"stix","pattern":"[ipv4-addr:value = '203.0.113.9']","valid_from":"2026-09-01T00:00:00Z"},
 {"type":"indicator","pattern":"[domain-name:value = 'evil.example'] OR [url:value = 'https://files.example/drop.bin']","valid_from":"2026-09-01T00:00:00Z"},
 {"type":"indicator","pattern":"[file:hashes.'SHA-256' = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789' OR file:hashes.MD5 = 'abcdef0123456789abcdef0123456789']"},
 {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.7' AND network-traffic:dst_port = 443]"},
 {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.8'] FOLLOWEDBY [domain-name:value = 'later.example']"},
 {"type":"indicator","pattern":"[ipv4-addr:value ISSUBSET '198.51.100.0/24']"},
 {"type":"indicator","pattern":"[domain-name:value != 'good.example']"},
 {"type":"indicator","pattern":"[domain-name:value MATCHES '^.*\\\\.example$']"},
 {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.9'] WITHIN 300 SECONDS"},
 {"type":"indicator","pattern_type":"yara","pattern":"rule x { condition: true }"},
 {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.10']","revoked":true},
 {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.11']","valid_until":"2026-01-01T00:00:00Z"},
 {"type":"indicator","pattern":"[ipv4-addr:value = '10.1.2.3']"},
 {"type":"indicator","pattern":"[url:value = 'https://x.example/a\\'b']"},
 {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.13'] AND [domain-name:value = 'both.example']"},
 {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.14' AND domain-name:value = 'and.example']"},
 {"type":"indicator","pattern_type":"snort","pattern":"[ipv4-addr:value = '198.51.100.15']"},
 {"type":"malware","name":"Qakbot"},
 {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.12'"}
]}`

// STIX: the part every feed uses is read, and the rest is counted as not
// read rather than read as something broader.
func TestASTIXBundleIsReadWhereItIsSimpleAndCountedWhereItIsNot(t *testing.T) {
	got, rep, err := ReadSTIX([]byte(bundle), "feed", now)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]Indicator{}
	for _, i := range got {
		values[i.Value] = i
	}
	for _, want := range []string{"203.0.113.9", "evil.example",
		"https://files.example/drop.bin",
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"abcdef0123456789abcdef0123456789", "https://x.example/a'b"} {
		if _, ok := values[want]; !ok {
			t.Errorf("%s was not read (have %v)", want, keys(values))
		}
	}
	// Each of these is a narrower claim than the address inside it.
	for _, never := range []string{"198.51.100.7", "198.51.100.8",
		"later.example", "good.example", "198.51.100.9", "198.51.100.10",
		"198.51.100.11", "198.51.100.12", "10.1.2.3", "198.51.100.13",
		"both.example", "198.51.100.14", "and.example", "198.51.100.15"} {
		if _, ok := values[never]; ok {
			t.Errorf("%s was taken from a pattern that says more than "+
				"\"this value\"", never)
		}
	}
	if rep.Unread != 11 || rep.Lapsed != 2 || rep.Never() != 1 {
		t.Errorf("unread %d, lapsed %d, never %d (%v)", rep.Unread,
			rep.Lapsed, rep.Never(), rep.Refused)
	}
	q := values["203.0.113.9"]
	if q.Note != "Qakbot C2" || q.From.Format("2006-01-02") != "2026-09-01" {
		t.Errorf("%+v", q)
	}
	if _, _, err := ReadSTIX([]byte(`{"type":"report"}`), "feed", now); err == nil {
		t.Error("something that is not a bundle was read as one")
	}
}

func keys(m map[string]Indicator) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestAListIsOneValueToALineAndSaysWhatItRefused(t *testing.T) {
	got, rep, err := ReadList([]byte(`# a feed
203.0.113.9
evil[.]example   # comment after
hxxp://files[.]example/drop.bin,high,2026-09-01
10.0.0.5
192.168.1.20
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
github.io
this is not anything

// another comment
`), "feed", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || rep.Read != 8 || rep.Never() != 5 {
		t.Fatalf("%d taken of %d read, %d refused: %v", len(got), rep.Read,
			rep.Never(), rep.Refused)
	}
	if rep.Refused["a private or local address"] != 2 ||
		rep.Refused["the digest of the empty file"] != 1 ||
		rep.Refused["a domain shared by many unrelated people"] != 1 {
		t.Errorf("reasons: %v", rep.Refused)
	}
	if len(rep.Examples) == 0 {
		t.Error("nothing to check the count against")
	}
}
