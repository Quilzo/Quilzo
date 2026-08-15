package i18n

import "testing"

var site = []Offer{
	{Tag: "en-GB", Default: true},
	{Tag: "de"},
	{Tag: "fr-CA"},
}

func TestTheObviousCases(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   string
	}{
		{"de", "de"},
		{"de-AT", "de"}, // region asked, language offered
		{"en", "en-GB"}, // language asked, region offered
		{"fr", "fr-CA"},
		{"de;q=0.9, en;q=0.8", "de"},
		{"en;q=0.8, de;q=0.9", "de"}, // order does not beat quality
		{"ja, ko", "en-GB"},          // nothing matches, default
		{"", "en-GB"},
		{"*", "en-GB"}, // wildcard takes the site's first choice
	} {
		if got := Negotiate(tc.header, site); got.Tag != tc.want {
			t.Errorf("%q → %q, want %q", tc.header, got.Tag, tc.want)
		}
	}
}

// q=0 means refused, not "least preferred". A client sending `de, en;q=0` will
// take German and will not take English, and treating that as a weak
// preference serves exactly what was refused.
func TestQualityZeroIsARefusal(t *testing.T) {
	got := Negotiate("de, en;q=0", site)
	if got.Tag != "de" {
		t.Errorf("got %q, want de", got.Tag)
	}
	// And when the only match is refused, the default is used rather than the
	// refused language.
	got = Negotiate("en-GB;q=0, en;q=0", site)
	if got.Tag == "en-GB" {
		t.Error("a refused language was served anyway")
	}
}

// A caller must be able to tell "you asked for this" from "we had nothing you
// wanted", because the second is worth reporting and the first is not.
func TestAFallbackSaysItIsOne(t *testing.T) {
	if m := Negotiate("de", site); m.Fallback {
		t.Error("an exact match reported itself as a fallback")
	}
	if m := Negotiate("ja", site); !m.Fallback {
		t.Error("serving the default after no match did not report a fallback")
	}
	if m := Negotiate("de", site); !m.Exact {
		t.Error("de is an exact match and did not say so")
	}
	if m := Negotiate("de-AT", site); m.Exact {
		t.Error("de-AT matched de and claimed to be exact")
	}
}

// An exact match beats a prefix match at the same quality, or asking for a
// specific region gets you a different one for no reason.
func TestAnExactMatchWinsAtEqualQuality(t *testing.T) {
	offers := []Offer{{Tag: "en", Default: true}, {Tag: "en-GB"}}
	if got := Negotiate("en-GB", offers); got.Tag != "en-GB" {
		t.Errorf("got %q, want the exact en-GB", got.Tag)
	}
}

// Ties go to the site's order, not the client's, so the outcome is stable and
// an operator controls it.
func TestTiesGoToTheSitesOrdering(t *testing.T) {
	first := Negotiate("de;q=0.5, fr;q=0.5", site).Tag
	for i := 0; i < 50; i++ {
		if got := Negotiate("de;q=0.5, fr;q=0.5", site).Tag; got != first {
			t.Fatalf("run %d gave %q, first gave %q", i, got, first)
		}
	}
	if first != "de" {
		t.Errorf("the tie went to %q; de is listed first on the site", first)
	}
}

// The header is attacker-controlled.
func TestAHostileHeaderIsBounded(t *testing.T) {
	var long string
	for i := 0; i < 5000; i++ {
		long += "xx-YY;q=0.5,"
	}
	if got := Negotiate(long+"de", site); got.Tag == "" {
		t.Error("a long header produced no answer at all")
	}
	for _, h := range []string{
		";;;;", "de;q=", "de;q=notanumber", "de;q=99", "de;q=-5",
		string(make([]byte, 100)), "\x00\x00", ",,,,,,",
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%q panicked: %v", h, r)
				}
			}()
			Negotiate(h, site)
		}()
	}
}

// -- caching ------------------------------------------------------------------

// Keying on the raw header would shatter the cache: browsers send dozens of
// distinct Accept-Language strings that all resolve to the same language.
func TestTheCacheKeyIsTheResolvedLanguage(t *testing.T) {
	headers := []string{
		"de", "de-DE", "de-AT,de;q=0.9", "de;q=1.0,en;q=0.5",
		"de-CH,de;q=0.9,en-US;q=0.8,en;q=0.7",
	}
	first := Negotiate(headers[0], site).CacheKey()
	for _, h := range headers[1:] {
		if got := Negotiate(h, site).CacheKey(); got != first {
			t.Errorf("%q keys as %q, but %q keys as %q — the cache would hold "+
				"a separate entry for every browser's phrasing",
				h, got, headers[0], first)
		}
	}
}

func TestNoOffersIsNotACrash(t *testing.T) {
	if got := Negotiate("de", nil); got.Tag != "" || !got.Fallback {
		t.Errorf("got %+v", got)
	}
}
