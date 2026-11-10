// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// A crawl term is checked when it is set, not when the server starts.
//
// `quilzo config set licence.permits ai-training-with-attribution` used to
// report success, write the value, and leave a site whose public server refused
// to start — the vocabulary was enforced at boot and nowhere else. A command
// that says it worked and produces a server that will not run is worse than a
// refusal, which is the same reasoning that put the brand-colour check here.
func TestALicenceTermIsRefusedWhereItIsSet(t *testing.T) {
	for _, key := range []string{"licence.permits", "licence.prohibits"} {
		s, ok := Lookup(key)
		if !ok {
			t.Fatalf("%s is not a setting", key)
		}
		if err := s.Validate("ai-training-with-attribution"); err == nil {
			t.Errorf("%s accepted a use outside the vocabulary; the public "+
				"server will refuse to start on this value", key)
		}
		for _, good := range []string{"search", "search,train", "none",
			"search, ai-summarize", ""} {
			if err := s.Validate(good); err != nil {
				t.Errorf("%s refused %q, which is in the vocabulary: %v",
					key, good, err)
			}
		}
	}
}

// A security contact is a URI, checked when it is set. A bare address was
// accepted, published as a security.txt Contact line nothing can use, and
// skipped by the automations that mail the security team.
func TestASecurityContactIsAURI(t *testing.T) {
	s, ok := Lookup("security.contact")
	if !ok {
		t.Fatal("security.contact is not a setting")
	}
	for _, bad := range []string{"security@example.com", "mailto:",
		"mailto:sec@example.com, sec2@example.com", "ftp://example.com",
		"javascript:alert(1)"} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%q was accepted as a security contact", bad)
		}
	}
	for _, good := range []string{"", "mailto:security@example.com",
		"MAILTO:security@example.com", "https://example.com/report",
		"mailto:a@example.com, https://example.com/report, tel:+44-20-7946-0000"} {
		if err := s.Validate(good); err != nil {
			t.Errorf("%q was refused: %v", good, err)
		}
	}
}

// The origin trial token is sent as a response header, so nothing but a
// token's own characters may be set: a line break would start a header of
// whoever set it's choosing.
func TestAnOriginTrialTokenCannotCarryAHeader(t *testing.T) {
	s, ok := Lookup("site.webmcp_trial")
	if !ok {
		t.Fatal("site.webmcp_trial is not a setting")
	}
	for _, bad := range []string{"abc\r\nSet-Cookie: x=1", "abc def", "abc;", strings.Repeat("a", 2049)} {
		if err := s.Validate(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if err := s.Validate("AqZ1abcDEF+/="); err != nil {
		t.Errorf("a token was refused: %v", err)
	}
}

// How often the access Quilzo grants is reviewed: between thirty days and
// a year whatever the reason, and longer than ninety only with one, since
// a longer wait is a grant nobody needs working for longer.
func TestTheAccessReviewPeriodIsBoundedAndLongerIsWeaker(t *testing.T) {
	c := fresh()
	if got := c.Dur("access.review.every").Hours() / 24; got != 90 {
		t.Fatalf("the default is %v days", got)
	}
	if err := c.Set("access.review.every", "720h", "", "dana"); err != nil {
		t.Errorf("thirty days, which is stricter, was refused: %v", err)
	}
	if err := c.Set("access.review.every", "4380h", "", "dana"); err == nil {
		t.Error("half a year was set with no reason")
	}
	if err := c.Set("access.review.every", "4380h", "an annual audit cycle", "dana"); err != nil {
		t.Errorf("half a year with a reason: %v", err)
	}
	for _, v := range []string{"480h", "9000h"} {
		if err := c.Set("access.review.every", v, "a reason", "dana"); err == nil {
			t.Errorf("%s is outside thirty days to a year and was accepted", v)
		}
	}
}

// A duration setting takes days and weeks as well as Go's durations, and
// says a duration back in the largest whole unit it is.
//
// `quilzo config set access.review.every 90d` was refused as "not a
// duration", on a setting whose own explanation says ninety days, so an
// operator had to know that ninety days is 2160h. The message about a
// weaker value then said "every 2400h0m0s", which is time.Duration's
// String and nobody's way of writing a hundred days.
func TestADurationSettingTakesDaysAndSaysThemBack(t *testing.T) {
	const day = 24 * time.Hour
	c := fresh()
	for v, want := range map[string]time.Duration{"60d": 60 * day, "8w": 56 * day, "720h": 30 * day, "1080h30m": 45*day + 30*time.Minute} {
		if err := c.Set("access.review.every", v, "", "dana"); err != nil {
			t.Fatalf("%s was refused: %v", v, err)
		}
		if got := c.Dur("access.review.every"); got != want {
			t.Errorf("%s reads as %v, want %v", v, got, want)
		}
	}

	var need *ErrNeedsAcceptance
	if err := c.Set("access.review.every", "100d", "", "dana"); !as(err, &need) {
		t.Fatalf("a hundred days with no reason: %v", err)
	}
	if !strings.Contains(need.Why, "every 100d ") || strings.Contains(need.Why, "0m0s") {
		t.Errorf("the weaker value is not said as written: %q", need.Why)
	}
	err := c.Set("access.review.every", "400d", "a reason", "dana")
	if err == nil || !strings.Contains(err.Error(), "400d is outside its bounds, 30d to 365d") {
		t.Errorf("the bounds are not said in days: %v", err)
	}

	// The default written another way is the default, not a change to it.
	if err := c.Set("access.review.every", "90d", "", "dana"); err != nil {
		t.Fatal(err)
	}
	if !c.IsDefault("access.review.every") {
		t.Error("ninety days, which is the default, was stored as a change from it")
	}

	for _, bad := range []string{"1.5d", "-3d", "d", "3 d", "30days", "99999999999d", "3x"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("%q parsed as a duration", bad)
		}
	}
	for d, want := range map[time.Duration]string{
		100 * day: "100d", 7 * day: "7d", 36 * time.Hour: "36h", 90 * time.Minute: "90m",
		5 * time.Second: "5s", 0: "0s", 1500 * time.Millisecond: "1.5s",
		time.Hour + 30*time.Minute + 15*time.Second: "1h30m15s",
	} {
		if got := FormatDuration(d); got != want {
			t.Errorf("%v is said as %q, want %q", d, got, want)
		}
		if back, err := ParseDuration(FormatDuration(d)); err != nil || back != d {
			t.Errorf("%q does not read back as %v: %v %v", FormatDuration(d), d, back, err)
		}
	}

	// And on the Settings screen and in `config show`, through Effective.
	if err := c.Set("access.review.every", "1440h", "", "dana"); err != nil {
		t.Fatal(err)
	}
	for _, e := range c.Effectives() {
		if e.Setting.Key == "access.review.every" {
			if e.Shown() != "60d" || e.Setting.DefaultShown() != "90d" {
				t.Errorf("shown as %q, default %q", e.Shown(), e.Setting.DefaultShown())
			}
			if e.Value != "1440h" {
				t.Errorf("the value as stored changed to %q", e.Value)
			}
		}
		if e.Setting.Key == "publish.require_a11y" && e.Shown() != "true" {
			t.Errorf("a setting that is not a duration is shown as %q", e.Shown())
		}
	}
}

// Every number that limits how much may be asked for has a ceiling no
// reason passes, or a point past which raising it takes a reason and a
// second administrator, so raising it far is never quiet.
//
// api.rate.burst had neither: `quilzo config set api.rate.burst 1000000`
// was accepted at once, nobody was asked why, and the posture scan stayed
// silent while each token could send a million requests before the rate
// applied. A number setting added later with neither fails here, unless it
// is listed below with the reason it needs none.
func TestEveryLimitThatCanBeRaisedHasABoundOrAWeakerRule(t *testing.T) {
	exempt := map[string]string{
		"review.required_approvals": "how many people approve a draft: more is stricter, and fewer waits for a second administrator (internal/dual)",
		"media.max_width":           "page weight, not a limit on anybody asking: 0 keeps the original, and media.MaxPixels bounds what an upload decodes",
		"media.max_height":          "the other side of media.max_width, for the same reason",
	}
	for _, s := range All() {
		if s.Kind != Int {
			continue
		}
		b, bounded := hardBounds[s.Key]
		capped := bounded && b[1] != unbounded
		why, isExempt := exempt[s.Key]
		switch {
		case isExempt && (capped || s.Weaker != nil):
			t.Errorf("%s is exempt (%s) and has a ceiling or a weaker rule as well; take it off the list", s.Key, why)
		case isExempt:
		case !capped && s.Weaker == nil:
			t.Errorf("%s can be raised as far as anybody likes and nobody is asked why: give it a "+
				"hard bound or a Weaker rule, or exempt it here with the reason", s.Key)
		case !capped:
			// A rule that never fires for a large value is not a rule about
			// raising it.
			if weak, _ := s.IsWeaker("1000000000"); !weak {
				t.Errorf("%s has a weaker rule that a billion does not trip", s.Key)
			}
		}
	}
	for key, why := range exempt {
		if s, ok := Lookup(key); !ok || s.Kind != Int || why == "" {
			t.Errorf("%s is exempt and is not a number setting, or says no reason", key)
		}
	}
}

// The API's burst: up to ten times its default as anybody likes, past
// that with a reason (and so a second administrator), and never past
// 6000, a whole minute at the most api.rate.per_minute takes without one.
func TestTheAPIBurstHasABoundAndALargeOneIsWeaker(t *testing.T) {
	s, _ := Lookup("api.rate.burst")
	if weak, why := s.IsWeaker("200"); weak {
		t.Errorf("a burst of 200, ten times the default, is weaker: %s", why)
	}
	if weak, why := s.IsWeaker("201"); !weak || !strings.Contains(why, "201") {
		t.Errorf("a burst of 201 is not weaker, or the reason does not say it: %v %q", weak, why)
	}

	c := fresh()
	var out *ErrOutOfBounds
	if err := c.Set("api.rate.burst", "1000000", "a load test", "dana"); !errors.As(err, &out) {
		t.Fatalf("a burst of a million, with a reason: %v", err)
	}
	var need *ErrNeedsAcceptance
	if err := c.Set("api.rate.burst", "500", "", "dana"); !as(err, &need) {
		t.Fatalf("a burst of 500 was set with no reason: %v", err)
	}
	if err := c.Set("api.rate.burst", "500", "a site build fetching in parallel", "dana"); err != nil {
		t.Fatal(err)
	}
	if w := c.Weakened(); len(w) != 1 || w[0].Setting.Key != "api.rate.burst" || w[0].Accepted == nil {
		t.Errorf("the posture scan is not told about a burst of 500: %+v", w)
	}
	if err := c.Set("api.rate.burst", "6000", "the same build", "dana"); err != nil {
		t.Errorf("6000, the bound, was refused: %v", err)
	}
	if err := c.Set("api.rate.burst", "6001", "the same build", "dana"); !errors.As(err, &out) {
		t.Errorf("6001, past the bound: %v", err)
	}
}

// A limit of zero is refused, with the least it takes, rather than taken
// and read as the default.
//
// `quilzo config set api.rate.per_minute 0`, meant as "off", was accepted,
// and the API went on allowing 120 a minute because it reads zero as unset.
// The burst, the page size, the body size, the browsers and an extension's
// output were the same, and a JPEG quality of 0 or 500 was 82. A file
// written before this still loads: the zero is left out and said, and the
// default it ran at anyway is what it runs at.
func TestALimitOfZeroIsRefusedRatherThanReadAsTheDefault(t *testing.T) {
	c := fresh()
	var out *ErrOutOfBounds
	err := c.Set("api.rate.per_minute", "0", "turn it off", "dana")
	if !errors.As(err, &out) || !strings.Contains(err.Error(), "0 is below 1, the least this takes") {
		t.Fatalf("a rate of zero: %v", err)
	}
	for _, key := range []string{"api.rate.burst", "api.page.max", "api.body.max_bytes",
		"browser.sessions", "ext.max_output_bytes", "media.jpeg_quality"} {
		if err := c.Set(key, "0", "a reason", "dana"); !errors.As(err, &out) {
			t.Errorf("%s = 0: %v", key, err)
		}
		if err := c.Set(key, "1", "", "dana"); err != nil {
			t.Errorf("%s = 1, which is stricter, was refused: %v", key, err)
		}
	}
	if err := c.Set("media.jpeg_quality", "101", "", "dana"); !errors.As(err, &out) {
		t.Errorf("a JPEG quality of 101: %v", err)
	}
	if err := c.Set("media.max_width", "0", "", "dana"); err != nil {
		t.Errorf("a width of 0, which keeps the original, was refused: %v", err)
	}

	old, err := Parse([]byte(`{"values":{"api.rate.per_minute":"0","api.rate.burst":"0"}}`))
	if err != nil {
		t.Fatalf("a file with a zero rate did not load: %v", err)
	}
	if old.Int("api.rate.per_minute") != 120 || old.Int("api.rate.burst") != 20 {
		t.Errorf("read as %d a minute, burst %d", old.Int("api.rate.per_minute"), old.Int("api.rate.burst"))
	}
	if got := strings.Join(old.Dropped(), "\n"); !strings.Contains(got,
		"api.rate.per_minute: 0 is below 1, the least this takes; 120 is used instead") {
		t.Errorf("the zero was not said: %q", got)
	}
}
