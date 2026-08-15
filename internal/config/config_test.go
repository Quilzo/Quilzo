package config

import (
	"strings"
	"testing"
	"time"
)

var when = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func fresh() *Config {
	return New().WithClock(func() time.Time { return when })
}

// -- the whole point ----------------------------------------------------------

// "Highly customizable, but do not undermine security" is a contradiction only
// where a customer's legitimate need is also what an attacker would ask for.
// The resolution is that nothing is forbidden and nothing is quiet: a weaker
// value needs a reason, and that reason is recorded and reported.
func TestAWeakerValueIsAllowedButNeedsAReason(t *testing.T) {
	c := fresh()
	err := c.Set("auth.throttle", "false", "", "dana")
	if err == nil {
		t.Fatal("throttling was switched off with no reason given")
	}
	var need *ErrNeedsAcceptance
	if !as(err, &need) {
		t.Fatalf("refused with %T, want *ErrNeedsAcceptance: %v", err, err)
	}
	if !strings.Contains(err.Error(), "unlimited") {
		t.Errorf("the refusal does not say what is given up: %v", err)
	}

	// With a reason, it is simply allowed. This is the half people expect to
	// be missing.
	if err := c.Set("auth.throttle", "false", "load test, staging only",
		"dana"); err != nil {
		t.Fatalf("a reasoned change was still refused: %v", err)
	}
	if c.Bool("auth.throttle") {
		t.Error("the setting did not take effect")
	}
}

// And it is reported for as long as it stands, which is what stops an accepted
// risk from becoming a forgotten one.
func TestAnAcceptedRiskIsReportedUntilItIsFixed(t *testing.T) {
	c := fresh()
	if err := c.Set("token.ttl.default", "20000h", "migration from the old "+
		"CMS runs until March", "dana"); err != nil {
		t.Fatal(err)
	}
	w := c.Weakened()
	if len(w) != 1 {
		t.Fatalf("%d weakened settings reported, want 1", len(w))
	}
	if w[0].Accepted == nil {
		t.Fatal("the acceptance was not recorded")
	}
	if w[0].Accepted.Reason == "" || w[0].Accepted.By != "dana" {
		t.Errorf("the record does not say who or why: %+v", w[0].Accepted)
	}

	// Putting it back removes the finding, rather than leaving a stale
	// acceptance attached to a setting that is now fine.
	if err := c.Set("token.ttl.default", "720h", "", "dana"); err != nil {
		t.Fatal(err)
	}
	if len(c.Weakened()) != 0 {
		t.Error("the finding survived the setting being put back")
	}
}

// An acceptance expires, because a decision nobody revisits stops being a
// decision. The reason it was made is usually true for a quarter and rarely
// true for a year.
func TestAnAcceptanceExpires(t *testing.T) {
	now := when
	c := New().WithClock(func() time.Time { return now })
	if err := c.Set("auth.throttle", "false", "staging", "dana"); err != nil {
		t.Fatal(err)
	}
	if c.Weakened()[0].Expired {
		t.Fatal("expired immediately")
	}
	now = now.Add(MaxAcceptance + time.Hour)
	if !c.Weakened()[0].Expired {
		t.Error("an acceptance from 90 days ago is still current")
	}
}

// A value weakened by editing the file directly appears with no acceptance,
// and that is the case worth showing loudest: the difference between a
// decision and an accident is whether somebody wrote down why.
func TestAWeakValueWithNoAcceptanceIsStillReported(t *testing.T) {
	c, err := Parse([]byte(`{"values":{"auth.throttle":"false"}}`))
	if err != nil {
		t.Fatal(err)
	}
	w := c.Weakened()
	if len(w) != 1 {
		t.Fatalf("%d weakened settings, want 1", len(w))
	}
	if w[0].Accepted != nil {
		t.Error("an acceptance appeared from nowhere")
	}
}

// Most settings have no security dimension and must not ask for a
// justification. Requiring a reason to change a page size trains people to
// type anything into the box that also guards the settings that matter.
func TestOrdinarySettingsChangeWithoutCeremony(t *testing.T) {
	c := fresh()
	for _, tc := range [][2]string{
		{"api.rate.burst", "40"},
		{"review.required_approvals", "2"},
		{"site.csp.extra_img", "cdn.example.com"},
		{"auth.throttle.after", "3"},  // stricter, not weaker
		{"token.ttl.default", "168h"}, // shorter, not weaker
	} {
		if err := c.Set(tc[0], tc[1], "", "dana"); err != nil {
			t.Errorf("%s = %s needed a reason: %v", tc[0], tc[1], err)
		}
	}
	if n := len(c.Weakened()); n != 0 {
		t.Errorf("%d of those were treated as weakening", n)
	}
}

// -- validation ---------------------------------------------------------------

func TestAValueThatDoesNotParseIsRefused(t *testing.T) {
	c := fresh()
	for _, tc := range [][2]string{
		{"auth.throttle.after", "lots"},
		{"auth.throttle.base", "1 second"},
		{"auth.throttle", "yes please"},
		{"site.csp.mode", "maybe"},
		{"api.page.max", "-1"},
	} {
		if err := c.Set(tc[0], tc[1], "reason", "dana"); err == nil {
			t.Errorf("%s = %q was accepted", tc[0], tc[1])
		}
	}
}

// A stored configuration naming a setting this version does not have is
// refused at load, not at first use. Discovering it mid-request means
// discovering it in front of a customer.
func TestAnUnknownSettingIsRefusedAtLoad(t *testing.T) {
	if _, err := Parse([]byte(`{"values":{"auth.thottle":"false"}}`)); err == nil {
		t.Error("a misspelled setting loaded silently, and would have had no " +
			"effect while looking as though it did")
	}
}

func TestAStoredValueThatDoesNotParseIsRefusedAtLoad(t *testing.T) {
	if _, err := Parse([]byte(`{"values":{"api.page.max":"loads"}}`)); err == nil {
		t.Error("a configuration with an unparseable value loaded")
	}
}

// -- the table itself ---------------------------------------------------------

// Every setting has to be explicable, because `config explain` prints this and
// a knob nobody can explain is a knob nobody should turn.
func TestEverySettingExplainsItself(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range All() {
		if seen[s.Key] {
			t.Errorf("%s is declared twice", s.Key)
		}
		seen[s.Key] = true

		if !strings.Contains(s.Key, ".") {
			t.Errorf("%s is not namespaced", s.Key)
		}
		if len(s.Summary) < 8 {
			t.Errorf("%s has no summary", s.Key)
		}
		if len(s.Why) < 40 {
			t.Errorf("%s does not explain itself; `config explain %s` would "+
				"print nothing worth reading", s.Key, s.Key)
		}
		if err := s.Validate(s.Default); err != nil {
			t.Errorf("%s has a default that does not validate: %v", s.Key, err)
		}
		if weak, why := s.IsWeaker(s.Default); weak {
			t.Errorf("%s ships weaker than itself: %s", s.Key, why)
		}
	}
}

// The defaults are the product's security posture, so they are asserted by
// value rather than left to whatever the table happens to say. Changing one
// should require changing this test, deliberately.
func TestTheDefaultsAreTheOnesWeMeanToShip(t *testing.T) {
	c := New()
	for _, tc := range []struct {
		key  string
		want string
	}{
		{"auth.throttle", "true"},
		{"auth.throttle.after", "5"},     // ASVS 5.0 alerting threshold
		{"auth.throttle.ceiling", "100"}, // ASVS 5.0 hourly ceiling
		{"auth.lockout.hard", "false"},   // soft, so it cannot be aimed at a victim
		{"publish.require_a11y", "true"},
		{"publish.require_types", "true"},
		{"site.csp.mode", "enforce"},
		{"ext.enabled", "false"},
		{"ext.require_pinned", "true"},
	} {
		if got := c.Raw(tc.key); got != tc.want {
			t.Errorf("%s defaults to %q, want %q", tc.key, got, tc.want)
		}
	}
}

// A round trip has to preserve both the values and the reasons, or an
// acceptance is lost on the next write and the finding reappears with nobody
// able to say why it was accepted.
func TestAConfigurationSurvivesARoundTrip(t *testing.T) {
	c := fresh()
	c.Set("api.rate.burst", "40", "", "dana")
	c.Set("auth.throttle.ceiling", "500", "penetration test window", "sam")

	body, err := c.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if back.Int("api.rate.burst") != 40 {
		t.Error("a plain value did not survive")
	}
	if back.Int("auth.throttle.ceiling") != 500 {
		t.Error("a weakened value did not survive")
	}
	w := back.Weakened()
	if len(w) != 1 || w[0].Accepted == nil ||
		w[0].Accepted.Reason != "penetration test window" {
		t.Errorf("the acceptance did not survive: %+v", w)
	}
}

func as(err error, target **ErrNeedsAcceptance) bool {
	e, ok := err.(*ErrNeedsAcceptance)
	if ok {
		*target = e
	}
	return ok
}
