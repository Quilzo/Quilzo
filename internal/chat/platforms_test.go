package chat

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// Two platforms sharing a name is one platform, and the way it happens is a
// copy-paste.
//
//	Telegram Platform = "telegram"
//	Slack    Platform = "slack"
//	Discord  Platform = "slack"   // <- added by duplicating the line above
//
// Every credential check still passes: the constants are distinct identifiers,
// so the compiler is content, and each platform verifies its own credentials
// correctly. What breaks is that Discord and Slack now derive the same signing
// key and produce colliding handles — a cross-platform replay and a shared set
// of pages, from a line that looks right.
//
// The declared list is read out of the source rather than restated here,
// because a list maintained by hand is the thing that goes stale and this test
// exists to catch exactly that kind of drift.
func TestNoTwoPlatformsShareAName(t *testing.T) {
	src, err := os.ReadFile("chat.go")
	if err != nil {
		t.Fatal(err)
	}

	declared := regexp.MustCompile(`(?m)^\s*(\w+)\s+Platform\s*=\s*"([^"]*)"`).
		FindAllStringSubmatch(string(src), -1)
	if len(declared) < 2 {
		t.Fatalf("found %d platform constants in the source; the pattern is "+
			"matching almost nothing and this test would pass by checking "+
			"nothing", len(declared))
	}

	byValue := map[string]string{}
	for _, d := range declared {
		name, value := d[1], d[2]
		if first, clash := byValue[value]; clash {
			t.Errorf("%s and %s are both %q. They would derive the same "+
				"signing key and collide in handles, so they are one platform "+
				"wearing two names.", first, name, value)
		}
		byValue[value] = name

		// And every declared name has to satisfy the rules, or a credential
		// minted for it is unverifiable and a handle built from it is
		// ambiguous.
		if !Platform(value).Valid() {
			t.Errorf("%s is %q, which Platform.Valid refuses", name, value)
		}
	}
	t.Logf("%d platform(s) declared, all distinct and valid", len(declared))
}

// The rule that makes a handle unambiguous, checked against the failure it
// prevents rather than by restating itself.
//
// A platform name ending in a digit lets the boundary between the name and the
// id fall in two places, so two different accounts produce one handle — and a
// handle is what content is stored under.
func TestNoTwoAccountsCanShareAHandle(t *testing.T) {
	// The exact collision that motivated the rule.
	a := Account{Platform: "tele", ID: 4212}
	b := Account{Platform: "tele4", ID: 212}
	if !a.Platform.Valid() {
		t.Fatalf("%q was refused, and it is a legitimate name", a.Platform)
	}
	if b.Platform.Valid() {
		t.Fatalf("%q ends in a digit and was accepted; it collides with "+
			"%q + %d, both giving %q",
			b.Platform, a.Platform, a.ID, a.Handle())
	}

	// And a sweep, so the property is checked rather than the one example.
	// Every valid platform name paired with a range of ids must give a handle
	// nothing else gives.
	names := []Platform{"telegram", "slack", "discord", "matrix", "web3chat"}
	seen := map[string]string{}
	checked := 0
	for _, p := range names {
		if !p.Valid() {
			t.Errorf("%q was refused and should not have been", p)
			continue
		}
		for id := int64(1); id <= 2000; id++ {
			h := Account{Platform: p, ID: id}.Handle()
			key := fmt.Sprintf("%s/%d", p, id)
			if other, clash := seen[h]; clash {
				t.Fatalf("handle %q is produced by both %s and %s", h, other, key)
			}
			seen[h] = key
			checked++
		}
	}
	// Count what was examined: an empty sweep finds no collisions and looks
	// exactly like a pass.
	if checked != len(names)*2000 {
		t.Fatalf("checked %d handles, expected %d", checked, len(names)*2000)
	}
	t.Logf("%d handles checked across %d platforms, no collision",
		checked, len(names))
}

// A trailing digit is refused wherever it appears in the name, not only at the
// end of a word.
func TestATrailingDigitIsRefusedAnywhereItEndsTheName(t *testing.T) {
	for _, bad := range []string{"tele4", "x1", "9", "chat2026", "a0"} {
		if Platform(bad).Valid() {
			t.Errorf("%q ends in a digit and was accepted", bad)
		}
	}
	// Digits inside a name are fine: the split is still the trailing run.
	for _, good := range []string{"web3chat", "s3rvice", "matrix"} {
		if !Platform(good).Valid() {
			t.Errorf("%q was refused; only a trailing digit is ambiguous", good)
		}
		h := Account{Platform: Platform(good), ID: 42}.Handle()
		if want := good + strconv.FormatInt(42, 10); h != want {
			t.Errorf("handle for %q is %q, want %q", good, h, want)
		}
	}
}
