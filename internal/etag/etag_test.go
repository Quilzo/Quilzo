// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package etag

import "testing"

func TestOneTagMatchesItself(t *testing.T) {
	if !Matches(`"abc"`, `"abc"`) {
		t.Fatal("a tag did not match itself")
	}
}

// The failure this package exists for: a client holding both a compressed and
// an uncompressed copy of a URL sends both validators.
func TestASecondValidatorStillMatches(t *testing.T) {
	header := `"abc-gzip", "abc"`
	if !Matches(header, `"abc"`) {
		t.Fatalf("the client held the tag and was sent the body again: %s", header)
	}
	if !Matches(header, `"abc-gzip"`) {
		t.Fatalf("the client held the tag and was sent the body again: %s", header)
	}
}

func TestSpacingDoesNotDecideIt(t *testing.T) {
	for _, header := range []string{`"a","b"`, `"a", "b"`, ` "a" ,  "b" `} {
		if !Matches(header, `"b"`) {
			t.Errorf("did not match in %q", header)
		}
	}
}

func TestStarMatchesAnything(t *testing.T) {
	if !Matches("*", `"abc"`) {
		t.Fatal("* did not match")
	}
	if !Matches(" * ", `"abc"`) {
		t.Fatal("* did not match when padded")
	}
}

// A star is a token, not a tag. A client asking about a resource whose tag is
// literally the three characters `"*"` is not asking about any representation.
func TestAQuotedStarIsNotTheToken(t *testing.T) {
	if Matches(`"*"`, `"abc"`) {
		t.Fatal("a quoted star matched an unrelated tag")
	}
}

func TestAWeakTagIsGoodEnoughForACache(t *testing.T) {
	if !Matches(`W/"abc"`, `"abc"`) {
		t.Fatal("a proxy weakened the tag and the cache stopped working")
	}
}

func TestNoHeaderIsNoMatch(t *testing.T) {
	if Matches("", `"abc"`) {
		t.Fatal("an absent header matched")
	}
	if Matches("   ", `"abc"`) {
		t.Fatal("a blank header matched")
	}
}

// Otherwise a resource with no validator answers 304 to any conditional
// request, and the client caches nothing forever.
func TestNoTagIsNoMatch(t *testing.T) {
	for _, tag := range []string{"", `""`, `W/""`} {
		if Matches(`""`, tag) {
			t.Errorf("an empty tag matched, tag=%q", tag)
		}
	}
}

func TestQuotingIsNotRequiredOfTheCaller(t *testing.T) {
	if !Matches(`"abc"`, "abc") {
		t.Fatal("an unquoted content hash did not match its own header")
	}
}

// The prefix is not the tag. This is the mistake a strings.HasPrefix version
// of this function makes.
func TestAPrefixIsNotAMatch(t *testing.T) {
	if Matches(`"abcdef"`, `"abc"`) {
		t.Fatal("a longer tag matched a shorter one")
	}
}
