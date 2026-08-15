package csp

import (
	"strings"
	"testing"
)

func pages() map[string]any {
	return map[string]any{
		"index": map[string]any{
			"title": "Home",
			"hero":  "https://cdn.example.com/hero.jpg",
			"video": "https://www.youtube.com/watch?v=abc123",
			"body":  "Some prose with no URLs in it at all.",
		},
		"about": map[string]any{
			"title":   "About",
			"photo":   "https://images.example.net/team.png",
			"podcast": "https://media.example.org/ep1.mp3",
			"tags":    []any{"a", "b"},
		},
	}
}

// The whole point: a policy naming the hosts in use, instead of `img-src
// https:` — which permits every host that speaks TLS and is what a
// hand-written policy decays into.
func TestThePolicyNamesTheHostsTheContentActuallyUses(t *testing.T) {
	p := Policy{Mode: Enforce, Sources: Collect(pages())}
	h := p.Build()

	for _, want := range []string{
		"img-src 'self' data: cdn.example.com images.example.net",
		"media-src 'self' media.example.org",
		"frame-src www.youtube-nocookie.com",
		"script-src 'none'",
		"default-src 'none'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("the policy does not contain %q\n  got: %s", want, h)
		}
	}
	// And it must not contain the thing it exists to replace.
	if strings.Contains(h, " https:") {
		t.Errorf("the generated policy still carries a schemeless wildcard: %s", h)
	}
}

// A YouTube URL has to become the host the iframe is actually served from. A
// policy naming youtube.com does not permit the embed, and the failure looks
// like the policy is broken rather than like the host is wrong.
func TestAnEmbedIsRewrittenToTheHostItIsServedFrom(t *testing.T) {
	for _, raw := range []string{
		"https://www.youtube.com/watch?v=x",
		"https://youtu.be/x",
		"https://youtube.com/embed/x",
	} {
		s := Collect(map[string]any{"p": map[string]any{"v": raw}})
		if len(s.Frame) != 1 || s.Frame[0] != "www.youtube-nocookie.com" {
			t.Errorf("%s produced frame-src %v", raw, s.Frame)
		}
		if len(s.Img) != 0 {
			t.Errorf("%s also landed in img-src: %v", raw, s.Img)
		}
	}
}

// Being wrong about an image is a broken picture. Being wrong about a frame
// permits somebody else's page inside yours, so anything not on the short
// embed list is an image rather than a guess.
func TestAnUnknownVideoLookingURLIsNotTreatedAsAnEmbed(t *testing.T) {
	s := Collect(map[string]any{"p": map[string]any{
		"v": "https://videos.attacker.example/embed/player?x=1",
	}})
	if len(s.Frame) != 0 {
		t.Errorf("an unknown host was permitted in frame-src: %v", s.Frame)
	}
	if len(s.Img) != 1 {
		t.Errorf("it should have been treated as an image: %v", s)
	}
}

// A site with no external references gets a policy that permits nothing
// external, which is the one most sites should have and almost none do.
func TestASiteWithNoExternalReferencesGetsATightPolicy(t *testing.T) {
	p := Policy{Mode: Enforce, Sources: Collect(map[string]any{
		"index": map[string]any{"title": "Home", "body": "Words."},
	})}
	h := p.Build()
	for _, want := range []string{
		"img-src 'self' data:", "media-src 'self'", "frame-src 'none'",
		"script-src 'none'",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("want %q in: %s", want, h)
		}
	}
}

// Relative URLs and prose are not hosts.
func TestOnlyAbsoluteURLsAreCollected(t *testing.T) {
	s := Collect(map[string]any{"p": map[string]any{
		"a": "/local/image.png",
		"b": "just some words, https is a protocol",
		"c": "mailto:someone@example.com",
		"d": "data:image/png;base64,AAAA",
		"e": "",
	}})
	if len(s.Img)+len(s.Media)+len(s.Frame) != 0 {
		t.Errorf("collected hosts from nothing: %+v", s)
	}
}

// A nonce policy carries strict-dynamic, which is what makes it survive
// contact with a page that loads scripts from scripts.
func TestANoncePolicyUsesStrictDynamic(t *testing.T) {
	h := Policy{Mode: Enforce, Nonce: "abc123"}.Build()
	if !strings.Contains(h, "script-src 'nonce-abc123' 'strict-dynamic'") {
		t.Errorf("the nonce policy is wrong: %s", h)
	}
}

// -- what the posture scan looks for -----------------------------------------

// The schemeless wildcard is invisible unless something says so: the page
// renders perfectly with `img-src https:`, which is why every hand-written
// policy ends up with one.
func TestAWildcardIsReported(t *testing.T) {
	found := Widened("default-src 'none'; img-src 'self' https:; script-src 'self'")
	if len(found) != 1 {
		t.Fatalf("%d findings, want 1: %v", len(found), found)
	}
	if !strings.Contains(found[0], "img-src") {
		t.Errorf("the finding does not name the directive: %s", found[0])
	}
}

func TestUnsafeInlineInScriptSrcIsReported(t *testing.T) {
	found := Widened("script-src 'self' 'unsafe-inline'")
	if len(found) == 0 {
		t.Fatal("script-src 'unsafe-inline' was not reported, and it defeats " +
			"the directive entirely")
	}
}

// And a style-src carrying it is not reported, because the generated policy
// has one and a scanner that flags its own output is a scanner people switch
// off. Stated as a test so the asymmetry is deliberate rather than forgotten.
func TestUnsafeInlineInStyleSrcIsNotReported(t *testing.T) {
	if found := Widened("style-src 'self' 'unsafe-inline'"); len(found) != 0 {
		t.Errorf("style-src 'unsafe-inline' was reported: %v", found)
	}
}

// A generated policy must pass its own check, or the tool ships something it
// would tell a customer to fix.
func TestTheGeneratedPolicyPassesItsOwnCheck(t *testing.T) {
	h := Policy{Mode: Enforce, Sources: Collect(pages())}.Build()
	if found := Widened(h); len(found) != 0 {
		t.Errorf("the generated policy is flagged by the generator's own "+
			"check: %v", found)
	}
}

// -- modes --------------------------------------------------------------------

func TestTheModeChoosesTheHeader(t *testing.T) {
	for _, tc := range []struct {
		mode Mode
		name string
		send bool
	}{
		{Enforce, "Content-Security-Policy", true},
		{ReportOnly, "Content-Security-Policy-Report-Only", true},
		{Off, "", false},
	} {
		name, send := Policy{Mode: tc.mode}.Header()
		if name != tc.name || send != tc.send {
			t.Errorf("%s gave (%q, %v)", tc.mode, name, send)
		}
	}
}
