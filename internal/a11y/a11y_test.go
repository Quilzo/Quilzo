// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package a11y

import (
	"strings"
	"testing"
)

// The scanner is hand-written, so it gets attacked before the checks that rest
// on it. Every case below is a place a naive scanner goes wrong, and getting one
// of them wrong produces accessibility findings that are confidently incorrect —
// which is worse than none, because someone will act on them.

func TestScannerHandlesTheAwkwardCases(t *testing.T) {
	cases := []struct {
		name, html string
		want       func([]tag) bool
		why        string
	}{
		{
			name: "a > inside a quoted attribute does not end the tag",
			html: `<img alt="a > b" src="x.png">`,
			want: func(ts []tag) bool {
				return len(ts) == 1 && ts[0].attrs["alt"] == "a > b" &&
					ts[0].attrs["src"] == "x.png"
			},
			why: "splitting on > is the classic scanner bug",
		},
		{
			name: "markup inside a comment is not scanned",
			html: `<!-- <img src=x> --><p>hi</p>`,
			want: func(ts []tag) bool {
				for _, tg := range ts {
					if tg.name == "img" {
						return false
					}
				}
				return true
			},
			why: "a commented-out image is not on the page",
		},
		{
			name: "a < inside a script is not a tag",
			html: `<script>if (a<b) { x(); }</script><p>after</p>`,
			want: func(ts []tag) bool {
				for _, tg := range ts {
					if tg.name == "b" {
						return false
					}
				}
				return true
			},
			why: "script content is raw text, not markup",
		},
		{
			name: "bare attributes are present with an empty value",
			html: `<video autoplay muted></video>`,
			want: func(ts []tag) bool {
				_, a := ts[0].attrs["autoplay"]
				_, m := ts[0].attrs["muted"]
				return a && m
			},
			why: "present-and-empty must differ from absent",
		},
		{
			name: "unquoted attribute values are read",
			html: `<a href=/about>x</a>`,
			want: func(ts []tag) bool { return ts[0].attrs["href"] == "/about" },
		},
		{
			name: "self-closing tags are marked",
			html: `<img src="a.png" alt="a" />`,
			want: func(ts []tag) bool { return ts[0].selfEnd },
		},
		{
			name: "tag and attribute names fold case",
			html: `<IMG ALT="x" SRC="y">`,
			want: func(ts []tag) bool {
				return ts[0].name == "img" && ts[0].attrs["alt"] == "x"
			},
		},
		{
			name: "a doctype is skipped",
			html: `<!doctype html><html lang="en"></html>`,
			want: func(ts []tag) bool { return ts[0].name == "html" },
		},
		{
			name: "an unterminated tag does not hang or panic",
			html: `<img alt="never closed`,
			want: func(ts []tag) bool { return true },
			why:  "malformed input must terminate",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scan(tc.html)
			if !tc.want(got) {
				t.Errorf("scanner got it wrong: %v\n  %s", got, tc.why)
			}
		})
	}
}

func has(r *Report, rule string) bool {
	for _, f := range r.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func TestBlockingFailures(t *testing.T) {
	cases := []struct {
		name, rule, html string
	}{
		{"image with no alt", "image-missing-alt",
			`<html lang="en"><title>t</title><img src="a.png"></html>`},
		{"heading level skipped", "heading-level-skipped",
			`<html lang="en"><title>t</title><h1>a</h1><h3>b</h3></html>`},
		{"link with no text", "link-has-no-text",
			`<html lang="en"><title>t</title><a href="/x"></a></html>`},
		{"no page language", "no-page-language",
			`<html><title>t</title><p>x</p></html>`},
		{"no title", "no-title",
			`<html lang="en"><p>x</p></html>`},
		{"unlabelled input", "input-has-no-label",
			`<html lang="en"><title>t</title><input type="text" name="q"></html>`},
		{"autoplaying audio", "media-autoplays",
			`<html lang="en"><title>t</title><audio autoplay src="a.mp3"></audio></html>`},
		{"untitled iframe", "frame-has-no-title",
			`<html lang="en"><title>t</title><iframe src="/x"></iframe></html>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Check("p", tc.html)
			if !has(r, tc.rule) {
				t.Fatalf("expected %s, got %v", tc.rule, r.Findings)
			}
			if !r.Blocks() {
				t.Errorf("%s should block a publish", tc.rule)
			}
		})
	}
}

// The negatives matter as much. A checker that flags correct markup teaches
// people to use the override, and after that it is not a control.
//
// The video here gained a captions track when 1.2.2 became a check. It used to
// be an autoplaying muted loop with no track, which was correct under the
// older rule set and is not under this one — and the honest reason it changed
// rather than the rule being softened is that "muted" is not "silent". A muted
// video is one the browser starts quiet and a reader can unmute; nothing in
// the markup says whether there is anything to hear. A recording that
// genuinely has no audio goes through the accessibility override with a
// written reason, which records who claimed it, rather than through an
// attribute that switches the check off.
func TestCorrectMarkupIsNotFlagged(t *testing.T) {
	good := `<!doctype html>
<html lang="en">
<head><title>Pricing</title></head>
<body>
  <h1>Pricing</h1>
  <h2>Plans</h2>
  <h3>Starter</h3>
  <h2>Questions</h2>
  <img src="chart.png" alt="Revenue rose from 2 to 9 million over four years">
  <img src="divider.png" alt="">
  <a href="/signup">Create an account</a>
  <label for="email">Email</label><input type="email" id="email">
  <input type="hidden" name="csrf" value="x">
  <button type="submit">Send</button>
  <table><tr><th>Plan</th></tr><tr><td>Starter</td></tr></table>
  <video autoplay muted src="loop.mp4">
    <track kind="captions" srclang="en" label="English" src="loop.vtt">
  </video>
  <iframe title="Pricing calculator" src="/calc"></iframe>
</body></html>`

	r := Check("pricing", good)
	if r.Blocks() {
		t.Fatalf("correct markup was blocked: %v", r.Findings)
	}
	if len(r.Findings) != 0 {
		t.Errorf("correct markup produced findings: %v", r.Findings)
	}
}

func TestDecorativeImagesAreAllowed(t *testing.T) {
	// alt="" is how you mark an image decorative. Flagging it would push authors
	// to write noise that a screen reader then has to read out.
	r := Check("p", `<html lang="en"><title>t</title><img src="x.png" alt=""></html>`)
	if has(r, "image-missing-alt") {
		t.Error("alt=\"\" is a decision, not an omission")
	}
}

func TestAdvisoryFindingsDoNotBlock(t *testing.T) {
	r := Check("p", `<html lang="en"><title>t</title>
      <h1>a</h1><a href="/x">click here</a>
      <img src="a.png" alt="photo.jpg"></html>`)
	if !has(r, "link-text-is-not-descriptive") {
		t.Error("expected the link text finding")
	}
	if !has(r, "image-alt-is-not-a-description") {
		t.Error("expected the alt-is-a-filename finding")
	}
	if r.Blocks() {
		t.Error("advisory findings must not block; they have real exceptions")
	}
}

func TestLinkWithAriaLabelIsFine(t *testing.T) {
	r := Check("p", `<html lang="en"><title>t</title>
      <a href="/x" aria-label="Close"><svg></svg></a></html>`)
	if has(r, "link-has-no-text") {
		t.Error("an aria-label supplies the accessible name")
	}
}

// A clean report must not read as a guarantee of accessibility.
func TestReportStatesItsOwnLimits(t *testing.T) {
	r := Check("p", `<html lang="en"><title>t</title><p>fine</p></html>`)
	if len(r.NotCheck) == 0 {
		t.Fatal("the report does not say what it did not check")
	}
	joined := strings.Join(r.NotCheck, " ")
	for _, want := range []string{"contrast", "useful"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the limits should mention %q", want)
		}
	}
}

// A link wrapping a described image is a named link.
//
// This blocked, and image links are the most ordinary thing on an image-led
// site, so the gate refused to publish a perfectly accessible page. Found by
// building one. What a false blocking failure teaches is to add a redundant
// aria-label or to reach for the override, and an override used from habit has
// stopped being a decision.
func TestALinkAroundADescribedImageHasAName(t *testing.T) {
	ok := `<html lang="en"><head><title>T</title></head><body>
	  <a href="/harbour"><img src="/m/1" alt="Dawn over a still harbour"></a>
	</body></html>`
	for _, f := range Check("p", ok).Findings {
		if f.Rule == "link-has-no-text" || f.Rule == "image-link-has-no-name" {
			t.Fatalf("a link around an image with alt text was reported as "+
				"nameless: %s", f)
		}
	}

	// Single quotes and extra attributes after alt must not confuse it.
	odd := `<html lang="en"><head><title>T</title></head><body>
	  <a href="/x"><img alt='A quiet coast road' src="/m/2" loading="lazy"></a>
	</body></html>`
	for _, f := range Check("p", odd).Findings {
		if f.Rule == "link-has-no-text" || f.Rule == "image-link-has-no-name" {
			t.Fatalf("alt in single quotes was not read: %s", f)
		}
	}
}

// A link whose only content is a decorative image really has no name.
func TestALinkAroundADecorativeImageIsStillReported(t *testing.T) {
	page := `<html lang="en"><head><title>T</title></head><body>
	  <a href="/x"><img src="/m/1" alt=""></a>
	</body></html>`
	found := false
	for _, f := range Check("p", page).Findings {
		if f.Rule == "image-link-has-no-name" {
			found = true
			if f.Severity != Blocking {
				t.Error("a link with no accessible name should block")
			}
			// The advice has to be the advice for this case.
			if !strings.Contains(f.Detail, "where it goes") {
				t.Errorf("the message does not say what to do: %s", f.Detail)
			}
		}
	}
	if !found {
		t.Fatal("a link containing only a decorative image was accepted; it " +
			"is announced as just \"link\"")
	}
}

// A genuinely empty link is still a genuinely empty link.
func TestAnEmptyLinkIsStillReported(t *testing.T) {
	page := `<html lang="en"><head><title>T</title></head><body>
	  <a href="/x"></a>
	</body></html>`
	found := false
	for _, f := range Check("p", page).Findings {
		if f.Rule == "link-has-no-text" {
			found = true
		}
	}
	if !found {
		t.Fatal("an empty link was not reported")
	}
}

// A video with no captions does not publish.
//
// WCAG 1.2.2 at Level A. This program refuses a Level A failure rather than
// warning about it, and a video a deaf reader cannot follow is the definition
// of the class — the same treatment as an image with no alternative text.
//
// The gap this closes: the gate checked exactly one thing about time-based
// media, autoplay, and did not disclose that it checked nothing else. So the
// conformance report this product generates — the VPAT-shaped document a buyer
// is shown — carried no row for the Time-based Media guideline in any state,
// for a product that ships a video section kind.
func TestAVideoWithNoCaptionsIsBlocked(t *testing.T) {
	r := Check("watch", page(`<video src="talk.mp4"></video>`))
	if !r.Blocks() {
		t.Fatalf("a video with no captions published: %v", r.Findings)
	}
	if !hasRule(r, "video-has-no-captions") {
		t.Errorf("blocked by something else: %v", r.Findings)
	}
}

// A source element counts as something to play.
func TestAVideoWithASourceElementIsChecked(t *testing.T) {
	r := Check("watch", page(
		`<video><source src="talk.mp4" type="video/mp4"></video>`))
	if !hasRule(r, "video-has-no-captions") {
		t.Errorf("a video whose file is in a source element was not "+
			"checked: %v", r.Findings)
	}
}

// Subtitles do not satisfy it.
//
// They translate the dialogue for somebody who can hear the rest. Captions
// carry the rest — a door closing, which of two people is speaking — and that
// difference is the whole of what a deaf reader is missing. Accepting either
// would make the check unable to tell whether it had been satisfied, and the
// HTML default for a track with no kind is subtitles.
func TestSubtitlesDoNotSatisfyCaptions(t *testing.T) {
	for name, markup := range map[string]string{
		"subtitles": `<video src="talk.mp4">` +
			`<track kind="subtitles" srclang="fr" src="fr.vtt"></video>`,
		"no kind at all": `<video src="talk.mp4">` +
			`<track srclang="en" src="en.vtt"></video>`,
		"descriptions": `<video src="talk.mp4">` +
			`<track kind="descriptions" srclang="en" src="d.vtt"></video>`,
	} {
		if r := Check("watch", page(markup)); !hasRule(r, "video-has-no-captions") {
			t.Errorf("%s was accepted as captions", name)
		}
	}
}

// A captions track satisfies it.
func TestACaptionsTrackSatisfiesIt(t *testing.T) {
	r := Check("watch", page(`<video src="talk.mp4">`+
		`<track kind="captions" srclang="en" label="English" src="en.vtt">`+
		`</video>`))
	if hasRule(r, "video-has-no-captions") {
		t.Errorf("a captioned video was blocked: %v", r.Findings)
	}
}

// A video element with nothing to play is not a video without captions.
//
// It is what the shipped layout emits before a file is chosen. There is no
// recording to caption, and a refusal there would be a refusal about nothing —
// which is how somebody learns to reach for the override.
func TestAnEmptyVideoElementIsNotBlocked(t *testing.T) {
	r := Check("watch", page(`<video controls></video>`))
	if hasRule(r, "video-has-no-captions") {
		t.Errorf("an empty video element was blocked: %v", r.Findings)
	}
}

// Two videos are judged separately, and a track inside one does not excuse
// the next.
func TestATrackDoesNotCarryToTheNextVideo(t *testing.T) {
	r := Check("watch", page(
		`<video src="a.mp4"><track kind="captions" srclang="en" src="a.vtt"></video>`+
			`<video src="b.mp4"></video>`))
	var found int
	for _, f := range r.Findings {
		if f.Rule == "video-has-no-captions" {
			found++
		}
	}
	if found != 1 {
		t.Errorf("%d finding(s) for one captioned and one uncaptioned "+
			"video, want 1: %v", found, r.Findings)
	}
}

// The Time-based Media guideline is spoken about, one way or the other.
//
// A criterion named in neither the covered list nor the uncovered one appears
// in no row of the conformance report at all — not supported, not failing, not
// even unevaluated. That silence is what this test exists to end.
func TestTimeBasedMediaIsAcknowledged(t *testing.T) {
	said := strings.Join(append(Covered(), NotCovered()...), " ")
	for _, criterion := range []string{"1.2.1", "1.2.2", "1.2.3", "1.2.5"} {
		if !strings.Contains(said, criterion) {
			t.Errorf("%s appears in neither list, so the conformance report "+
				"says nothing about it in any state", criterion)
		}
	}
}

// page wraps markup in the minimum a page needs so only the interesting rule
// can fire.
func page(body string) string {
	return `<!doctype html><html lang="en"><head><title>A page</title></head>` +
		`<body><h1>A page</h1>` + body + `</body></html>`
}

// hasRule reports whether a report carries a finding with this rule id.
func hasRule(r *Report, rule string) bool {
	for _, f := range r.Findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}
