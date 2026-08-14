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
  <video autoplay muted src="loop.mp4"></video>
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
