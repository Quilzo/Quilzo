package tmpl

import "testing"

// The template engine is the highest-value target in this program: it takes
// author-supplied markup and content-supplied values and produces the bytes a
// reader's browser executes. A panic here is a denial of service and a wrong
// escape is cross-site scripting.
func FuzzRender(f *testing.F) {
	f.Add(`<p>{{ page.title }}</p>`, "hello")
	f.Add(`{% if page.a %}{{ page.a }}{% end %}`, "x")
	f.Add(`{% for i in page.list %}{{ i }}{% end %}`, "y")
	f.Add(`<a href="{{ page.url }}">x</a>`, "javascript:alert(1)")
	f.Add(`{% raw page.html %}`, "<script>alert(1)</script>")
	f.Add(`{{`, "")
	f.Add(`{% end %}`, "")
	f.Add(`{% for a in b %}{% for c in d %}{% for e in f %}x{% end %}{% end %}{% end %}`, "")

	f.Fuzz(func(t *testing.T, src, value string) {
		// Must not panic, and must terminate. Both are the point: an author can
		// write a template, and a template that hangs or crashes takes the site
		// with it.
		out, err := Render(src, map[string]any{
			"page": map[string]any{
				"title": value, "a": value, "url": value, "html": value,
				"list": []any{value, value},
			},
		})
		if err != nil {
			return
		}
		// Whatever came out, an unescaped script tag must not appear from a
		// value unless the template asked for raw.
		if containsScript(out) && !containsRaw(src) {
			t.Errorf("a script tag reached the output without raw\n src: %q\n val: %q\n out: %q",
				src, value, out)
		}
	})
}

func containsScript(s string) bool {
	for i := 0; i+8 <= len(s); i++ {
		if s[i:i+8] == "<script>" {
			return true
		}
	}
	return false
}

func containsRaw(s string) bool {
	for i := 0; i+5 <= len(s); i++ {
		if s[i:i+5] == "% raw" {
			return true
		}
	}
	return false
}
