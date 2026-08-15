package seo

import (
	"strings"
	"testing"
)

// A redirect map is authored, and an authored redirect that produces an
// off-site jump is an open redirect with a nice name.
func FuzzRedirects(f *testing.F) {
	f.Add("/a", "/b")
	f.Add("/a", "https://evil.example/")
	f.Add("/a", "//evil.example/")
	f.Add("/a", "javascript:alert(1)")
	f.Add("/a", "\\/\\/evil.example")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, from, to string) {
		m, err := NewMap([]Redirect{{From: from, To: to, Permanent: true}})
		if err != nil {
			return
		}
		r, ok := m.Lookup(from)
		if !ok {
			return
		}
		got := r.To
		// An absolute http(s) target is legitimate — an admin may redirect to
		// a partner site. What must never survive is a dangerous scheme, a
		// control character, or a relative target that a browser will read as
		// an authority.
		if sc := schemeOf(got); sc != "" {
			if sc != "http" && sc != "https" {
				t.Errorf("%q -> %q carries scheme %q", from, got, sc)
			}
			return
		}
		if err := noControls(got); err != nil {
			t.Errorf("%q -> %q: %v", from, got, err)
		}
		if strings.HasPrefix(got, "//") || strings.HasPrefix(got, "/\\") ||
			strings.HasPrefix(got, "\\") {
			t.Errorf("%q -> %q is read as an authority by a browser", from, got)
		}
	})
}
