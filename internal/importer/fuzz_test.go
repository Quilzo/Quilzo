package importer

import (
	"strings"
	"testing"
	"time"
)

var when = time.Unix(1786000000, 0)

// Import takes a file exported by somebody else's CMS, which means the bytes
// come from outside and the parse happens before anything validates them.
func FuzzImport(f *testing.F) {
	f.Add(`<?xml version="1.0"?><rss xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><item><title>a</title><link>http://x/a</link><content:encoded>hi</content:encoded></item></channel></rss>`)
	f.Add("---\ntitle: a\n---\nbody")
	f.Add(`[{"title":"a","body":"b","path":"/a"}]`)
	f.Add(`<rss><channel><item><title>`)
	f.Add("---\n---\n")
	f.Add(`<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><rss>&x;</rss>`)

	f.Fuzz(func(t *testing.T, src string) {
		src4, ok := Detect([]byte(src))
		if !ok {
			return
		}
		res, err := Import(src4, strings.NewReader(src), when)
		if err != nil {
			return
		}
		for _, p := range res.Pages {
			// A page name becomes a path on disk and a URL, so it must never
			// carry a separator or a traversal.
			for _, bad := range []string{"/", "\\", "..", "\x00"} {
				if contains(p.Name, bad) {
					t.Errorf("imported a page named %q", p.Name)
				}
			}
			for _, v := range p.Fields {
				str, ok := v.(string)
				if !ok {
					continue
				}
				if contains(lower(str), "<script") {
					t.Errorf("a script tag survived the import: %q", str)
				}
				if contains(lower(str), "javascript:") {
					t.Errorf("a javascript: URL survived: %q", str)
				}
			}
		}
	})
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
