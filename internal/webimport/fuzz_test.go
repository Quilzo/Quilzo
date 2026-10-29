// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package webimport

import (
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/quilzo/quilzo/internal/tmpl"
)

// Whatever a page is made of, reading it ends, and nothing it says becomes
// an address that is not a web page's.
func FuzzRead(f *testing.F) {
	for _, s := range []string{
		bakery().pages["/"], "<", "<a href='", "<!--", "<script>", "<img srcset=', ,'>",
		`<a href="javascript:alert(1)">x</a><a href="data:text/html,x">y</a>`,
		"<nav><nav><a href=/a>a</a></nav>", "<base href='https://evil.example/'><a href=x>x</a>",
	} {
		f.Add(s)
	}
	base, _ := url.Parse("https://hartsbakery.example/")
	f.Fuzz(func(t *testing.T, s string) {
		p := Read([]byte(s), base)
		for _, u := range p.Links {
			if u.Scheme != "http" && u.Scheme != "https" {
				t.Fatalf("a %s: address came out", u.Scheme)
			}
		}
		for _, b := range p.Blocks {
			if b.Src != nil && b.Src.Scheme != "http" && b.Src.Scheme != "https" {
				t.Fatalf("a picture at %s", b.Src)
			}
			if strings.ContainsAny(b.Text, "\x00\n") {
				t.Fatalf("a block holds a control character: %q", b.Text)
			}
		}
	})
}

// Whatever an export holds, reading it ends; whatever its words say, the
// prose they become never holds markup; and a folder's picture is a file of
// the folder or a web address, never anywhere else.
func FuzzExports(f *testing.F) {
	for _, s := range []string{wxr, ghost, "---\ntitle: x\n---\n# h\n\n- a\n- b\n\n![p](../../etc/passwd)", "+++\na = 1\n+++",
		"[x][y]\n\n[y]: javascript:alert(1)", "<div><script>x</script></div>", "```\n", "{{< figure src=\"/x\" >}}"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = FromWordPress([]byte(s), "x")
		_, _ = FromGhost([]byte(s), "x", nil)
		fm, body := matter(s)
		_ = fm
		fsys := fstest.MapFS{"a.md": {Data: []byte(s)}, "img.png": {Data: []byte("png")}}
		if site, err := FromFiles(fsys, "x"); err == nil {
			for _, pst := range site.Posts {
				for _, b := range pst.Blocks {
					checkBlock(t, b)
				}
			}
			for _, pg := range site.Pages {
				for _, b := range pg.Blocks {
					checkBlock(t, b)
				}
			}
		}
		for _, b := range mdBlocks(body, nil) {
			checkBlock(t, b)
		}
	})
}

func checkBlock(t *testing.T, b Block) {
	if b.Src != nil && b.Src.Scheme != "http" && b.Src.Scheme != "https" && b.Src.Scheme != "file" {
		t.Fatalf("a picture at %s", b.Src)
	}
	if b.Src != nil && b.Src.Scheme == "file" && strings.Contains(b.Src.Path, "..") {
		t.Fatalf("a picture outside the folder: %s", b.Src)
	}
	if out := string(tmpl.Prose(b.MD)); strings.Contains(out, "<script") || strings.Contains(strings.ToLower(out), `href="javascript`) {
		t.Fatalf("words became markup: %q", out)
	}
}
