package export

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rsh1k/scrivet/internal/importer"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

// A site with every field shape the store can hold, including the ones that
// break naive exporters: characters that are markup, characters that YAML
// interprets, a body with the sequence that ends a CDATA section.
func fullSite() Site {
	return Site{
		Name:    "Example & Co",
		BaseURL: "https://example.com",
		Pages: map[string]any{
			"index": map[string]any{
				"title": "Home",
				"body":  "Welcome to the site.",
				"slug":  "index",
			},
			"tricky": map[string]any{
				"title":  `Quotes "and" <angles> & ampersands`,
				"body":   "A body containing ]]> which ends a CDATA section.\nAnd a second line.",
				"slug":   "tricky",
				"note":   "no",       // YAML 1.1 reads bare `no` as false
				"code":   "12:30",    // and bare 12:30 as a sexagesimal integer
				"anchor": "&notreal", // a leading & is a YAML anchor
				"tags":   []any{"one", "two"},
			},
		},
		Changed: map[string]time.Time{
			"index":  time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			"tricky": time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC),
		},
		Redirects: []Redirect{
			{From: "/old", To: "/index", Permanent: true, Note: "moved"},
		},
	}
}

// The only check that means anything. Every CMS has an export button; most
// produce something that loses half the content, and nobody finds out until the
// day they try to leave.
//
// Export, re-import, compare. A single changed field fails this.
func TestJSONRoundTripsExactly(t *testing.T) {
	site := fullSite()
	files, err := Export(JSON, site, now)
	if err != nil {
		t.Fatal(err)
	}

	body := find(t, files, "content/pages.json")
	rep, err := importer.Import(importer.JSON, strings.NewReader(string(body)), now)
	if err != nil {
		t.Fatalf("this tool cannot re-import its own export: %v", err)
	}

	got := map[string]any{}
	for _, p := range rep.Pages {
		got[p.Name] = p.Fields
		if len(p.Dropped) > 0 {
			t.Errorf("%s lost %v on the way back in", p.Name, p.Dropped)
		}
	}
	if len(got) != len(site.Pages) {
		t.Fatalf("exported %d pages, re-imported %d", len(site.Pages), len(got))
	}
	for name, want := range site.Pages {
		if !reflect.DeepEqual(got[name], want) {
			t.Errorf("%s did not survive the round trip:\n  out: %#v\n  back: %#v",
				name, want, got[name])
		}
	}
}

// Markdown is lossier by construction — the body becomes the document and the
// front matter is flat — but every field must still come back, and the values
// must not be reinterpreted by YAML on the way.
func TestMarkdownRoundTripsEveryField(t *testing.T) {
	site := fullSite()
	files, err := Export(Markdown, site, now)
	if err != nil {
		t.Fatal(err)
	}

	for name, original := range site.Pages {
		body := find(t, files, "content/"+name+".md")
		rep, err := importer.Import(importer.Markdown,
			strings.NewReader(string(body)), now)
		if err != nil {
			t.Fatalf("%s does not re-import: %v", name, err)
		}
		if len(rep.Skipped) > 0 {
			t.Errorf("%s: front matter this tool wrote was not readable by the "+
				"same tool: %v", name, rep.Skipped)
		}
		got := rep.Pages[0].Fields
		fields := original.(map[string]any)

		for k, want := range fields {
			if k == "tags" {
				continue // a list becomes a flow sequence; checked separately
			}
			w, isString := want.(string)
			if !isString {
				continue
			}
			if k == "body" {
				// The body becomes the document, and trailing whitespace is
				// normalised. Compare the content.
				if !strings.Contains(str(got["body"]), strings.TrimSpace(w)) {
					t.Errorf("%s body did not survive:\n  out:  %q\n  back: %q",
						name, w, got["body"])
				}
				continue
			}
			if str(got[k]) != w {
				t.Errorf("%s field %q changed: %q -> %q", name, k, w, got[k])
			}
		}
	}
}

// The values YAML silently reinterprets. `no` is false in YAML 1.1, `12:30` is
// a sexagesimal integer, a leading `&` is an anchor. Everything is quoted on
// the way out, which is what stops any of that happening.
func TestValuesYAMLWouldReinterpretComeBackAsStrings(t *testing.T) {
	files, err := Export(Markdown, fullSite(), now)
	if err != nil {
		t.Fatal(err)
	}
	body := string(find(t, files, "content/tricky.md"))

	for _, want := range []string{`note: "no"`, `code: "12:30"`, `anchor: "&notreal"`} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %s in the front matter, got:\n%s", want, body)
		}
	}
	// And an unquoted form must not appear.
	for _, bad := range []string{"note: no\n", "code: 12:30\n", "anchor: &notreal"} {
		if strings.Contains(body, bad) {
			t.Errorf("%q was written unquoted, so a YAML reader will change it", bad)
		}
	}
}

// A body containing "]]>" would close the CDATA section early, letting the rest
// of the content be parsed as markup — a corruption in the export and an
// injection into whatever reads it next.
func TestWXRSurvivesContentThatWouldEndACDATASection(t *testing.T) {
	files, err := Export(WXR, fullSite(), now)
	if err != nil {
		t.Fatal(err)
	}
	body := string(find(t, files, "content/wordpress-export.xml"))

	// Every ]]> in the output must be part of the escaped form. A bare one
	// closes the section and lets the remaining content be parsed as markup.
	scan := body
	for {
		i := strings.Index(scan, "]]>")
		if i < 0 {
			break
		}
		// The escaped form is "]]]]><![CDATA[>", so a legitimate occurrence is
		// preceded by "]]" and followed by "<![CDATA[>".
		escaped := i >= 2 && scan[i-2:i] == "]]" &&
			strings.HasPrefix(scan[i+3:], "<![CDATA[>")
		closing := strings.HasPrefix(scan[i:], "]]></")
		if !escaped && !closing {
			t.Errorf("a bare ]]> at offset %d closes the CDATA section early",
				len(body)-len(scan)+i)
			break
		}
		scan = scan[i+3:]
	}

	// It must still parse, and this tool reads WXR, so re-import it.
	rep, err := importer.Import(importer.WordPress, strings.NewReader(body), now)
	if err != nil {
		t.Fatalf("the WXR this tool produced does not parse: %v", err)
	}
	if len(rep.Pages) != 2 {
		t.Fatalf("re-imported %d pages from 2", len(rep.Pages))
	}
	// Only the page whose body contains the sequence needs to have kept it.
	var checked bool
	for _, p := range rep.Pages {
		if p.Name != "tricky" {
			continue
		}
		checked = true
		if !strings.Contains(str(p.Fields["body"]), "]]>") {
			t.Errorf("the ]]> sequence was lost on the round trip: %q",
				p.Fields["body"])
		}
	}
	if !checked {
		t.Error("the page carrying the sequence did not survive at all")
	}
}

// Markup in a title must survive as text rather than becoming markup.
func TestMarkupInContentIsNeitherExecutedNorLost(t *testing.T) {
	for _, f := range []Format{Markdown, JSON, WXR} {
		files, err := Export(f, fullSite(), now)
		if err != nil {
			t.Fatal(err)
		}
		var all strings.Builder
		for _, file := range files {
			all.Write(file.Body)
		}
		out := all.String()
		if strings.Contains(out, "<angles>") && f != Markdown && f != JSON {
			t.Errorf("%s: a raw tag reached the output", f)
		}
	}

	// The WXR case specifically: re-import and check the title came back whole.
	files, _ := Export(WXR, fullSite(), now)
	rep, err := importer.Import(importer.WordPress,
		strings.NewReader(string(find(t, files, "content/wordpress-export.xml"))), now)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range rep.Pages {
		if str(p.Fields["title"]) == `Quotes "and" <angles> & ampersands` {
			found = true
		}
	}
	if !found {
		t.Error("a title containing markup did not survive the round trip")
	}
}

// -- what an export must contain ---------------------------------------------

// An export without redirects hands somebody a site that loses its rankings on
// arrival.
func TestRedirectsAreCarriedInEveryFormat(t *testing.T) {
	for _, f := range Formats() {
		files, err := Export(f, fullSite(), now)
		if err != nil {
			t.Fatal(err)
		}
		body := find(t, files, "redirects.json")
		if !strings.Contains(string(body), "/old") {
			t.Errorf("%s: the redirect map is missing", f)
		}
	}
}

// An export nobody can work out how to use is an export that exists to satisfy
// a checkbox, so the instructions name real tools.
func TestEveryExportExplainsHowToLoadItElsewhere(t *testing.T) {
	expect := map[Format][]string{
		Markdown: {"Hugo", "Astro", "Eleventy", "Jekyll"},
		JSON:     {"lossless"},
		WXR:      {"Tools → Import"},
	}
	for f, wants := range expect {
		files, err := Export(f, fullSite(), now)
		if err != nil {
			t.Fatal(err)
		}
		readme := string(find(t, files, "README.md"))
		for _, want := range wants {
			if !strings.Contains(readme, want) {
				t.Errorf("%s: the README does not mention %q", f, want)
			}
		}
	}
}

// Plain files, no archive. Somebody should be able to recover one page with a
// text editor and no tooling at all.
func TestTheOutputIsOrdinaryFiles(t *testing.T) {
	for _, f := range Formats() {
		files, err := Export(f, fullSite(), now)
		if err != nil {
			t.Fatal(err)
		}
		if len(files) < 2 {
			t.Errorf("%s produced %d files", f, len(files))
		}
		for _, file := range files {
			if strings.HasPrefix(file.Path, "/") || strings.Contains(file.Path, "..") {
				t.Errorf("%s: unsafe path %q", f, file.Path)
			}
			if strings.Contains(file.Path, "\\") {
				t.Errorf("%s: %q uses a backslash", f, file.Path)
			}
			for _, ext := range []string{".zip", ".tar", ".gz", ".bin"} {
				if strings.HasSuffix(file.Path, ext) {
					t.Errorf("%s: %q is an archive; an export should be readable "+
						"with cat", f, file.Path)
				}
			}
			if len(file.Body) == 0 {
				t.Errorf("%s: %q is empty", f, file.Path)
			}
		}
	}
}

func TestAnEmptySiteIsRefusedRatherThanProducingAnEmptyExport(t *testing.T) {
	for _, f := range Formats() {
		if _, err := Export(f, Site{}, now); err == nil {
			t.Errorf("%s produced an export of nothing", f)
		}
	}
}

func find(t *testing.T, files []File, path string) []byte {
	t.Helper()
	for _, f := range files {
		if f.Path == path {
			return f.Body
		}
	}
	var have []string
	for _, f := range files {
		have = append(have, f.Path)
	}
	t.Fatalf("no %s in the export; got %v", path, have)
	return nil
}
