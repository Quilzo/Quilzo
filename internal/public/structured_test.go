package public

import (
	"encoding/json"
	"strings"
	"testing"
)

// The whole reason this is built in Go: a title with a quote or an angle
// bracket has to survive into valid JSON, and the template renderer would
// escape it for HTML instead. This is the test that would have caught doing it
// the obvious way.
func TestHostileContentCannotBreakOutOfTheStructuredDataBlock(t *testing.T) {
	for _, payload := range []string{
		`</script><script>alert(1)</script>`,
		`a "quoted" title`,
		`<b>markup</b> & entities`,
		"a title with a \n newline",
	} {
		out := pageStructuredData("index", map[string]any{
			"title": payload, "description": payload,
		}, "Example", "https://example.com")

		if out == "" {
			t.Errorf("payload %q produced no block at all", payload)
			continue
		}
		lower := strings.ToLower(out)
		if strings.Contains(lower, "</script><script>") ||
			strings.Contains(lower, "<script>alert") {
			t.Errorf("payload %q broke out:\n%s", payload, out)
		}
		// And the result still has to be JSON, or the block is decoration.
		body := between(out, `<script type="application/ld+json">`, `</script>`)
		var doc map[string]any
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			t.Errorf("payload %q produced invalid JSON: %v\n%s", payload, err, body)
			continue
		}
		if doc["name"] != payload {
			t.Errorf("payload %q came back as %q", payload, doc["name"])
		}
	}
}

// A page is a WebPage until the content says it is an article. Read off the
// content rather than the layout, because the layout is a design decision and
// this is a claim about what the page is.
func TestThePageTypeComesFromTheContent(t *testing.T) {
	plain := decode(t, pageStructuredData("x", map[string]any{
		"title": "A page",
	}, "Example", ""))
	if plain["@type"] != "WebPage" {
		t.Errorf("a page with no byline is %v, want WebPage", plain["@type"])
	}

	article := decode(t, pageStructuredData("x", map[string]any{
		"title": "A piece", "byline": "A. Writer", "published": "2026-08-15",
		"section": "Engineering", "tags": []any{"one", "two"},
	}, "Example", ""))
	if article["@type"] != "Article" {
		t.Errorf("a page with a byline is %v, want Article", article["@type"])
	}
	if article["datePublished"] != "2026-08-15" {
		t.Errorf("the publication date is %v", article["datePublished"])
	}
	if _, present := article["dateModified"]; present {
		t.Error("a dateModified was invented; only the content may say when a " +
			"page changed, which is the same argument the sitemap's lastmod makes")
	}
}

// A page with no title makes no claim at all. Emitting a block with an empty
// name is worse than emitting nothing: it is a machine-readable assertion that
// this page is called "".
func TestAPageWithNoTitleGetsNoBlock(t *testing.T) {
	if out := pageStructuredData("x", map[string]any{
		"description": "words",
	}, "Example", ""); out != "" {
		t.Errorf("a titleless page produced:\n%s", out)
	}
}

// Breadcrumbs are absolute or absent. A relative URL in structured data is
// resolved against whatever the consumer assumes, and a crawler that guesses
// wrong indexes a page that does not exist.
func TestBreadcrumbsAreAbsoluteOrAbsent(t *testing.T) {
	body := map[string]any{
		"title": "Deep page",
		"breadcrumbs": []any{
			map[string]any{"label": "Home", "href": "/"},
			map[string]any{"label": "Section", "href": "/section"},
			map[string]any{"label": "Here"},
		},
	}

	withBase := pageStructuredData("x", body, "Example", "https://example.com")
	if !strings.Contains(withBase, `"https://example.com/section"`) {
		t.Errorf("a breadcrumb was not made absolute:\n%s", withBase)
	}
	if !strings.Contains(withBase, `"BreadcrumbList"`) {
		t.Errorf("no breadcrumb list was emitted:\n%s", withBase)
	}

	withoutBase := pageStructuredData("x", body, "Example", "")
	if strings.Contains(withoutBase, `"item"`) {
		t.Errorf("a relative breadcrumb URL was emitted with no base:\n%s", withoutBase)
	}
}

func decode(t *testing.T, out string) map[string]any {
	t.Helper()
	body := between(out, `<script type="application/ld+json">`, `</script>`)
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, body)
	}
	return doc
}

func between(s, open, close string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	rest := s[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return rest
	}
	return rest[:j]
}
