// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/webimport"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func wxrDoc(items string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:wp="http://wordpress.org/export/1.2/"
     xmlns:content="http://purl.org/rss/1.0/modules/content/"
     xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel><title>A site</title>` + items + `</channel></rss>`
}

// -- the attacks that have actually hit WordPress ----------------------------

// CVE-2021-29447 and the 5.7 XXE were both this. The usual fix is a parser
// setting that disables external entities, which works until somebody forgets
// it in the next parser they add. Go's encoding/xml does not process DTD entity
// declarations at all, so the reference is never resolved because the
// declaration was never read.
//
// Asserted rather than assumed: "the standard library is safe" is a belief that
// survives the library changing.
func TestExternalEntitiesAreNeverResolved(t *testing.T) {
	for _, payload := range []string{
		`<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`,
		`<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>`,
		`<!DOCTYPE r [<!ENTITY % p SYSTEM "http://evil/e.dtd"> %p;]>`,
	} {
		doc := `<?xml version="1.0"?>` + payload + wxrDoc(
			`<item><title>&xxe;</title><wp:post_name>x</wp:post_name>
			 <wp:post_type>post</wp:post_type><wp:status>publish</wp:status></item>`)
		rep, err := Import(WordPress, strings.NewReader(doc), now)
		if err == nil {
			for _, p := range rep.Pages {
				if strings.Contains(str(p.Fields["title"]), "root:") {
					t.Fatal("a file was read through an entity")
				}
			}
			t.Errorf("a document declaring an external entity was accepted: %s",
				payload)
			continue
		}
		if !strings.Contains(err.Error(), "entities") &&
			!strings.Contains(err.Error(), "entity") {
			t.Errorf("refused for the wrong reason: %v", err)
		}
	}
}

// The other half of the same class: no external reference, just exponential
// expansion. Three levels here; the real attack uses nine.
func TestBillionLaughsCannotExpand(t *testing.T) {
	doc := `<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>` + wxrDoc(`<item><title>&lol3;</title></item>`)

	done := make(chan struct{})
	go func() {
		_, _ = Import(WordPress, strings.NewReader(doc), now)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the parser is still expanding after five seconds")
	}
}

// -- what an import may not do ----------------------------------------------

// Following attachment URLs during an import turns a file somebody sent you
// into a request from inside your network to a host they chose. The URLs are
// collected; fetching them is a separate, explicit step.
func TestAttachmentURLsAreCollectedAndNotFetched(t *testing.T) {
	doc := wxrDoc(`
	<item><title>A post</title><wp:post_name>a-post</wp:post_name>
	  <wp:post_type>post</wp:post_type><wp:status>publish</wp:status>
	  <content:encoded>Text with &lt;img src="http://169.254.169.254/x.png"&gt;</content:encoded>
	</item>
	<item><title>An image</title><wp:post_type>attachment</wp:post_type>
	  <wp:attachment_url>https://old.example/wp-content/photo.jpg</wp:attachment_url>
	</item>`)

	rep, err := Import(WordPress, strings.NewReader(doc), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Media) == 0 {
		t.Fatal("attachment URLs were not collected")
	}
	// The note has to say plainly that nothing was fetched, or somebody will
	// assume it was and wonder why the images are missing.
	joined := strings.Join(rep.Notes, " ")
	if !strings.Contains(joined, "NOT downloaded") {
		t.Errorf("the report does not say the URLs were not fetched: %v", rep.Notes)
	}
	// An internal address in the export must not be special-cased away here —
	// it is collected like any other and refused at fetch time, where the check
	// belongs.
	var sawInternal bool
	for _, m := range rep.Media {
		if strings.Contains(m, "169.254") {
			sawInternal = true
		}
	}
	if !sawInternal {
		t.Log("the internal URL was not collected, which is also acceptable")
	}
}

// -- HTML becomes text -------------------------------------------------------

func TestPostBodiesAreFlattenedToText(t *testing.T) {
	doc := wxrDoc(`<item><title>Hello</title><wp:post_name>hello</wp:post_name>
	  <wp:post_type>post</wp:post_type><wp:status>publish</wp:status>
	  <content:encoded>&lt;p&gt;First.&lt;/p&gt;&lt;script&gt;alert(1)&lt;/script&gt;
	    &lt;p&gt;Second &lt;a href="https://example.com"&gt;link&lt;/a&gt;.&lt;/p&gt;
	    &lt;img src="https://example.com/p.png" alt="A photo"&gt;</content:encoded>
	</item>`)

	rep, err := Import(WordPress, strings.NewReader(doc), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Pages) != 1 {
		t.Fatalf("got %d pages", len(rep.Pages))
	}
	body := str(rep.Pages[0].Fields["body"])

	if strings.Contains(body, "<") || strings.Contains(body, ">") {
		t.Errorf("markup survived into the body: %q", body)
	}
	if strings.Contains(body, "alert(1)") {
		t.Errorf("script content survived: %q", body)
	}
	if !strings.Contains(body, "First.") || !strings.Contains(body, "Second") {
		t.Errorf("the prose was lost: %q", body)
	}
	if !strings.Contains(body, "A photo") {
		t.Errorf("alt text was dropped; it is the description of the image: %q", body)
	}
	// And what was dropped has to be reported.
	if len(rep.Pages[0].Dropped) == 0 {
		t.Error("nothing was reported as dropped, but a script tag was removed")
	}
}

// Entities are decoded once, after tags are removed. Decoding first would turn
// &lt;script&gt; into a tag the scanner then honours — the double-decode bug.
func TestEncodedTagsDoNotBecomeRealTags(t *testing.T) {
	text, _, _, _ := flattenHTML(`&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;`)
	if strings.Contains(text, "<script>") {
		t.Errorf("a double-encoded tag was decoded into markup: %q", text)
	}
}

// -- structure ---------------------------------------------------------------

func TestWordPressInternalsAreSkippedAndReported(t *testing.T) {
	doc := wxrDoc(`
	<item><title>Real</title><wp:post_name>real</wp:post_name>
	  <wp:post_type>post</wp:post_type><wp:status>publish</wp:status></item>
	<item><title>Menu</title><wp:post_type>nav_menu_item</wp:post_type></item>
	<item><title>Old</title><wp:post_type>revision</wp:post_type></item>
	<item><title>Binned</title><wp:post_name>binned</wp:post_name>
	  <wp:post_type>post</wp:post_type><wp:status>trash</wp:status></item>`)

	rep, err := Import(WordPress, strings.NewReader(doc), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Pages) != 1 {
		t.Errorf("imported %d pages, expected 1", len(rep.Pages))
	}
	if len(rep.Skipped) != 3 {
		t.Errorf("skipped %d items silently or noisily: %v",
			len(rep.Skipped), rep.Skipped)
	}
	// Every skip must say why. An importer that drops half an export quietly is
	// worse than one that refuses, because the loss is found months later by a
	// reader.
	for _, s := range rep.Skipped {
		if !strings.Contains(s, "—") && !strings.Contains(s, "trash") {
			t.Errorf("a skip with no reason: %q", s)
		}
	}
}

func TestDuplicateSlugsAreMadeUnique(t *testing.T) {
	doc := wxrDoc(strings.Repeat(`<item><title>Same</title>
	  <wp:post_name>same</wp:post_name><wp:post_type>post</wp:post_type>
	  <wp:status>publish</wp:status></item>`, 3))

	rep, err := Import(WordPress, strings.NewReader(doc), now)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, p := range rep.Pages {
		if seen[p.Name] {
			t.Errorf("%q appeared twice; the later import would overwrite the "+
				"earlier one silently", p.Name)
		}
		seen[p.Name] = true
	}
	if len(rep.Pages) != 3 {
		t.Errorf("got %d pages", len(rep.Pages))
	}
	// Numbered from the name they share, and not each from the one before:
	// the third was "same-2-3".
	var names []string
	for _, p := range rep.Pages {
		names = append(names, p.Name)
	}
	if got := strings.Join(names, ","); got != "same,same-2,same-3" {
		t.Errorf("the pages are named %s, not same,same-2,same-3", got)
	}
}

// Items that would have the same name are numbered from that name, and
// finding the next number does not start again for each.
//
// Each was numbered from the name the one before it was given, so the
// thousandth of a thousand posts called "same" was same-2-3-4-…-1000,
// built by walking every name before it: an export of 10,000 same-titled
// items took seven minutes of CPU to import, and a feed an author brought
// could hold a CPU for an hour.
func TestSameTitledItemsAreNumberedFromTheirBaseInTimeInProportionToThem(t *testing.T) {
	item := func(name string) string {
		return `<item><title>Same</title><wp:post_name>` + name + `</wp:post_name>` +
			`<wp:post_type>post</wp:post_type><wp:status>publish</wp:status></item>`
	}
	var b strings.Builder
	b.WriteString(item("same"))
	b.WriteString(item("same-3"))
	for i := 0; i < 10000; i++ {
		b.WriteString(item("same"))
	}
	doc := wxrDoc(b.String())

	start := time.Now()
	rep, err := Import(WordPress, strings.NewReader(doc), now)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("importing %d same-titled items took %v", len(rep.Pages), took)
	}
	if len(rep.Pages) != 10002 {
		t.Fatalf("got %d pages, not 10002", len(rep.Pages))
	}
	var first []string
	for _, p := range rep.Pages[:5] {
		first = append(first, p.Name)
	}
	if got, last := strings.Join(first, ","), rep.Pages[len(rep.Pages)-1].Name; got != "same,same-3,same-2,same-4,same-5" || last != "same-10002" {
		t.Errorf("the pages are named %s ... %s", got, last)
	}
}

// A page name becomes part of a URL and a key in the store, so it has to be
// constrained regardless of what the export contained.
func TestSlugsAreConstrained(t *testing.T) {
	cases := map[string]string{
		"../../etc/passwd": "etc-passwd",
		"Hello, World!":    "hello-world",
		"  spaced  out  ":  "spaced-out",
		"UPPER":            "upper",
		"a/b/c":            "a-b-c",
		"...":              "",
		"page<script>":     "pagescript",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, wanted %q", in, got, want)
		}
	}
}

// -- markdown ----------------------------------------------------------------

func TestMarkdownFrontMatterIsReadFlat(t *testing.T) {
	doc := `---
title: A post
slug: a-post
published: 2026-08-15
---

# A post

Some prose.`
	rep, err := Import(Markdown, strings.NewReader(doc), now)
	if err != nil {
		t.Fatal(err)
	}
	f := rep.Pages[0].Fields
	if f["title"] != "A post" || f["slug"] != "a-post" {
		t.Errorf("front matter not read: %#v", f)
	}
	if !strings.Contains(str(f["body"]), "Some prose.") {
		t.Errorf("body missing: %q", f["body"])
	}
}

// A full YAML parser is a large attack surface: anchors and aliases give a
// billion-laughs equivalent, and several parsers construct arbitrary types from
// tags. Front matter in practice is flat keys, so that is all that is read and
// the rest is reported rather than guessed at.
func TestYAMLAnchorsAndAliasesAreRefusedNotInterpreted(t *testing.T) {
	doc := `---
title: A post
base: &anchor a very long string
copy: *anchor
danger: !!python/object/apply:os.system ["id"]
---
Body.`
	rep, err := Import(Markdown, strings.NewReader(doc), now)
	if err != nil {
		t.Fatal(err)
	}
	f := rep.Pages[0].Fields
	if _, ok := f["copy"]; ok {
		t.Error("a YAML alias was interpreted")
	}
	if _, ok := f["danger"]; ok {
		t.Error("a YAML type tag was interpreted")
	}
	if len(rep.Skipped) == 0 {
		t.Error("the unread keys were dropped without being reported")
	}
}

// -- json --------------------------------------------------------------------

func TestJSONArraysAndMapsBothImport(t *testing.T) {
	arr := `[{"title":"One","slug":"one"},{"title":"Two","slug":"two"}]`
	rep, err := Import(JSON, strings.NewReader(arr), now)
	if err != nil || len(rep.Pages) != 2 {
		t.Fatalf("array import: %v, %d pages", err, len(rep.Pages))
	}

	obj := `{"home":{"title":"Home"},"about":{"title":"About"}}`
	rep, err = Import(JSON, strings.NewReader(obj), now)
	if err != nil || len(rep.Pages) != 2 {
		t.Fatalf("map import: %v, %d pages", err, len(rep.Pages))
	}
	if rep.Pages[0].Name != "about" {
		t.Errorf("pages are not in a stable order: %s", rep.Pages[0].Name)
	}
}

// Two pages that come to the same name both arrive, numbered from it.
//
// The JSON reader numbered nothing. An array of two pages titled "Same" read
// as two pages both named "same", and `quilzo import` and the browser's
// import both write pages by name, so the second replaced the first and a
// page was lost without a word. Every other format numbers the names it
// shares (same, same-2, same-3), and now this one does too.
func TestTwoSameNamedPagesInAJSONImportBothArrive(t *testing.T) {
	arr := `[{"title":"Same","body":"first"},{"title":"Same","body":"second"},
		{"slug":"same","body":"third"}]`
	rep, err := Import(JSON, strings.NewReader(arr), now)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range rep.Pages {
		got = append(got, p.Name+"="+str(p.Fields["body"]))
	}
	if g := strings.Join(got, ","); g != "same=first,same-2=second,same-3=third" {
		t.Fatalf("the pages arrived as %s, not same, same-2 and same-3 in order", g)
	}
	// A page's own link agrees with the name it was given, or the page
	// numbered so as not to replace another would still claim its address.
	if s := rep.Pages[2].Fields["slug"]; s != "same-3" {
		t.Errorf("the third page is named same-3 but its slug says %v", s)
	}

	// A map's keys are names already, but two of them can come to the same
	// one. The key that is already its name keeps it; the other is numbered.
	obj := `{"About Us":{"title":"Numbered"},"about-us":{"title":"Kept"}}`
	rep, err = Import(JSON, strings.NewReader(obj), now)
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	for _, p := range rep.Pages {
		got = append(got, p.Name+"="+str(p.Fields["title"]))
	}
	if g := strings.Join(got, ","); g != "about-us=Kept,about-us-2=Numbered" {
		t.Fatalf("the pages arrived as %s, not about-us and about-us-2", g)
	}
}

// A Ghost export is not read as Quilzo's pages, and the refusal says where it
// can be brought. It is JSON, so it was read as pages and refused with "no
// importable pages found", while `quilzo site import` reads the same file
// into a site with its posts: two readers of one file, and the one that could
// not read it said there was nothing in it.
func TestAGhostExportIsNotReadAsQuilzoPages(t *testing.T) {
	ghost := `{"db":[{"meta":{"exported_on":1761700000000,"version":"5.98.0"},` +
		`"data":{"posts":[{"id":"1","title":"Hello","slug":"hello","type":"post",` +
		`"status":"published","html":"<p>Hi.</p>"}]}}]}`
	src, _ := Detect([]byte(ghost))
	rep, err := Import(src, strings.NewReader(ghost), now)
	if err == nil {
		t.Fatalf("a Ghost export was read as %d Quilzo pages", len(rep.Pages))
	}
	if !strings.Contains(err.Error(), "Ghost export") || !strings.Contains(err.Error(), "quilzo site import") {
		t.Errorf("refused without saying what it is or where it goes: %v", err)
	}

	// A page called "posts" with a field called "data" is still a page: the
	// hint is only for a file the page reader found nothing in.
	rep, err = Import(JSON, strings.NewReader(`{"posts":{"title":"Posts","data":"x","meta":"y"}}`), now)
	if err != nil || len(rep.Pages) != 1 {
		t.Fatalf("a page called posts was refused: %v", err)
	}
}

// A Ghost export with no "db" around it is not read as Quilzo's pages either.
//
// Ghost writes its export both ways, and the site import reads both. The
// refusal above came only once the page reader found nothing, and this shape
// gives it something: its "meta" and its "data" are objects, so it was read
// as two pages called "data" and "meta", the posts a list in a field, and
// `quilzo import` and the browser's import wrote them into the draft without
// a word while `quilzo site import` read the same file as a post.
func TestAGhostExportWithNoDBAroundItIsNotReadAsQuilzoPages(t *testing.T) {
	ghost := `{"meta":{"exported_on":1761700000000,"version":"5.98.0"},` +
		`"data":{"posts":[{"id":"1","title":"Hello","slug":"hello","type":"post",` +
		`"status":"published","html":"<p>Hi.</p>"}]}}`
	for _, src := range []Source{"", JSON} {
		if src == "" {
			src, _ = Detect([]byte(ghost))
		}
		rep, err := Import(src, strings.NewReader(ghost), now)
		if err == nil {
			var names []string
			for _, p := range rep.Pages {
				names = append(names, p.Name)
			}
			t.Fatalf("a Ghost export was read as the Quilzo pages %v", names)
		}
		if !strings.Contains(err.Error(), "Ghost export") || !strings.Contains(err.Error(), "quilzo site import") {
			t.Errorf("refused without saying what it is or where it goes: %v", err)
		}
	}

	// Pages that are called data and meta, with nothing of Ghost's in them,
	// are still pages.
	rep, err := Import(JSON, strings.NewReader(`{"data":{"title":"Our data"},"meta":{"title":"About this site"}}`), now)
	if err != nil || len(rep.Pages) != 2 {
		t.Fatalf("pages called data and meta were refused: %v", err)
	}
}

// Content types are flat, which is what keeps validation bounded. A nested
// object has nowhere to go, so it is reported rather than flattened into keys
// nobody declared.
func TestNestedObjectsAreReportedNotFlattened(t *testing.T) {
	rep, err := Import(JSON, strings.NewReader(
		`[{"title":"X","slug":"x","meta":{"a":{"b":1}}}]`), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rep.Pages[0].Fields["meta"]; ok {
		t.Error("a nested object was imported into a flat field set")
	}
	if len(rep.Pages[0].Dropped) == 0 {
		t.Error("the nested object was dropped without being reported")
	}
}

// -- bounds and detection ----------------------------------------------------

func TestDetectionRecognisesEachFormat(t *testing.T) {
	cases := map[string]Source{
		`<?xml version="1.0"?><rss><channel><wp:author/></channel></rss>`: WordPress,
		"---\ntitle: x\n---\nbody": Markdown,
		`[{"title":"x"}]`:          JSON,
		`{"home":{}}`:              JSON,
	}
	for body, want := range cases {
		got, ok := Detect([]byte(body))
		if !ok || got != want {
			t.Errorf("Detect(%.30q) = %q/%v, wanted %q", body, got, ok, want)
		}
	}
	if _, ok := Detect([]byte("just some text")); ok {
		t.Error("plain text was detected as a known format")
	}
}

func TestAnEmptyOrOversizedImportIsRefused(t *testing.T) {
	if _, err := Import(JSON, strings.NewReader(""), now); err == nil {
		t.Error("an empty import was accepted")
	}
	if _, err := Import("nonsense", strings.NewReader("{}"), now); err == nil {
		t.Error("an unknown source was accepted")
	}
}

// The regression above: removing <script> while keeping what was between it
// turns the script body into visible page text, which is how an import produces
// a page that reads "alert(1)" in the middle of a paragraph.
func TestTheContentsOfScriptAndStyleAreDiscardedNotFlattened(t *testing.T) {
	cases := []string{
		`<p>Before.</p><script>var x = "leak";</script><p>After.</p>`,
		`<p>Before.</p><style>body{background:url(evil)}</style><p>After.</p>`,
		`<p>Before.</p><noscript>fallback text</noscript><p>After.</p>`,
		`<p>Before.</p><iframe src="https://evil"></iframe><p>After.</p>`,
	}
	for _, in := range cases {
		text, _, _, dropped := flattenHTML(in)
		for _, leaked := range []string{"leak", "background", "fallback", "evil"} {
			if strings.Contains(text, leaked) {
				t.Errorf("%q leaked into the body: %q", leaked, text)
			}
		}
		if !strings.Contains(text, "Before.") || !strings.Contains(text, "After.") {
			t.Errorf("prose around the discarded element was lost: %q", text)
		}
		if len(dropped) == 0 {
			t.Errorf("content was discarded silently for %q", in)
		}
	}
}

// An unclosed script would swallow the rest of the document. That may be the
// right outcome, but it cannot be a silent one.
func TestAnUnclosedScriptIsReported(t *testing.T) {
	text, _, _, dropped := flattenHTML(`<p>Kept.</p><script>rest of the page`)
	if strings.Contains(text, "rest of the page") {
		t.Errorf("script content survived: %q", text)
	}
	var warned bool
	for _, d := range dropped {
		if strings.Contains(d, "unclosed") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("the truncation was not reported: %v", dropped)
	}
}

// WXR carries both content:encoded and excerpt:encoded. An unqualified tag
// matches whichever appears first, which silently imports excerpts as bodies on
// exports that order them the other way.
func TestTheBodyComesFromContentNotExcerpt(t *testing.T) {
	doc := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:wp="http://wordpress.org/export/1.2/"
     xmlns:content="http://purl.org/rss/1.0/modules/content/"
     xmlns:excerpt="http://wordpress.org/export/1.2/excerpt/">
<channel><item>
  <title>T</title><wp:post_name>t</wp:post_name>
  <wp:post_type>post</wp:post_type><wp:status>publish</wp:status>
  <excerpt:encoded>THE EXCERPT</excerpt:encoded>
  <content:encoded>THE FULL BODY</content:encoded>
</item></channel></rss>`

	rep, err := Import(WordPress, strings.NewReader(doc), now)
	if err != nil {
		t.Fatal(err)
	}
	body := str(rep.Pages[0].Fields["body"])
	if !strings.Contains(body, "THE FULL BODY") {
		t.Errorf("the body is %q; the full content was not used", body)
	}
	if strings.Contains(body, "THE EXCERPT") {
		t.Errorf("the excerpt was imported as the body: %q", body)
	}
}

// The export already contains every URL the content had in the old system.
// Leaving the redirect map to be typed by hand afterwards is leaving the most
// valuable output of a migration on the floor — it is the artefact that decides
// whether the rankings survive.
func TestOldURLsBecomeRedirects(t *testing.T) {
	doc := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:wp="http://wordpress.org/export/1.2/"
     xmlns:content="http://purl.org/rss/1.0/modules/content/">
<channel>
<item><title>Hello</title><link>https://old.example/2019/03/hello-world/</link>
  <wp:post_name>hello-world</wp:post_name><wp:post_type>post</wp:post_type>
  <wp:status>publish</wp:status></item>
<item><title>About</title><link>https://old.example/about-us/</link>
  <wp:post_name>about-us</wp:post_name><wp:post_type>page</wp:post_type>
  <wp:status>publish</wp:status></item>
</channel></rss>`

	rep, err := Import(WordPress, strings.NewReader(doc), now)
	if err != nil {
		t.Fatal(err)
	}
	// One redirect, not two. The dated permalink /2019/03/hello-world moved to
	// /hello-world, but /about-us is /about-us in both systems — most pages
	// keep their path across a migration, and a self-redirect is a loop.
	if len(rep.Redirects) != 1 {
		t.Fatalf("got %d redirects; expected only the page that moved: %#v",
			len(rep.Redirects), rep.Redirects)
	}
	r := rep.Redirects[0]
	if !r.Permanent {
		t.Error("the redirect is temporary; the content genuinely moved and a " +
			"temporary redirect does not transfer ranking")
	}
	// The hostname is dropped: a map carrying hostnames breaks when the site
	// moves again.
	if r.From != "/2019/03/hello-world" || r.To != "/hello-world" {
		t.Errorf("the old path did not map to the new one: %s -> %s", r.From, r.To)
	}
	// And the pages that did not move are accounted for, so nobody wonders
	// where the other redirect went.
	if !strings.Contains(strings.Join(rep.Notes, " "), "same path") {
		t.Errorf("the unchanged page was not mentioned: %v", rep.Notes)
	}
	// And the operator is told what to do with them.
	if !strings.Contains(strings.Join(rep.Notes, " "), "redirects") {
		t.Errorf("the redirects were generated without being mentioned: %v",
			rep.Notes)
	}
}

// A contradictory or looping map has to fail the import rather than produce a
// site that redirects in circles.
func TestAnUnusableRedirectMapIsReportedNotShipped(t *testing.T) {
	// Two different posts claiming the same old URL.
	doc := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:wp="http://wordpress.org/export/1.2/"
     xmlns:content="http://purl.org/rss/1.0/modules/content/">
<channel>
<item><title>One</title><link>https://old.example/same/</link>
  <wp:post_name>one</wp:post_name><wp:post_type>post</wp:post_type>
  <wp:status>publish</wp:status></item>
<item><title>Two</title><link>https://old.example/same/</link>
  <wp:post_name>two</wp:post_name><wp:post_type>post</wp:post_type>
  <wp:status>publish</wp:status></item>
</channel></rss>`

	rep, err := Import(WordPress, strings.NewReader(doc), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Redirects) != 0 {
		t.Error("a contradictory redirect map was shipped anyway")
	}
	joined := strings.Join(rep.Notes, " ")
	if !strings.Contains(joined, "break") {
		t.Errorf("the consequence was not stated: %v", rep.Notes)
	}
	// The pages themselves must still import — losing the content because the
	// redirects were ambiguous would be the wrong trade.
	if len(rep.Pages) != 2 {
		t.Errorf("imported %d pages; the content should survive a redirect "+
			"problem", len(rep.Pages))
	}
}

// One WordPress export gives one set of pages with one set of names,
// whichever command reads it. `quilzo import` named a page from its slug or
// its title, and `quilzo site import` from its link's path: on plain
// permalinks (?page_id=) site import named every page alike and refused the
// export, and on pretty links without a slug the two named the same pages
// qa-night and qa, nave-caf and naive.
func TestQuilzoImportAndSiteImportReadTheSameWordPressExportAlike(t *testing.T) {
	item := func(title, link, slug string) string {
		s := `<item><title>` + title + `</title><link>` + link + `</link>`
		if slug != "" {
			s += `<wp:post_name>` + slug + `</wp:post_name>`
		}
		return s + `<wp:post_type>page</wp:post_type><wp:status>publish</wp:status>` +
			`<content:encoded><![CDATA[<p>Words.</p>]]></content:encoded></item>`
	}
	for name, items := range map[string]string{
		"plain links, as a fresh install has them": item("Q&amp;A night", "https://old.example.org/?page_id=11", "qa-night") +
			item("Naïve café", "https://old.example.org/?page_id=12", "naive-cafe") +
			item("Tom &amp; Jerry_v1.2", "https://old.example.org/?page_id=13", "tom-jerry"),
		"pretty links, with no slugs": item("Q&amp;A night", "https://old.example.org/qa/", "") +
			item("Naïve café", "https://old.example.org/naive/", "") +
			item("Tom &amp; Jerry_v1.2", "https://old.example.org/tj/", ""),
		"pretty links that are not the slugs": item("Q&amp;A night", "https://old.example.org/events/qa/", "qa-night") +
			item("Naïve café", "https://old.example.org/naive/", "naive-cafe"),
	} {
		doc := strings.Replace(wxrDoc(items), "<channel><title>A site</title>",
			"<channel><title>A site</title><link>https://old.example.org</link>", 1)
		rep, err := Import(WordPress, strings.NewReader(doc), now)
		if err != nil {
			t.Fatalf("%s: quilzo import: %v", name, err)
		}
		var imported []string
		for _, p := range rep.Pages {
			imported = append(imported, p.Name)
		}
		s, err := webimport.FromWordPress([]byte(doc), "")
		if err != nil {
			t.Fatalf("%s: site import: %v", name, err)
		}
		b, err := webimport.Package(s, "", "dana", nil, now)
		if err != nil {
			t.Fatalf("%s: site import: %v", name, err)
		}
		if err := b.Package.Validate(feature.Checks{}); err != nil {
			t.Fatalf("%s: site import: %v", name, err)
		}
		var packaged []string
		for _, p := range b.Package.Pages {
			if p.Name != "index" {
				packaged = append(packaged, p.Name)
			}
		}
		sort.Strings(imported)
		sort.Strings(packaged)
		if strings.Join(imported, " ") != strings.Join(packaged, " ") {
			t.Errorf("%s: quilzo import names the pages %v and site import %v", name, imported, packaged)
		}
	}
}
