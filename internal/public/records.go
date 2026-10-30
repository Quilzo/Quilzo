// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"crypto/sha256"
	"encoding/hex"
	"html"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/render"
)

// What the chatbots and site search know about records.
//
// # The gap this closes
//
// A shop's products are records, and a product's words are on its own page
// (detail.go) and nowhere else. The chatbots and site search read pages as
// they are stored, and a page standing for records stores none: it names a
// listing and a key. So asked what the brass pen costs, the shop's own
// chatbot could not find it on the site, while the site showed the price at
// /product/brass-pen to anybody who looked.
//
// # Read the way the page shows it
//
// Reading the collection would fill the gap and leak, for the reason the
// detail route reads through a listing: a record's fields are not what is
// public about it. So a record is read through its page, by the code that
// serves the page. Every page a visitor can open now that stands for
// records; every record the listing it names keeps, with no arguments, as
// the sitemap and a static copy count them (render.DetailRows); drawn by
// detailBody, as the route draws it; and then read as a visitor reads it:
// the words inside <main>, and nothing inside a tag, a script, a form or a
// hidden element. A field the listing hands the layout and the layout does
// not print is not something the page says, and it is not something a
// chatbot can say either.
//
// What a visitor cannot open is not read: a page for members or outside its
// publish window, a record that is only in the draft, one the listing's
// conditions leave out, a key two records share (the route answers it with
// neither), and an address that a redirect, a page of the same name or
// another of the site's routes answers instead.
//
// # What it costs
//
// Every record is drawn once for what it depends on, not once per question:
// the published content, the records, the pages a visitor can open, the
// minute when a listing reads the clock, and the payment links behind a Buy
// button. The chatbots and the search index share the set. It is bounded by
// maxRecordPages, in page order and then in each listing's own, so which
// records are read is the same every time.

// maxRecordPages is how many records' pages the chatbots and site search
// read. A site with more answers about the first this many, in the order
// its listings keep them.
const maxRecordPages = 1000

// maxRecordWords is how much of one record's page is read.
const maxRecordWords = 2000

// recordSet is the records read for one set of things they depend on.
type recordSet struct {
	key   string
	pages map[string]any
}

// RecordPages is every record a visitor can open now at its own address,
// keyed by that address (page/key) and read the way its page shows it: what
// this site's chatbots and search know about records. For the command line
// and the admin, so a chatbot tried there answers as it answers visitors.
func (st *Site) RecordPages() (map[string]any, error) {
	visible, _, err := st.pages()
	if err != nil {
		return nil, err
	}
	recs, _ := st.recordPages(visible)
	// A copy of the set, which the chatbots and search go on sharing.
	return readable(map[string]any{}, recs), nil
}

// recordPages is the records a visitor can open, given the pages they can
// open now, and a name for what the set was read from that changes whenever
// the set could. Empty when no page stands for records.
func (st *Site) recordPages(visible map[string]any) (map[string]any, string) {
	if st.Listings == nil || st.Listings.Set == nil {
		return nil, ""
	}
	var stands []string
	for name, body := range visible {
		if d, ok := detailOf(body); ok && d.Declared() {
			stands = append(stands, name)
		}
	}
	if len(stands) == 0 {
		return nil, ""
	}
	sort.Strings(stands)
	members := st.membersShadow()
	key := st.recordKey(visible, members, stands)

	st.recordMu.Lock()
	defer st.recordMu.Unlock()
	if st.records != nil && st.records.key == key {
		return st.records.pages, key
	}
	pages := st.readRecords(visible, members, stands)
	st.records = &recordSet{key: key, pages: pages}
	return pages, key
}

// membersShadow is the pages for members a signed-in member opens now. The
// page handler answers their names before it looks for a record, so a
// record at the same address is not what anybody opens there.
func (st *Site) membersShadow() map[string]any {
	if !st.membersOn() {
		return nil
	}
	pages, err := st.membersOnlyPages()
	if err != nil {
		return nil
	}
	return pages
}

// recordKey names everything the records read for a visitor depend on.
func (st *Site) recordKey(visible, members map[string]any, stands []string) string {
	h := sha256.New()
	h.Write([]byte(st.Store.GetRef(st.ref())))
	h.Write([]byte{0})
	h.Write([]byte(st.Listings.At()))
	// The pages a visitor can open: a page standing for records opens or
	// closes with its publish window, and a page of the same name as a
	// record's address is answered instead of it.
	for _, set := range []map[string]any{visible, members} {
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		h.Write([]byte{1})
		for _, n := range names {
			h.Write([]byte(n + "\x00"))
		}
	}
	// The minute, when a listing keeps records by the clock: an event's page
	// goes when the event is over, with nothing published.
	for _, name := range stands {
		d, _ := detailOf(visible[name])
		if l, ok := st.Listings.Set.Get(d.Listing); ok && l.Timed() {
			h.Write([]byte("\x02" + listing.Now()))
			break
		}
	}
	// The payment links, which a record's Buy button and its price follow.
	if st.BuyTag != nil {
		h.Write([]byte("\x03" + st.BuyTag()))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// readRecords draws and reads every record a visitor can open.
func (st *Site) readRecords(visible, members map[string]any, stands []string) map[string]any {
	src := st.sources()
	// What visitors wrote under a page, and the times a booking has free,
	// are on it and are not what the site says about the record. Neither is
	// knowledge on an ordinary page either: a page's comments section names
	// a board, and its booking section a service.
	src.Thread, src.Booking = nil, nil

	mux := st.routes()
	out := map[string]any{}
	for _, name := range stands {
		body := visible[name]
		d, _ := detailOf(body)
		keys, rows, err := render.DetailRows(src, name, body, d)
		if err != nil {
			continue
		}
		shared := map[string]int{}
		for _, k := range keys {
			shared[k]++
		}
		for i, row := range rows {
			if len(out) == maxRecordPages {
				return out
			}
			key := keys[i]
			addr := name + "/" + key
			if !st.recordOpens(mux, addr, key, shared[key], visible, members) {
				continue
			}
			page, err := st.detailBody(src, name, body, row, nil)
			if err != nil {
				continue
			}
			title, text := readPage(page)
			if text == "" {
				continue
			}
			out[addr] = map[string]any{"title": title, "body": text}
		}
	}
	return out
}

// recordOpens says whether a visitor asking for a record's address gets the
// record's page, the way the site answers it: by page() and not by a route
// of its own, such as /media/ or /book/; then a redirect first, a page of
// that name for anybody or for members next, and only then the record,
// which the route finds by a key naming one record and fitting in one
// segment.
func (st *Site) recordOpens(mux *http.ServeMux, addr, key string, records int,
	visible, members map[string]any) bool {

	if records != 1 || key == "" || strings.ContainsAny(key, "/?#") {
		// Not a link anything here would write either: see recordLink.
		return false
	}
	ask := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/" + addr}}
	if _, pattern := mux.Handler(ask); pattern != "/" {
		return false
	}
	if _, moved := st.Redirects.Lookup("/" + addr); moved {
		return false
	}
	if _, page := visible[addr]; page {
		return false
	}
	_, forMembers := members[addr]
	return !forMembers
}

// What a visitor reads on a page.

// unread are elements whose content is not what the page says to somebody
// reading it: code, styling, what a browser draws rather than says, what
// somebody fills in, and the navigation, which is the same on every page.
var unread = map[string]bool{
	"head": true, "script": true, "style": true, "template": true,
	"noscript": true, "svg": true, "math": true, "iframe": true,
	"object": true, "canvas": true, "video": true, "audio": true,
	"form": true, "button": true, "select": true, "textarea": true,
	"dialog": true, "nav": true,
}

// around are the parts of a page around its content, left out when the
// page does not say where its content is with <main>.
var around = map[string]bool{"header": true, "footer": true, "aside": true}

// rawText are elements whose content is not markup, so it is skipped to
// their closing tag rather than read for tags.
var rawText = map[string]bool{"script": true, "style": true, "textarea": true, "title": true}

// voidTags have no closing tag.
var voidTags = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "link": true, "meta": true,
	"source": true, "track": true, "wbr": true,
}

// paragraphTags end the words before them and start new ones.
var paragraphTags = map[string]bool{
	"p": true, "div": true, "section": true, "article": true, "main": true,
	"header": true, "footer": true, "aside": true, "li": true, "ul": true,
	"ol": true, "dl": true, "dt": true, "dd": true, "table": true, "tr": true,
	"blockquote": true, "figure": true, "figcaption": true, "pre": true,
	"br": true, "hr": true, "address": true, "caption": true,
	"details": true, "summary": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
}

// readPage reads a rendered page as a visitor reads it: its first heading
// as its title, and its words as paragraphs, with a heading as "## " and a
// term beside what it means. Only what is inside <main> when the page has
// one, and otherwise its body less what is around the content.
//
// Nothing inside a tag is read. An attribute is not something the page
// says to somebody reading it, and an address, a picture's file or a value
// a layout tucked into one is exactly what a record's page shows nobody.
func readPage(page string) (title, text string) {
	lower := lowerASCII(page)
	r := &pageReader{hasMain: hasTag(lower, "main"), hasBody: hasTag(lower, "body")}
	r.scan(page, lower)
	r.flush()
	if r.term != "" {
		r.add(sentence(r.term))
	}
	title = r.title
	if title == "" {
		title = docTitle(page, lower)
	}
	return title, strings.Join(r.paras, "\n\n")
}

// pageReader is one reading of a page.
type pageReader struct {
	hasMain, hasBody bool
	// open is the elements being read inside, innermost last.
	open []string
	// skip is the element whose content is being left out, and depth how
	// many of it are open inside itself.
	skip  string
	depth int
	// cur is the words being read, and kind the element they are in: a
	// heading, a term or what it means, or a paragraph.
	cur  strings.Builder
	kind string
	// term is a term waiting for what it means.
	term  string
	title string
	paras []string
	words int
}

func (r *pageReader) scan(page, lower string) {
	for i := 0; i < len(page); {
		if page[i] != '<' {
			j := strings.IndexByte(page[i:], '<')
			if j < 0 {
				j = len(page) - i
			}
			r.textRun(page[i : i+j])
			i += j
			continue
		}
		if strings.HasPrefix(page[i:], "<!--") {
			end := strings.Index(page[i+4:], "-->")
			if end < 0 {
				return
			}
			i += 4 + end + 3
			continue
		}
		// A tag runs to the first > outside quotes.
		j, quote := i+1, byte(0)
		for ; j < len(page); j++ {
			c := page[j]
			if quote != 0 {
				if c == quote {
					quote = 0
				}
				continue
			}
			if c == '"' || c == '\'' {
				quote = c
			} else if c == '>' {
				break
			}
		}
		if j >= len(page) {
			return
		}
		raw := lower[i+1 : j]
		i = j + 1
		name, closing := tagName(raw)
		if name == "" {
			continue
		}
		if !closing && rawText[name] && !strings.HasSuffix(raw, "/") {
			// Its content is not markup: on to its closing tag.
			end := strings.Index(lower[i:], "</"+name)
			if end < 0 {
				return
			}
			i += end
			continue
		}
		r.tag(name, raw, closing)
	}
}

// tagName is a tag's element name, lower case, and whether it closes one.
func tagName(raw string) (string, bool) {
	if strings.HasPrefix(raw, "!") || strings.HasPrefix(raw, "?") {
		return "", false
	}
	closing := strings.HasPrefix(raw, "/")
	raw = strings.TrimPrefix(raw, "/")
	end := strings.IndexAny(raw, " \t\r\n/")
	if end < 0 {
		end = len(raw)
	}
	return raw[:end], closing
}

func (r *pageReader) tag(name, raw string, closing bool) {
	selfClosing := voidTags[name] || strings.HasSuffix(raw, "/")
	if r.skip != "" {
		if name == r.skip && !selfClosing {
			if closing {
				r.depth--
			} else {
				r.depth++
			}
			if r.depth == 0 {
				r.skip = ""
			}
		}
		return
	}
	if closing {
		if paragraphTags[name] {
			r.flush()
		}
		for i := len(r.open) - 1; i >= 0; i-- {
			if r.open[i] == name {
				r.open = r.open[:i]
				break
			}
		}
		if (name == "td" || name == "th") && r.reading() {
			r.cur.WriteString(" · ")
		}
		return
	}
	if !selfClosing && (unread[name] || hidden(raw) || !r.hasMain && around[name]) {
		r.flush()
		r.skip, r.depth = name, 1
		return
	}
	if paragraphTags[name] {
		r.flush()
		switch {
		case len(name) == 2 && name[0] == 'h' && name[1] >= '1' && name[1] <= '6':
			r.kind = name
		case name == "dt" || name == "dd":
			r.kind = name
		}
	}
	if !selfClosing {
		r.open = append(r.open, name)
	}
}

// hidden says an element is not shown: it has the hidden attribute, or it
// is taken away from a screen reader as well.
func hidden(raw string) bool {
	i := strings.IndexAny(raw, " \t\r\n")
	if i < 0 {
		return false
	}
	s := raw[i:]
	for {
		s = strings.TrimLeft(s, " \t\r\n/")
		if s == "" {
			return false
		}
		end := strings.IndexAny(s, " \t\r\n=/")
		if end < 0 {
			end = len(s)
		}
		name, value := s[:end], ""
		s = strings.TrimLeft(s[end:], " \t\r\n")
		if strings.HasPrefix(s, "=") {
			s = strings.TrimLeft(s[1:], " \t\r\n")
			if s != "" && (s[0] == '"' || s[0] == '\'') {
				q := s[0]
				if j := strings.IndexByte(s[1:], q); j >= 0 {
					value, s = s[1:1+j], s[2+j:]
				} else {
					value, s = s[1:], ""
				}
			} else {
				j := strings.IndexAny(s, " \t\r\n")
				if j < 0 {
					j = len(s)
				}
				value, s = s[:j], s[j:]
			}
		}
		if name == "hidden" || name == "aria-hidden" && strings.TrimSpace(value) == "true" {
			return true
		}
	}
}

// textRun takes the text between two tags.
func (r *pageReader) textRun(t string) {
	if r.skip != "" || !r.reading() {
		return
	}
	r.cur.WriteString(html.UnescapeString(t))
	r.cur.WriteByte(' ')
}

// reading says whether text here is the page's content: inside <main> when
// the page has one, and otherwise inside its body, or anywhere in a page
// that is only a body's worth of markup.
func (r *pageReader) reading() bool {
	if !r.hasMain && !r.hasBody {
		return true
	}
	want := "body"
	if r.hasMain {
		want = "main"
	}
	for _, o := range r.open {
		if o == want {
			return true
		}
	}
	return false
}

// flush ends the words being read.
func (r *pageReader) flush() {
	t := strings.Join(strings.Fields(r.cur.String()), " ")
	t = strings.TrimSpace(strings.TrimSuffix(t, "·"))
	kind := r.kind
	r.cur.Reset()
	r.kind = ""
	if t == "" {
		return
	}
	switch {
	case kind == "dt":
		if r.term != "" {
			r.add(sentence(r.term))
		}
		r.term = t
		return
	case kind != "" && kind[0] == 'h':
		if r.term != "" {
			r.add(sentence(r.term))
			r.term = ""
		}
		if kind == "h1" && r.title == "" {
			r.title = t
			return
		}
		r.add("## " + t)
		return
	}
	if r.term != "" {
		t = r.term + ": " + t
		r.term = ""
	}
	r.add(sentence(t))
}

// add keeps a paragraph, while there is room for it.
func (r *pageReader) add(p string) {
	n := len(strings.Fields(p))
	if r.words+n > maxRecordWords {
		return
	}
	r.words += n
	r.paras = append(r.paras, p)
}

// sentence ends words that do not end themselves, so a value read beside
// its term is one sentence and not the start of the next.
func sentence(t string) string {
	last, _ := utf8.DecodeLastRuneInString(t)
	if strings.ContainsRune(".!?:;…", last) {
		return t
	}
	return t + "."
}

// lowerASCII lower-cases the ASCII letters of a page and leaves every other
// byte where it was, so an offset in one is the same offset in the other:
// tags are found in the lower-cased page and text is read from the page.
// strings.ToLower does not keep offsets: the Kelvin sign is three bytes and
// its lower case one, and a record carrying one would have been read from
// the wrong place, or past the end.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// hasTag says whether a page has an element, by its opening tag.
func hasTag(lower, name string) bool {
	for i := 0; ; {
		j := strings.Index(lower[i:], "<"+name)
		if j < 0 {
			return false
		}
		i += j + 1 + len(name)
		if i >= len(lower) {
			return false
		}
		if c := lower[i]; c == '>' || c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '/' {
			return true
		}
	}
}

// docTitle is the page's <title>, for a page with no heading of its own.
func docTitle(page, lower string) string {
	i := strings.Index(lower, "<title")
	if i < 0 {
		return ""
	}
	open := strings.IndexByte(lower[i:], '>')
	if open < 0 {
		return ""
	}
	start := i + open + 1
	end := strings.Index(lower[start:], "</title")
	if end < 0 {
		return ""
	}
	return strings.Join(strings.Fields(html.UnescapeString(page[start:start+end])), " ")
}

// readable is the pages and the records' pages in one set.
//
// A record is in its set only where it is what a visitor opens at its
// address (recordOpens), so a page of the same name in a wider set is one
// nobody opens there, such as a page whose window has closed. The record
// is what search and a chatbot answer with at that address, and the page
// does not come back through it.
func readable(pages, records map[string]any) map[string]any {
	if len(records) == 0 {
		return pages
	}
	out := make(map[string]any, len(pages)+len(records))
	for n, b := range pages {
		out[n] = b
	}
	for n, b := range records {
		out[n] = b
	}
	return out
}

// withRecords is the pages a visitor can open now and the records they can
// open, in one set: what search answers from and shows.
func (st *Site) withRecords(visible map[string]any) map[string]any {
	records, _ := st.recordPages(visible)
	return readable(visible, records)
}
