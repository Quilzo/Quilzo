// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package export

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/yamlite"
)

// Reading an export back.
//
// An export is proved by a round trip: export a site, read what came out, and
// it must be the same site. The reader lived in internal/importer, beside the
// readers of other systems' files, and it read this package's Markdown with
// the flat front matter reader written for Jekyll and Hugo. So a number, a
// yes or no and a list came back as text, a marked export's front matter was
// read as its body (the banner is the first line, not ---), and a record's
// file came back as a page named after its title. The writer and its reader
// are kept together here, so the round trip is one package's promise and the
// importer reads this package's JSON through it.

// MaxPages bounds how many pages, and how many records, one file gives.
const MaxPages = 20000

// Page is one page read back.
type Page struct {
	Name    string         `json:"name"`
	Fields  map[string]any `json:"fields"`
	Dropped []string       `json:"dropped,omitempty"`
}

// Content is what one file of an export holds: pages, or the records of one
// collection, never both.
type Content struct {
	Pages []Page
	// Collection names the collection Records belong to, empty when the file
	// carried pages.
	Collection string
	Records    []Record
	// Skipped says what was not read, and why. A reader that quietly drops
	// half a file is worse than one that refuses, because the loss is found
	// months later by a reader.
	Skipped []string
}

// Read reads one file an export wrote. JSON is content/pages.json (or an array
// of pages, the shape headless systems write) or a collection's file; Markdown,
// which a crate also holds, is one page, or one record when its front matter
// names its id and its collection.
func Read(f Format, body []byte) (*Content, error) {
	switch f {
	case JSON:
		return readJSON(body)
	case Markdown, ROCrate:
		return readMarkdown(body)
	}
	return nil, fmt.Errorf("%s is not read back here: a WordPress export is read "+
		"by `quilzo import` and `quilzo site import`", f)
}

// ReadCollection reads the file the JSON export writes for a collection.
//
// It returns false rather than an error for anything else, so the page shapes
// still get their turn. It only claims a document that has both keys and an
// array of objects carrying ids: a document with a stray "collection" field is
// not one of these.
func ReadCollection(body []byte) (*Content, bool) {
	var doc struct {
		Collection string `json:"collection"`
		Records    []struct {
			ID      string         `json:"id"`
			Fields  map[string]any `json:"fields"`
			Created int64          `json:"created"`
			Updated int64          `json:"updated"`
		} `json:"records"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	if doc.Collection == "" || doc.Records == nil {
		return nil, false
	}

	c := &Content{Collection: doc.Collection}
	for i, r := range doc.Records {
		if len(c.Records) >= MaxPages {
			c.Skipped = append(c.Skipped, "stopped at the record limit")
			break
		}
		if r.ID == "" {
			// Refused rather than given a fresh id. A record whose identity
			// was invented on import is no longer the record anything else
			// links to, and the broken relation is found by a reader.
			c.Skipped = append(c.Skipped, fmt.Sprintf(
				"record %d has no id, so nothing that links to it would still "+
					"find it", i+1))
			continue
		}
		if r.Fields == nil {
			c.Skipped = append(c.Skipped, fmt.Sprintf(
				"record %q has no fields", r.ID))
			continue
		}
		c.Records = append(c.Records, Record{
			ID: r.ID, Fields: r.Fields, Created: r.Created, Updated: r.Updated,
		})
	}
	sort.Slice(c.Records, func(i, j int) bool {
		return c.Records[i].ID < c.Records[j].ID
	})
	return c, true
}

func readJSON(body []byte) (*Content, error) {
	// A collections file first, because it is unambiguous: nothing else this
	// reads has a top-level "collection" name beside a "records" array.
	// Checked before the page shapes so a catalogue is never read as a set of
	// pages named "collection" and "records".
	if c, ok := ReadCollection(body); ok {
		return c, nil
	}

	c := &Content{}
	// Every page is numbered from the name it shares with one before it, as
	// the other formats are. Nothing was: two pages titled "Same" read as two
	// pages named "same", and both imports write pages by name, so the second
	// replaced the first and a page was lost without a word.
	named := NewNames()

	var asArray []map[string]any
	if err := json.Unmarshal(body, &asArray); err == nil {
		for i, item := range asArray {
			if len(c.Pages) >= MaxPages {
				c.Skipped = append(c.Skipped, "stopped at the page limit")
				break
			}
			// An array carries no names, so "page-3" is a last resort and a
			// title is a better guess than a position.
			p, err := ReadPage(item, fmt.Sprintf("page-%d", i+1), false)
			if err != nil {
				c.Skipped = append(c.Skipped, fmt.Sprintf("item %d: %v", i+1, err))
				continue
			}
			c.Pages = append(c.Pages, named.page(p))
		}
		if len(c.Pages) == 0 {
			return nil, fmt.Errorf("the array contained no importable pages")
		}
		return c, nil
	}

	var asMap map[string]any
	if err := json.Unmarshal(body, &asMap); err != nil {
		return nil, fmt.Errorf("this is not JSON: %w", err)
	}
	// A map of name -> page is what the export writes.
	//
	// Its keys are unique, but two of them can still come to one name
	// ("About Us" and "about-us"). A key that is already its own name claims
	// it first, so the page that was exactly where it said keeps its place
	// and the other is numbered; each group goes in key order, so which one
	// is numbered does not change from one run to the next.
	keys := make([]string, 0, len(asMap))
	for name := range asMap {
		keys = append(keys, name)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		if a, b := Slug(keys[i]) == keys[i], Slug(keys[j]) == keys[j]; a != b {
			return a
		}
		return keys[i] < keys[j]
	})
	for _, name := range keys {
		v := asMap[name]
		item, ok := v.(map[string]any)
		if !ok {
			c.Skipped = append(c.Skipped, fmt.Sprintf(
				"%q is a %T, not a page object", name, v))
			continue
		}
		// A map's key is the page's identity, not a fallback.
		//
		// This is what makes an export re-importable. The exporter writes
		// {"index": {"title": "Home"}}, and preferring the title over the key
		// imported it as "home" — so a round trip renamed every page whose
		// title was not its name, and the front page in particular became
		// unreachable because / serves whatever is called "index".
		//
		// "there is no lock-in here, and this is how it is proved" is a claim
		// this tool makes in its own help text. It has to survive the round
		// trip exactly, or it is not proved.
		p, err := ReadPage(item, name, true)
		if err != nil {
			c.Skipped = append(c.Skipped, fmt.Sprintf("%q: %v", name, err))
			continue
		}
		c.Pages = append(c.Pages, named.page(p))
	}
	sort.Slice(c.Pages, func(i, j int) bool {
		return c.Pages[i].Name < c.Pages[j].Name
	})
	if len(c.Pages) == 0 {
		return nil, fmt.Errorf("no importable pages found")
	}
	return c, nil
}

// ReadPage reads one page object. authoritative says whether the given name
// is the page's identity: true when it came from a map key or a file's place,
// false when it is a positional placeholder for an array element.
func ReadPage(item map[string]any, given string, authoritative bool) (Page, error) {
	fields := map[string]any{}
	var dropped []string
	for k, v := range item {
		switch v.(type) {
		case string, float64, bool, nil:
			fields[k] = v
		case []any:
			fields[k] = v
		default:
			// A nested object has nowhere to go: content types are flat, which
			// is what keeps validation bounded. Reported rather than flattened
			// into keys nobody declared.
			dropped = append(dropped, k+" (nested object)")
		}
	}
	name := ""
	if authoritative {
		name = Slug(given)
	}
	if name == "" {
		name = Slug(str(fields["slug"]))
	}
	if name == "" {
		name = Slug(str(fields["name"]))
	}
	if name == "" {
		name = Slug(str(fields["title"]))
	}
	if name == "" {
		name = Slug(given)
	}
	if name == "" {
		return Page{}, fmt.Errorf("no usable name")
	}
	sort.Strings(dropped)
	return Page{Name: name, Fields: fields, Dropped: dropped}, nil
}

// readMarkdown reads one Markdown file this package wrote.
//
// The front matter is read by yamlite, the reader agent definitions and a
// folder of Markdown are read by, so what was written as a number, a yes or no,
// a list or a map comes back as one. It refuses anchors, aliases and tags, and
// a key given twice, rather than interpreting them: a file this package wrote
// has none, so one that does is not one of these.
func readMarkdown(body []byte) (*Content, error) {
	text := strings.TrimPrefix(strings.ReplaceAll(string(body), "\r\n", "\n"), "\ufeff")
	text = unmark(text)
	if !strings.HasPrefix(text, "---\n") {
		return nil, errors.New("this has no front matter, so it is not a page " +
			"or record an export wrote")
	}
	inner := "\n" + text[len("---\n"):]
	head, rest, ok := strings.Cut(inner, "\n---\n")
	if !ok {
		head, ok = strings.CutSuffix(inner, "\n---")
		if !ok {
			return nil, errors.New("the front matter has no end")
		}
	}
	// The export puts a blank line after the front matter and ends a body
	// with a line break when it had none: both are its own, not the page's.
	rest = strings.TrimSuffix(strings.TrimPrefix(rest, "\n"), "\n")

	v, err := yamlite.Parse([]byte(head))
	if err != nil {
		return nil, fmt.Errorf("the front matter does not read: %w", err)
	}
	front, ok := v.(map[string]any)
	if !ok && v != nil {
		return nil, errors.New("the front matter is not a set of keys")
	}
	if front == nil {
		front = map[string]any{}
	}
	if rest != "" {
		front["body"] = rest
	}

	// A record says which it is and where it belongs, which a page never
	// does. Read as a page, a product came back as a page named after its
	// title, with its id and collection as two fields nobody declared.
	if id, coll := str(front["id"]), str(front["collection"]); id != "" && coll != "" {
		r := Record{ID: id}
		for k, at := range map[string]*int64{"created": &r.Created, "updated": &r.Updated} {
			if s := str(front[k]); s != "" {
				t, err := time.Parse(time.RFC3339, s)
				if err != nil {
					return nil, fmt.Errorf("record %q: %s is not a time: %q", id, k, s)
				}
				*at = t.Unix()
			}
			delete(front, k)
		}
		delete(front, "id")
		delete(front, "collection")
		r.Fields = front
		return &Content{Collection: coll, Records: []Record{r}}, nil
	}

	p, err := ReadPage(front, "", false)
	if err != nil {
		return nil, err
	}
	return &Content{Pages: []Page{p}}, nil
}

// unmark takes off the banner marked puts on a Markdown file: a line of its
// own at the top and at the foot. Anything else is returned as it was.
func unmark(text string) string {
	banner, rest, ok := strings.Cut(text, "\n\n")
	if !ok || banner == "" || banner == "---" || strings.Contains(banner, "\n") ||
		!strings.HasPrefix(rest, "---\n") {
		return text
	}
	if inner, ok := strings.CutSuffix(rest, "\n\n"+banner+"\n"); ok {
		return inner
	}
	return text
}

// ReadDir reads a whole export back into the Site it was made from: the pages
// and records under content/, when each page last changed, the redirects, and
// the marking. It returns what was not read beside it.
func ReadDir(fsys fs.FS) (Site, []string, error) {
	s := Site{Pages: map[string]any{}}
	var skipped []string
	named := NewNames()
	err := fs.WalkDir(fsys, "content", func(p string, d fs.DirEntry, err error) error {
		if err != nil && p == "content" && errors.Is(err, fs.ErrNotExist) {
			// Said below, in words, with what is missing.
			return nil
		}
		if err != nil || d.IsDir() {
			return err
		}
		var f Format
		switch path.Ext(p) {
		case ".json":
			f = JSON
		case ".md":
			f = Markdown
		default:
			skipped = append(skipped, p+": not a file this reads back")
			return nil
		}
		body, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		c, err := Read(f, body)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		for _, pg := range c.Pages {
			// A Markdown page's name is where its file is, as a map key is
			// in JSON: its own slug field can say something else.
			if f == Markdown {
				if n := Slug(strings.TrimSuffix(strings.TrimPrefix(p, "content/"), ".md")); n != "" {
					pg.Name = n
				}
			}
			pg = named.page(pg)
			s.Pages[pg.Name] = pg.Fields
			for _, d := range pg.Dropped {
				skipped = append(skipped, fmt.Sprintf("%s: page %s: %s", p, pg.Name, d))
			}
		}
		if c.Collection != "" {
			if s.Collections == nil {
				s.Collections = map[string][]Record{}
			}
			s.Collections[c.Collection] = append(s.Collections[c.Collection], c.Records...)
		}
		for _, k := range c.Skipped {
			skipped = append(skipped, p+": "+k)
		}
		return nil
	})
	if err != nil {
		return Site{}, skipped, err
	}
	for _, rs := range s.Collections {
		sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	}

	if body, err := fs.ReadFile(fsys, "last-changed.json"); err == nil {
		var when map[string]string
		if err := json.Unmarshal(body, &when); err != nil {
			return Site{}, skipped, fmt.Errorf("last-changed.json: %w", err)
		}
		s.Changed = map[string]time.Time{}
		for name, at := range when {
			t, err := time.Parse(time.RFC3339, at)
			if err != nil {
				skipped = append(skipped, fmt.Sprintf(
					"last-changed.json: %s: %q is not a time", name, at))
				continue
			}
			s.Changed[Slug(name)] = t
		}
	}
	if body, err := fs.ReadFile(fsys, "redirects.json"); err == nil {
		var doc struct {
			Redirects []Redirect `json:"redirects"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return Site{}, skipped, fmt.Errorf("redirects.json: %w", err)
		}
		s.Redirects = doc.Redirects
	}
	if body, err := fs.ReadFile(fsys, "CLASSIFICATION"); err == nil {
		s.Banner, _, _ = strings.Cut(string(body), "\n")
	}

	if len(s.Pages) == 0 && len(s.Collections) == 0 {
		return Site{}, skipped, errors.New("there are no pages or records under " +
			"content/, so this is not an export this program wrote")
	}
	return s, skipped, nil
}

// Slug is the name an import gives a page from a name it was handed: safe as a
// page name and readable as a URL. A page name becomes part of a URL and a key
// in the store, so it is constrained whatever the file said.
func Slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := true
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '-' || r == ' ' || r == '_' || r == '/' || r == '.':
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 80 {
		out = strings.Trim(out[:80], "-")
	}
	return out
}

// Names gives each page of an import a name no page before it has.
//
// A name taken is numbered from the name the pages share: same, same-2,
// same-3. Each used to be numbered from the name the one before it was given,
// so the thousandth "same" was same-2-3-4-…-1000, found by building every name
// before it: 10,000 same-titled items took seven minutes of CPU to import.
// next keeps, for a name taken, the number to try first, since every one
// below it is taken (as webimport's postSlugs keeps it).
type Names struct {
	taken map[string]bool
	next  map[string]int
}

// NewNames starts an import's names.
func NewNames() *Names {
	return &Names{taken: map[string]bool{}, next: map[string]int{}}
}

// Claim returns base, or base numbered if a page before it has that name.
func (n *Names) Claim(base string) string {
	name := base
	for k := max(2, n.next[base]); n.taken[name]; k++ {
		name = fmt.Sprintf("%s-%d", base, k)
		n.next[base] = k + 1
	}
	n.taken[name] = true
	return name
}

// page claims p's name, and when it had to be numbered its own slug field
// follows it: a page renamed so as not to replace another must not still
// claim the other's address.
func (n *Names) page(p Page) Page {
	name := n.Claim(p.Name)
	if name != p.Name {
		p.Name = name
		if _, ok := p.Fields["slug"].(string); ok {
			p.Fields["slug"] = name
		}
	}
	return p
}
