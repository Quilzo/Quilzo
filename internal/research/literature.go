// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package research

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Literature from open indexes.
//
// A citation is added by its identifier, never by a title a model
// remembers: a DOI, a PubMed ID, an arXiv ID or an OpenAlex ID. It is
// looked up in OpenAlex (which also holds PubMed's and arXiv's records),
// in Crossref for a DOI OpenAlex does not have, and in arXiv's own index
// for an arXiv ID, and only a work an index returned is kept. What the
// index holds of the work's abstract is kept with it, because that is
// what a sentence citing it is checked against.

// Getter fetches a URL and says what the server answered. The caller's
// client, so the network rules are its.
type Getter func(ctx context.Context, url string) (body []byte, status int, err error)

// Index is the open indexes, at their addresses.
type Index struct {
	Get Getter
	// The bases, for a test or a mirror; empty is the public one.
	OpenAlex, Crossref, Arxiv string
	// Mailto is sent to OpenAlex and Crossref, which ask for a contact.
	Mailto string
}

func (ix Index) base(set, def string) string {
	if set != "" {
		return strings.TrimSuffix(set, "/")
	}
	return def
}

// Identifier is a work's identifier, as given.
type Identifier struct {
	Kind  string // doi, pmid, arxiv, openalex
	Value string
}

func (id Identifier) String() string { return id.Kind + ":" + id.Value }

var (
	reDOI      = regexp.MustCompile(`^10\.\d{4,9}/\S{1,300}$`)
	rePMID     = regexp.MustCompile(`^\d{1,9}$`)
	reArxiv    = regexp.MustCompile(`^(\d{4}\.\d{4,5}|[a-z-]+(\.[A-Z]{2})?/\d{7})(v\d+)?$`)
	reOpenAlex = regexp.MustCompile(`^W\d{1,12}$`)
)

// ParseIdentifier reads doi:10…, a doi.org address, pmid:…, arxiv:… or an
// OpenAlex W… identifier.
func ParseIdentifier(s string) (Identifier, error) {
	s = strings.TrimSpace(s)
	low := strings.ToLower(s)
	for _, p := range []string{"https://doi.org/", "http://doi.org/", "https://dx.doi.org/", "doi:"} {
		if strings.HasPrefix(low, p) {
			s, low = s[len(p):], low[len(p):]
			if reDOI.MatchString(s) {
				return Identifier{"doi", strings.ToLower(s)}, nil
			}
			return Identifier{}, fmt.Errorf("%q is not a DOI", s)
		}
	}
	switch {
	case reDOI.MatchString(s):
		return Identifier{"doi", low}, nil
	case strings.HasPrefix(low, "pmid:") && rePMID.MatchString(strings.TrimSpace(s[5:])):
		return Identifier{"pmid", strings.TrimSpace(s[5:])}, nil
	case strings.HasPrefix(low, "arxiv:") && reArxiv.MatchString(strings.TrimSpace(s[6:])):
		return Identifier{"arxiv", strings.TrimSpace(s[6:])}, nil
	case strings.HasPrefix(low, "openalex:") && reOpenAlex.MatchString(strings.TrimSpace(s[9:])):
		return Identifier{"openalex", strings.TrimSpace(s[9:])}, nil
	case reOpenAlex.MatchString(s):
		return Identifier{"openalex", s}, nil
	}
	return Identifier{}, fmt.Errorf("%q is not an identifier this resolves: doi:10…, pmid:…, arxiv:… or an OpenAlex W…", s)
}

// ErrNotFound is an identifier no index has.
var ErrNotFound = errors.New("no index has a work with that identifier")

// Resolve looks a work up.
func (ix Index) Resolve(ctx context.Context, id Identifier) (Source, error) {
	if ix.Get == nil {
		return Source{}, errors.New("no way to reach the indexes here")
	}
	switch id.Kind {
	case "arxiv":
		return ix.arxiv(ctx, id)
	case "doi":
		src, err := ix.openAlex(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return ix.crossref(ctx, id)
		}
		return src, err
	}
	return ix.openAlex(ctx, id)
}

func (ix Index) getJSON(ctx context.Context, u string, v any) error {
	body, status, err := ix.Get(ctx, u)
	switch {
	case err != nil:
		return err
	case status == 404:
		return ErrNotFound
	case status != 200:
		return fmt.Errorf("the index answered %d", status)
	}
	return json.Unmarshal(body, v)
}

type openAlexWork struct {
	ID          string `json:"id"`
	DOI         string `json:"doi"`
	Title       string `json:"display_name"`
	Year        int    `json:"publication_year"`
	CitedBy     int    `json:"cited_by_count"`
	Authorships []struct {
		Author struct {
			Name string `json:"display_name"`
		} `json:"author"`
	} `json:"authorships"`
	PrimaryLocation *struct {
		Landing string `json:"landing_page_url"`
		Source  *struct {
			Name string `json:"display_name"`
		} `json:"source"`
	} `json:"primary_location"`
	Abstract map[string][]int `json:"abstract_inverted_index"`
}

// abstract puts an inverted index back into words.
func (w openAlexWork) abstract() string {
	type at struct {
		pos  int
		word string
	}
	var words []at
	for word, positions := range w.Abstract {
		for _, p := range positions {
			if p >= 0 && p < 20_000 {
				words = append(words, at{p, word})
			}
		}
	}
	sort.Slice(words, func(i, j int) bool { return words[i].pos < words[j].pos })
	parts := make([]string, len(words))
	for i, w := range words {
		parts[i] = w.word
	}
	return strings.Join(parts, " ")
}

func (w openAlexWork) source(id Identifier) Source {
	s := Source{ID: id.String(), Title: cleanText(w.Title), Year: w.Year, Abstract: limit(cleanText(w.abstract()), 8000),
		Resolver: "OpenAlex", DOI: strings.ToLower(strings.TrimPrefix(w.DOI, "https://doi.org/"))}
	for _, a := range w.Authorships {
		if n := cleanText(a.Author.Name); n != "" && len(s.Authors) < 50 {
			s.Authors = append(s.Authors, n)
		}
	}
	if pl := w.PrimaryLocation; pl != nil {
		if pl.Source != nil {
			s.Venue = cleanText(pl.Source.Name)
		}
		s.URL = pl.Landing
	}
	if s.DOI != "" {
		s.URL = "https://doi.org/" + s.DOI
	}
	if s.URL == "" {
		s.URL = w.ID
	}
	return s
}

func (ix Index) openAlexQuery() url.Values {
	q := url.Values{}
	if ix.Mailto != "" {
		q.Set("mailto", ix.Mailto)
	}
	return q
}

func (ix Index) openAlex(ctx context.Context, id Identifier) (Source, error) {
	base := ix.base(ix.OpenAlex, "https://api.openalex.org")
	q := ix.openAlexQuery()
	var w openAlexWork
	switch id.Kind {
	case "doi":
		q.Set("filter", "doi:"+id.Value)
		var list struct {
			Results []openAlexWork `json:"results"`
		}
		if err := ix.getJSON(ctx, base+"/works?"+q.Encode(), &list); err != nil {
			return Source{}, err
		}
		if len(list.Results) == 0 {
			return Source{}, ErrNotFound
		}
		w = list.Results[0]
	case "pmid", "openalex":
		path := "/works/" + id.Value
		if id.Kind == "pmid" {
			path = "/works/pmid:" + id.Value
		}
		if err := ix.getJSON(ctx, base+path+"?"+q.Encode(), &w); err != nil {
			return Source{}, err
		}
	default:
		return Source{}, fmt.Errorf("OpenAlex does not resolve %s", id.Kind)
	}
	if strings.TrimSpace(w.Title) == "" {
		return Source{}, ErrNotFound
	}
	return w.source(id), nil
}

func (ix Index) crossref(ctx context.Context, id Identifier) (Source, error) {
	base := ix.base(ix.Crossref, "https://api.crossref.org")
	u := base + "/works/" + url.PathEscape(id.Value)
	if ix.Mailto != "" {
		u += "?mailto=" + url.QueryEscape(ix.Mailto)
	}
	var doc struct {
		Message struct {
			Title  []string `json:"title"`
			Author []struct {
				Given  string `json:"given"`
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"author"`
			Issued struct {
				Parts [][]int `json:"date-parts"`
			} `json:"issued"`
			Container []string `json:"container-title"`
			Abstract  string   `json:"abstract"`
			DOI       string   `json:"DOI"`
		} `json:"message"`
	}
	if err := ix.getJSON(ctx, u, &doc); err != nil {
		return Source{}, err
	}
	m := doc.Message
	if len(m.Title) == 0 || strings.TrimSpace(m.Title[0]) == "" {
		return Source{}, ErrNotFound
	}
	s := Source{ID: id.String(), DOI: strings.ToLower(m.DOI), Title: cleanText(m.Title[0]),
		Abstract: limit(cleanText(m.Abstract), 8000), Resolver: "Crossref", URL: "https://doi.org/" + id.Value}
	for _, a := range m.Author {
		n := strings.TrimSpace(a.Given + " " + a.Family)
		if n == "" {
			n = a.Name
		}
		if n = cleanText(n); n != "" && len(s.Authors) < 50 {
			s.Authors = append(s.Authors, n)
		}
	}
	if len(m.Issued.Parts) > 0 && len(m.Issued.Parts[0]) > 0 {
		s.Year = m.Issued.Parts[0][0]
	}
	if len(m.Container) > 0 {
		s.Venue = cleanText(m.Container[0])
	}
	return s, nil
}

func (ix Index) arxiv(ctx context.Context, id Identifier) (Source, error) {
	base := ix.base(ix.Arxiv, "https://export.arxiv.org")
	body, status, err := ix.Get(ctx, base+"/api/query?id_list="+url.QueryEscape(id.Value))
	switch {
	case err != nil:
		return Source{}, err
	case status != 200:
		return Source{}, fmt.Errorf("arXiv answered %d", status)
	}
	var feed struct {
		Entries []struct {
			ID        string `xml:"id"`
			Title     string `xml:"title"`
			Summary   string `xml:"summary"`
			Published string `xml:"published"`
			Authors   []struct {
				Name string `xml:"name"`
			} `xml:"author"`
			DOI string `xml:"http://arxiv.org/schemas/atom doi"`
		} `xml:"entry"`
	}
	if err := xml.Unmarshal(body, &feed); err != nil {
		return Source{}, fmt.Errorf("arXiv's answer was not its feed: %w", err)
	}
	if len(feed.Entries) == 0 || strings.Contains(feed.Entries[0].ID, "/api/errors") ||
		strings.TrimSpace(feed.Entries[0].Title) == "" {
		return Source{}, ErrNotFound
	}
	e := feed.Entries[0]
	s := Source{ID: id.String(), Title: cleanText(e.Title), Abstract: limit(cleanText(e.Summary), 8000),
		Resolver: "arXiv", Venue: "arXiv", URL: "https://arxiv.org/abs/" + id.Value, DOI: strings.ToLower(e.DOI)}
	if t, err := time.Parse(time.RFC3339, e.Published); err == nil {
		s.Year = t.Year()
	}
	for _, a := range e.Authors {
		if n := cleanText(a.Name); n != "" && len(s.Authors) < 50 {
			s.Authors = append(s.Authors, n)
		}
	}
	return s, nil
}

// Candidate is a work a search found.
type Candidate struct {
	ID      string
	Title   string
	Year    int
	Authors []string
	Venue   string
	CitedBy int
}

// Search finds works in OpenAlex, most relevant first. It adds nothing: a
// person or an agent cites what it chooses, by identifier.
func (ix Index) Search(ctx context.Context, query string, n int) ([]Candidate, error) {
	if ix.Get == nil {
		return nil, errors.New("no way to reach the indexes here")
	}
	query = strings.TrimSpace(query)
	if query == "" || len(query) > 300 {
		return nil, errors.New("a search is between 1 and 300 characters")
	}
	if n <= 0 || n > 25 {
		n = 10
	}
	q := ix.openAlexQuery()
	q.Set("search", query)
	q.Set("per-page", strconv.Itoa(n))
	var list struct {
		Results []openAlexWork `json:"results"`
	}
	if err := ix.getJSON(ctx, ix.base(ix.OpenAlex, "https://api.openalex.org")+"/works?"+q.Encode(), &list); err != nil {
		return nil, err
	}
	var out []Candidate
	for _, w := range list.Results {
		id := "openalex:" + strings.TrimPrefix(w.ID, "https://openalex.org/")
		if w.DOI != "" {
			id = "doi:" + strings.ToLower(strings.TrimPrefix(w.DOI, "https://doi.org/"))
		}
		src := w.source(Identifier{})
		out = append(out, Candidate{ID: id, Title: src.Title, Year: w.Year, Authors: src.Authors,
			Venue: src.Venue, CitedBy: w.CitedBy})
	}
	return out, nil
}

var reTags = regexp.MustCompile(`<[^>]{0,200}>`)

// cleanText is an index's text as plain words: markup out, entities read,
// space collapsed.
func cleanText(s string) string {
	s = html.UnescapeString(reTags.ReplaceAllString(s, " "))
	return strings.Join(strings.Fields(s), " ")
}

func limit(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := strings.LastIndexFunc(s[:n], unicode.IsSpace)
	if cut < n/2 {
		cut = n
	}
	return s[:cut] + "…"
}

// SuggestKey is a key for a work: its first author's family name and its
// year, made unique among the keys taken.
func SuggestKey(s Source, taken map[string]bool) string {
	base := "work"
	if len(s.Authors) > 0 {
		fields := strings.Fields(s.Authors[0])
		var b strings.Builder
		for _, r := range strings.ToLower(fields[len(fields)-1]) {
			if r >= 'a' && r <= 'z' {
				b.WriteRune(r)
			}
		}
		if b.Len() > 0 {
			base = b.String()
		}
	}
	if len(base) > 30 {
		base = base[:30]
	}
	if s.Year != 0 {
		base += strconv.Itoa(s.Year)
	}
	key := base
	for i := 0; taken[key]; i++ {
		key = base + string(rune('a'+i%26))
		if i >= 26 {
			key = base + "-" + strconv.Itoa(i)
		}
	}
	return key
}
