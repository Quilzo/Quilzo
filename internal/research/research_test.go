// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package research

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var day = time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)

func TestValuesAreWhatTheCodeWroteDown(t *testing.T) {
	vs, err := ReadValues([]byte(`{"mean_age": 41.25, "response_rate": {"value": 62.5, "unit": "%"}}`))
	if err != nil || len(vs) != 2 || vs[0].Name != "mean_age" || vs[1].Unit != "%" {
		t.Fatalf("%+v %v", vs, err)
	}
	for name, body := range map[string]string{
		"a name with capitals": `{"Mean": 1}`,
		"text":                 `{"mean": "41"}`,
		"a list":               `[1, 2]`,
	} {
		if _, err := ReadValues([]byte(body)); err == nil {
			t.Errorf("%s was read as values", name)
		}
	}
	if got := Format(62.5, "%"); got != "62.5%" {
		t.Errorf("%q", got)
	}
	if got := Format(1.0/3, "years"); got != "0.333333 years" {
		t.Errorf("%q", got)
	}
}

// A plan is registered once; after that it changes only by an amendment
// that says why, and says whether the data had been seen.
func TestAPlanChangesOnlyByAmendmentOnceRegistered(t *testing.T) {
	p := Project{Name: "trial", Question: "Does it work?"}
	if err := Register(&p, "dana", day); err == nil {
		t.Fatal("an empty plan was registered")
	}
	if _, err := SetPlan(&p, "Compare means with a t-test.", "dana", "", day); err != nil {
		t.Fatal(err)
	}
	if err := Register(&p, "dana", day); err != nil || !p.Plan.BeforeData || p.Plan.Digest != Digest(p.Plan.Text) {
		t.Fatalf("%+v %v", p.Plan, err)
	}
	if _, err := SetPlan(&p, "Compare medians instead.", "dana", "", day); err == nil {
		t.Fatal("a registered plan was changed without saying why")
	}
	p.DataSeen = day.Add(time.Hour)
	a, err := SetPlan(&p, "Compare medians instead.", "dana", "the outcome is skewed", day.Add(2*time.Hour))
	if err != nil || !a.AfterData || a.From == a.To || p.Plan.Digest != a.To || len(p.Amendments) != 1 {
		t.Fatalf("%+v %v", a, err)
	}
	if err := Register(&p, "dana", day); err == nil {
		t.Error("a plan was registered twice")
	}
}

func TestOnlyANumberACleanComputationWroteIsAClaim(t *testing.T) {
	p := Project{Name: "trial"}
	r := Run{ID: "r-20261014-0000abcd", Project: "trial", Values: []Value{{Name: "effect", Value: 0.42}}}
	c, err := Pin(&p, r, "effect", "dana", day)
	if err != nil || c.Value != 0.42 || len(p.Claims) != 1 {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := Pin(&p, r, "made_up", "dana", day); err == nil {
		t.Error("a value the computation never wrote was pinned")
	}
	r.Exit = 1
	if _, err := Pin(&p, r, "effect", "dana", day); err == nil {
		t.Error("a value from a failed computation was pinned")
	}
}

// Every number a report asserts is linked to a computation or stated as
// such; numbers that name things are left alone.
func TestEveryNumberInAReportIsLinkedOrFlagged(t *testing.T) {
	report := "## 2. Results\n\n" +
		"The effect was {{effect}} in {{= 120}} patients, and 37% improved (Figure 2, Table 1).\n" +
		"COVID-19 and p53 were measured; see `run 42` and https://doi.org/10.1000/xyz.\n\n" +
		"1. First item\n2. Second item, on the 3rd day\n"
	var numbers, claims, stated []string
	for _, para := range Parse(report) {
		for _, sg := range para.Segments {
			switch sg.Kind {
			case "number":
				numbers = append(numbers, sg.Text)
			case "claim":
				claims = append(claims, sg.Refs[0])
			case "stated":
				stated = append(stated, sg.Text)
			}
		}
	}
	if strings.Join(numbers, ",") != "37" || strings.Join(claims, ",") != "effect" || strings.Join(stated, ",") != "120" {
		t.Errorf("numbers %v, claims %v, stated %v", numbers, claims, stated)
	}
}

func project() Project {
	return Project{Name: "trial", Question: "Does it work?",
		Plan:   Plan{Text: "t-test", Digest: Digest("t-test"), Registered: day, By: "dana", BeforeData: true},
		Claims: []Claim{{Name: "effect", Run: "r-20261014-0000abcd", Value: 0.42}},
		Sources: []Source{
			{Key: "smith2020", ID: "doi:10.1000/a", Title: "Aspirin lowers fever in adults", Year: 2020, Authors: []string{"Ann Smith"},
				Abstract: "In a randomised trial of adults, aspirin lowered fever within two hours compared with placebo."},
			{Key: "bare", ID: "doi:10.1000/b", Title: "A work with no abstract"},
		}}
}

func TestTheCheckFindsWhatCannotBeTraced(t *testing.T) {
	p := project()
	p.Report = "Aspirin lowered fever within two hours in adults [@smith2020]. Our effect was {{effect}}.\n\n" +
		"Aspirin cures headaches in children [@smith2020].\n\n" +
		"It also helps 40 percent of people [@ghost].\n\n" +
		"Nothing else is known [@bare]. The size was {{size}}."
	fs := Check(p, nil)
	text := ""
	for _, f := range fs {
		if f.Problem {
			text += f.What + "\n"
		}
	}
	for _, want := range []string{
		"40 is a number nobody can trace",
		"[@ghost] cites nothing that resolved",
		"{{size}} is not a claim",
		"Aspirin cures headaches in children.\": not supported",
		"nothing of [@bare] is held",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, "within two hours in adults") {
		t.Errorf("a supported sentence was flagged:\n%s", text)
	}
	if Problems(fs) != 5 {
		t.Errorf("%d problems:\n%s", Problems(fs), text)
	}
	// A claim whose computation did not reproduce is a problem.
	no := false
	p.Report = "Our effect was {{effect}}."
	fs = Check(p, []Run{{ID: "r-20261014-1111abcd", Rerun: "r-20261014-0000abcd", Reproduced: &no, Differs: []string{"effect 0.42, then 0.43"}}})
	if Problems(fs) != 1 || !strings.Contains(fs[len(fs)-1].What, "did not reproduce") {
		t.Errorf("%+v", fs)
	}
}

func TestARenderedReportSaysWhereEveryNumberCameFrom(t *testing.T) {
	p := project()
	p.Report = "# Fever\n\nThe effect was {{effect}} [@smith2020; @bare], as before [@smith2020]."
	blocks, cited := Render(p)
	if len(cited) != 2 || cited[0].Key != "smith2020" {
		t.Fatalf("cited %+v", cited)
	}
	var text strings.Builder
	for _, pc := range blocks[1].Pieces {
		text.WriteString(pc.Text)
	}
	if text.String() != "The effect was 0.42 [1, 2], as before [1]." {
		t.Errorf("%q", text.String())
	}
	md := Markdown(p, []Run{{ID: "r-20261014-0000abcd", Code: File{Path: "analysis.py", Digest: strings.Repeat("a", 64)},
		Environment: Environment{Interpreter: "python3", Version: "Python 3.12.3", Box: "native"}}})
	for _, want := range []string{"## References", "1. Ann Smith (2020). Aspirin lowers fever in adults.",
		"registered on 14 October 2026 by dana, before the data was analysed", "| effect | 0.42 | r-20261014-0000abcd | analysis.py aaaaaaaaaaaa"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in\n%s", want, md)
		}
	}
}

func TestIdentifiersAreReadOrRefused(t *testing.T) {
	for in, want := range map[string]string{
		"doi:10.1038/S41586-020-2649-2": "doi:10.1038/s41586-020-2649-2",
		"https://doi.org/10.1000/xyz":   "doi:10.1000/xyz",
		"10.1000/xyz":                   "doi:10.1000/xyz",
		"pmid:31452104":                 "pmid:31452104",
		"arXiv:2401.01234v2":            "arxiv:2401.01234v2",
		"W2741809807":                   "openalex:W2741809807",
	} {
		if id, err := ParseIdentifier(in); err != nil || id.String() != want {
			t.Errorf("%s: %v %v", in, id, err)
		}
	}
	for _, bad := range []string{"Attention is all you need", "doi:11.1/x", "pmid:abc", ""} {
		if _, err := ParseIdentifier(bad); err == nil {
			t.Errorf("%q was read as an identifier", bad)
		}
	}
}

func indexes(t *testing.T) (Index, *[]string) {
	t.Helper()
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.URL.String())
		switch {
		case r.URL.Path == "/oa/works" && r.URL.Query().Get("filter") == "doi:10.1000/known":
			w.Write([]byte(`{"results":[{"id":"https://openalex.org/W1","doi":"https://doi.org/10.1000/known",
				"display_name":"Aspirin <i>lowers</i> fever","publication_year":2020,
				"authorships":[{"author":{"display_name":"Ann Smith"}}],
				"primary_location":{"source":{"display_name":"The Journal"}},
				"abstract_inverted_index":{"Aspirin":[0],"lowered":[1],"fever":[2]}}]}`))
		case r.URL.Path == "/oa/works" && r.URL.Query().Get("search") != "":
			w.Write([]byte(`{"results":[{"id":"https://openalex.org/W1","doi":"https://doi.org/10.1000/known","display_name":"Aspirin lowers fever","publication_year":2020,"cited_by_count":12}]}`))
		case r.URL.Path == "/oa/works":
			w.Write([]byte(`{"results":[]}`))
		case r.URL.Path == "/oa/works/pmid:123":
			w.Write([]byte(`{"id":"https://openalex.org/W2","display_name":"A PubMed work","publication_year":2019}`))
		case strings.HasPrefix(r.URL.Path, "/cr/works/"):
			if strings.Contains(r.URL.Path, "10.1000") && strings.HasSuffix(r.URL.Path, "only-crossref") {
				w.Write([]byte(`{"message":{"title":["Only in Crossref"],"author":[{"given":"Bo","family":"Li"}],
					"issued":{"date-parts":[[2018,3]]},"container-title":["Proceedings"],"abstract":"<jats:p>Findings.</jats:p>","DOI":"10.1000/only-crossref"}}`))
				return
			}
			http.NotFound(w, r)
		case r.URL.Path == "/ax/api/query":
			if r.URL.Query().Get("id_list") == "2401.01234" {
				w.Write([]byte(`<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>http://arxiv.org/abs/2401.01234v1</id>
					<title>Agents that check their work</title><summary>We show agents can check claims.</summary>
					<published>2024-01-02T00:00:00Z</published><author><name>Ana Diaz</name></author></entry></feed>`))
				return
			}
			w.Write([]byte(`<feed xmlns="http://www.w3.org/2005/Atom"></feed>`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	get := func(ctx context.Context, u string) ([]byte, int, error) {
		res, err := http.Get(u)
		if err != nil {
			return nil, 0, err
		}
		defer res.Body.Close()
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := res.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		return []byte(b.String()), res.StatusCode, nil
	}
	return Index{Get: get, OpenAlex: srv.URL + "/oa", Crossref: srv.URL + "/cr", Arxiv: srv.URL + "/ax"}, &asked
}

// A citation is kept only for a work an index returned, with what the
// index holds of its words.
func TestACitationIsAWorkAnIndexReturned(t *testing.T) {
	ix, _ := indexes(t)
	ctx := context.Background()
	src, err := ix.Resolve(ctx, Identifier{"doi", "10.1000/known"})
	if err != nil || src.Title != "Aspirin lowers fever" || src.Abstract != "Aspirin lowered fever" ||
		src.Venue != "The Journal" || src.Resolver != "OpenAlex" || src.URL != "https://doi.org/10.1000/known" {
		t.Fatalf("%+v %v", src, err)
	}
	if src, err := ix.Resolve(ctx, Identifier{"doi", "10.1000/only-crossref"}); err != nil || src.Resolver != "Crossref" ||
		src.Year != 2018 || src.Abstract != "Findings." || src.Authors[0] != "Bo Li" {
		t.Errorf("%+v %v", src, err)
	}
	if src, err := ix.Resolve(ctx, Identifier{"arxiv", "2401.01234"}); err != nil || src.Year != 2024 || src.Authors[0] != "Ana Diaz" {
		t.Errorf("%+v %v", src, err)
	}
	if src, err := ix.Resolve(ctx, Identifier{"pmid", "123"}); err != nil || src.Title != "A PubMed work" {
		t.Errorf("%+v %v", src, err)
	}
	for _, id := range []Identifier{{"doi", "10.1000/invented"}, {"arxiv", "9999.99999"}} {
		if _, err := ix.Resolve(ctx, id); err == nil {
			t.Errorf("%s resolved", id)
		}
	}
	found, err := ix.Search(ctx, "aspirin fever", 5)
	if err != nil || len(found) != 1 || found[0].ID != "doi:10.1000/known" || found[0].CitedBy != 12 {
		t.Errorf("%+v %v", found, err)
	}
	if k := SuggestKey(src, map[string]bool{"smith2020": true}); k == "" {
		t.Error("no key")
	}
	if k := SuggestKey(Source{Authors: []string{"Ann Smith"}, Year: 2020}, map[string]bool{"smith2020": true}); k != "smith2020a" {
		t.Errorf("%q", k)
	}
}
