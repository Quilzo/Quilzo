// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package websearch

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// Each provider is asked the way its documentation says: the key where it
// goes and nowhere else, the query escaped, the count bounded.
func TestEachProviderIsAskedItsOwnWay(t *testing.T) {
	for _, c := range []struct {
		id, method, address, header, value, body string
	}{
		{"brave", "GET", "https://api.search.brave.com/res/v1/web/search?q=sourdough+%26+rye&count=5", "X-Subscription-Token", "K", ""},
		{"tavily", "POST", "https://api.tavily.com/search", "Authorization", "Bearer K", `{"query":"sourdough & rye","max_results":5}`},
		{"exa", "POST", "https://api.exa.ai/search", "x-api-key", "K", `"numResults":5`},
		{"serper", "POST", "https://google.serper.dev/search", "X-API-KEY", "K", `{"q":"sourdough & rye","num":5}`},
		{"serpapi", "GET", "https://serpapi.com/search.json?engine=google&q=sourdough+%26+rye&num=5&api_key=K", "", "", ""},
		{"kagi", "GET", "https://kagi.com/api/v0/search?q=sourdough+%26+rye&limit=5", "Authorization", "Bot K", ""},
		{"perplexity", "POST", "https://api.perplexity.ai/search", "Authorization", "Bearer K", `"max_results":5`},
		{"jina", "GET", "https://s.jina.ai/?q=sourdough+%26+rye", "Authorization", "Bearer K", ""},
	} {
		p, ok := Get(c.id)
		if !ok {
			t.Fatalf("no %s", c.id)
		}
		method, address, body, headers, err := p.Request("sourdough & rye", 5, "K", "")
		if err != nil {
			t.Fatalf("%s: %v", c.id, err)
		}
		if method != c.method || address != c.address {
			t.Errorf("%s: %s %s", c.id, method, address)
		}
		if c.header != "" && headers[c.header] != c.value {
			t.Errorf("%s: %s is %q", c.id, c.header, headers[c.header])
		}
		if c.body != "" && !strings.Contains(string(body), c.body) {
			t.Errorf("%s: body %s", c.id, body)
		}
		// The key is in one place only.
		n := strings.Count(address, "K") - strings.Count(c.address, "K") + strings.Count(string(body), `"K"`)
		for _, v := range headers {
			if strings.Contains(v, "K") {
				n++
			}
		}
		if c.id == "serpapi" {
			n++
		}
		if n != 1 {
			t.Errorf("%s: the key is sent %d times", c.id, n)
		}
	}
	// A query with a quote in it stays one JSON string.
	p, _ := Get("tavily")
	_, _, body, _, _ := p.Request(`say "hi"`, 99, "K", "")
	if !strings.Contains(string(body), `"query":"say \"hi\""`) || !strings.Contains(string(body), `"max_results":20`) {
		t.Errorf("%s", body)
	}
}

// What a provider answers is read into title, address and summary; a
// result with no web address is left out; and no more than asked for.
func TestWhatAProviderAnswersIsRead(t *testing.T) {
	brave, _ := Get("brave")
	got, err := brave.Read([]byte(`{"web":{"results":[
		{"title":"Hart's Bakery","url":"https://hartsbakery.co.uk/","description":"Sourdough   under the arches"},
		{"title":"A script","url":"javascript:alert(1)","description":"x"},
		{"title":"Two","url":"https://two.example/","description":"b"},
		{"title":"Three","url":"https://three.example/","description":"c"}]}}`), 2)
	if err != nil || len(got) != 2 || got[0] != (Result{"Hart's Bakery", "https://hartsbakery.co.uk/", "Sourdough under the arches"}) ||
		got[1].URL != "https://two.example/" {
		t.Fatalf("%+v %v", got, err)
	}
	exa, _ := Get("exa")
	got, _ = exa.Read([]byte(`{"results":[{"title":"Rye","url":"https://rye.example/","text":"A rye loaf"}]}`), 5)
	if len(got) != 1 || got[0].Summary != "A rye loaf" {
		t.Fatalf("%+v", got)
	}
	if _, err := brave.Read([]byte(`not json`), 5); err == nil {
		t.Error("an answer that is not JSON was read")
	}
	if got, err := brave.Read([]byte(`{"query":{}}`), 5); err != nil || len(got) != 0 {
		t.Errorf("an answer with no results: %+v %v", got, err)
	}
}

// A provider on the operator's network is reached at its https address
// and nowhere else; a key that is not there says how to keep it; a key in
// an error is not repeated.
func TestSearchesNeedWhatTheyNeed(t *testing.T) {
	sx, _ := Get("searxng")
	for _, base := range []string{"", "http://search.internal", "https://user:pw@search.internal", "https://search.internal/?x=1"} {
		if _, _, _, _, err := sx.Request("q", 5, "", base); err == nil {
			t.Errorf("SearXNG at %q", base)
		}
	}
	_, address, _, _, err := sx.Request("q", 5, "", "https://search.internal/")
	if err != nil || address != "https://search.internal/search?q=q&format=json" {
		t.Errorf("%s %v", address, err)
	}
	brave, _ := Get("brave")
	if _, _, _, _, err := brave.Request("q", 5, "", ""); err == nil || !strings.Contains(err.Error(), "quilzo secret set search-brave") {
		t.Errorf("%v", err)
	}
	if _, _, _, _, err := brave.Request(strings.Repeat("q", MaxQuery+1), 5, "K", ""); err == nil {
		t.Error("an over-long query")
	}
	serpapi, _ := Get("serpapi")
	_, err = serpapi.Search(context.Background(), func(_ context.Context, _, address string, _ []byte, _ map[string]string) (int, []byte, error) {
		u, _ := url.Parse(address)
		return 0, nil, errors.New("dial " + u.String() + " failed")
	}, "q", 5, "SECRET-KEY", "")
	if err == nil || strings.Contains(err.Error(), "SECRET-KEY") {
		t.Fatalf("the key is in the error: %v", err)
	}
	_, err = brave.Search(context.Background(), func(context.Context, string, string, []byte, map[string]string) (int, []byte, error) {
		return 429, []byte(`{"error":"rate limited"}`), nil
	}, "q", 5, "K", "")
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Errorf("%v", err)
	}
}
