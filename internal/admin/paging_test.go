// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"html"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/site"
)

// The arithmetic, which is the whole of this.
//
// Off-by-one in a listing is the kind of bug that ships: the page renders, the
// numbers are nearly right, and the only symptom is a row that is on two pages
// or on none.
func TestWhereInTheListThisRequestIs(t *testing.T) {
	for _, c := range []struct {
		why                    string
		url                    string
		total, size            int
		offset, from, to       int
		hasPrev, hasNext, need bool
		prev, next             int
	}{
		{why: "a list that fits on one page",
			url: "/", total: 7, size: 50,
			offset: 0, from: 1, to: 7, need: false},
		{why: "the first of several",
			url: "/", total: 312, size: 50,
			offset: 0, from: 1, to: 50, hasNext: true, next: 50, need: true},
		{why: "the second",
			url: "/?from=50", total: 312, size: 50,
			offset: 50, from: 51, to: 100, hasPrev: true, hasNext: true,
			prev: 0, next: 100, need: true},
		{why: "the last, which is short",
			url: "/?from=300", total: 312, size: 50,
			offset: 300, from: 301, to: 312, hasPrev: true, prev: 250, need: true},
		{why: "exactly one full page",
			url: "/", total: 50, size: 50,
			offset: 0, from: 1, to: 50, need: false},
		{why: "one more than a page",
			url: "/", total: 51, size: 50,
			offset: 0, from: 1, to: 50, hasNext: true, next: 50, need: true},
		{why: "an empty list",
			url: "/", total: 0, size: 50,
			offset: 0, from: 0, to: 0, need: false},
		// A kept link after things were deleted lands at the end, not on a
		// blank screen that reads as everything having gone.
		{why: "an offset past the end",
			url: "/?from=9999", total: 312, size: 50,
			offset: 300, from: 301, to: 312, hasPrev: true, prev: 250, need: true},
		{why: "an offset past the end of a short list",
			url: "/?from=9999", total: 7, size: 50,
			offset: 0, from: 1, to: 7, need: false},
		// Nonsense is the start rather than an error: this is a URL somebody
		// may have typed or a link somebody may have mangled.
		{why: "a negative offset", url: "/?from=-5", total: 312, size: 50,
			offset: 0, from: 1, to: 50, hasNext: true, next: 50, need: true},
		{why: "an offset that is not a number", url: "/?from=banana",
			total: 312, size: 50,
			offset: 0, from: 1, to: 50, hasNext: true, next: 50, need: true},
	} {
		p := paginate(httptest.NewRequest("GET", c.url, nil), c.total, c.size)
		if p.Offset != c.offset || p.From != c.from || p.To != c.to {
			t.Errorf("%s: offset/from/to = %d/%d/%d, want %d/%d/%d",
				c.why, p.Offset, p.From, p.To, c.offset, c.from, c.to)
		}
		if p.HasPrev != c.hasPrev || p.HasNext != c.hasNext {
			t.Errorf("%s: prev/next = %t/%t, want %t/%t",
				c.why, p.HasPrev, p.HasNext, c.hasPrev, c.hasNext)
		}
		if p.HasPrev && p.Prev != c.prev {
			t.Errorf("%s: Prev = %d, want %d", c.why, p.Prev, c.prev)
		}
		if p.HasNext && p.Next != c.next {
			t.Errorf("%s: Next = %d, want %d", c.why, p.Next, c.next)
		}
		if p.Needed != c.need {
			t.Errorf("%s: Needed = %t, want %t", c.why, p.Needed, c.need)
		}
	}
}

// Every row is on exactly one page, walking forwards.
//
// The property the arithmetic exists for, checked by walking rather than by
// reasoning about it: a row on two pages or on none is what an off-by-one
// actually looks like.
func TestWalkingTheListCoversEveryRowExactlyOnce(t *testing.T) {
	for _, total := range []int{0, 1, 49, 50, 51, 99, 100, 101, 312} {
		const size = 50
		seen := make([]int, total)
		offset, steps := 0, 0
		for {
			p := paginate(httptest.NewRequest("GET",
				"/?from="+itoa(offset), nil), total, size)
			start, end := p.slice(total)
			for i := start; i < end; i++ {
				seen[i]++
			}
			steps++
			if !p.HasNext || steps > 100 {
				break
			}
			offset = p.Next
		}
		for i, n := range seen {
			if n != 1 {
				t.Errorf("total %d: row %d appeared %d times", total, i, n)
				break
			}
		}
	}
}

// Walking back reaches the offsets walking forward used.
//
// Otherwise "next" then "previous" does not return somebody to where they
// were, which is the most obvious thing anybody does with these two buttons.
func TestBackAndForwardAgreeOnTheOffsets(t *testing.T) {
	const total, size = 312, 50
	var forward []int
	offset := 0
	for {
		p := paginate(httptest.NewRequest("GET", "/?from="+itoa(offset), nil), total, size)
		forward = append(forward, p.Offset)
		if !p.HasNext {
			break
		}
		offset = p.Next
	}

	var back []int
	offset = forward[len(forward)-1]
	for {
		p := paginate(httptest.NewRequest("GET", "/?from="+itoa(offset), nil), total, size)
		back = append(back, p.Offset)
		if !p.HasPrev {
			break
		}
		offset = p.Prev
	}

	if len(back) != len(forward) {
		t.Fatalf("forward took %d pages and back took %d: %v vs %v",
			len(forward), len(back), forward, back)
	}
	for i := range forward {
		if forward[i] != back[len(back)-1-i] {
			t.Fatalf("the two directions disagree: %v vs %v", forward, back)
		}
	}
}

// Turning the page keeps whatever else the reader had set.
//
// Without this, paging silently drops a filter — which looks like the filter
// being cleared rather than like a link missing a parameter.
func TestTurningThePageKeepsTheFilter(t *testing.T) {
	p := paginate(httptest.NewRequest("GET",
		"/?from=50&q=brass&state=changed", nil), 312, 50)

	if !strings.Contains(p.Query, "q=brass") ||
		!strings.Contains(p.Query, "state=changed") {
		t.Errorf("the page link drops the filter: %q", p.Query)
	}
	// And does not carry the offset twice, which would leave the browser to
	// pick one.
	if strings.Contains(p.Query, "from=") {
		t.Errorf("the query carries its own offset as well: %q", p.Query)
	}
	if !strings.HasPrefix(p.Query, "&") {
		t.Errorf("the query does not join onto ?from=N: %q", p.Query)
	}
	// Nothing else set means nothing to join.
	if q := paginate(httptest.NewRequest("GET", "/", nil), 10, 50).Query; q != "" {
		t.Errorf("an unfiltered list carries %q", q)
	}
}

// slice never goes out of bounds, whatever it is given.
func TestSliceStaysInsideTheList(t *testing.T) {
	for _, total := range []int{0, 1, 7, 50, 312} {
		for _, from := range []string{"0", "1", "49", "50", "311", "312", "99999"} {
			p := paginate(httptest.NewRequest("GET", "/?from="+from, nil), total, 50)
			start, end := p.slice(total)
			if start < 0 || end < start || end > total {
				t.Errorf("total %d from %s gave [%d:%d]", total, from, start, end)
			}
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// nextLink is where a screen's Next link goes, as it is written in the page.
var nextLink = regexp.MustCompile(`<a rel="next" href="([^"]*)"`)

// Next goes to the next page whatever else is in the address.
//
// The rest of the query was joined on as a string already encoded,
// "&e=…&fs=…", and the template escaped it a second time, so after any
// action that came back with a message Next was /?from=50%26e%3d…: the
// server read from as "50&e=…", which is not a number, and showed the first
// page again until somebody cleared the address bar. A filter went the same
// way. The one-shot message is not carried at all: it was about the action,
// not about the page somebody turns to.
func TestNextMovesOnAfterAMessage(t *testing.T) {
	srv, token := setup(t)
	pages, err := site.PagesAt(srv.Store, site.RefDraft)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 120; i++ {
		pages[fmt.Sprintf("bulk-%03d", i)] = map[string]any{"title": fmt.Sprintf("Bulk page %d", i)}
	}
	if _, err := site.SaveDraft(srv.Store, pages, "many pages", "test"); err != nil {
		t.Fatal(err)
	}

	at := signFlash(srv.flashKey, "/?e="+url.QueryEscape("about is still used by two pages"))
	body := get(t, srv, at, token).Body.String()
	if !strings.Contains(body, "about is still used by two pages") {
		t.Fatal("the message did not show, so this is not testing what it says")
	}
	m := nextLink.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("the list has no Next")
	}
	next := html.UnescapeString(m[1])
	u, err := url.Parse(next)
	if err != nil || u.Path != "/" || u.Query().Get("from") != "50" {
		t.Fatalf("Next goes to %q", next)
	}
	for _, p := range []string{"e", "m", "fs"} {
		if u.Query().Has(p) {
			t.Errorf("Next carries the message's %s: %s", p, next)
		}
	}
	if body := get(t, srv, next, token).Body.String(); !strings.Contains(body, "51 to 100 of 122") {
		t.Errorf("Next showed the first page again")
	}

	// And whatever else the reader had set comes along, once: choosing a
	// picture always has the page and the place in its address, so its
	// Next never moved at all.
	p := paginate(httptest.NewRequest("GET", "/media/pick?page=about&at=0&from=50&m=x&fs=y", nil), 312, 50)
	var out strings.Builder
	if err := srv.tpl.ExecuteTemplate(&out, "paging", map[string]any{"Paging": p, "PagePath": "/media/pick"}); err != nil {
		t.Fatal(err)
	}
	m = nextLink.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("no Next in %s", out.String())
	}
	got, _ := url.Parse(html.UnescapeString(m[1]))
	if q := got.Query(); got.Path != "/media/pick" || q.Get("page") != "about" || q.Get("at") != "0" ||
		q.Get("from") != "100" || q.Has("m") || q.Has("fs") || len(q["from"]) != 1 {
		t.Errorf("a page link is %s", got)
	}
}
