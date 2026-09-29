// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package analytics

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const chrome = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0 Safari/537.36"

func visit(c *Counter, path, ip, ua string, headers map[string]string) {
	r := httptest.NewRequest("GET", "http://shop.example"+path, nil)
	r.RemoteAddr = ip + ":5555"
	r.Header.Set("User-Agent", ua)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	c.Visit(r, strings.SplitN(path, "?", 2)[0])
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func counter(t *testing.T) (*Counter, *clock, string) {
	dir := t.TempDir()
	cl := &clock{time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)}
	c, err := Open(dir, cl.now)
	if err != nil {
		t.Fatal(err)
	}
	return c, cl, dir
}

func TestViewsAndVisitorsWithoutACookie(t *testing.T) {
	c, _, _ := counter(t)
	visit(c, "/", "203.0.113.1", chrome, nil)
	visit(c, "/", "203.0.113.1", chrome, nil)
	visit(c, "/returns", "203.0.113.1", chrome, nil)
	visit(c, "/", "203.0.113.2", chrome, nil)
	d := c.Today()
	if d.Views != 4 || d.Visitors != 2 {
		t.Fatalf("views %d visitors %d", d.Views, d.Visitors)
	}
	if d.Pages["/"].Views != 3 || d.Pages["/"].Visitors != 2 || d.Pages["/returns"].Visitors != 1 {
		t.Fatalf("%+v", d.Pages)
	}
}

func TestCrawlersAndPrefetchesAreNotViews(t *testing.T) {
	c, _, _ := counter(t)
	for _, ua := range []string{"", "Googlebot/2.1", "curl/8.5", "python-requests/2.31",
		"Mozilla/5.0 (compatible; Bingbot/2.0)", "UptimeRobot/2.0"} {
		visit(c, "/", "198.51.100.1", ua, nil)
	}
	visit(c, "/returns", "198.51.100.2", chrome, map[string]string{"Sec-Purpose": "prefetch"})
	d := c.Today()
	if d.Views != 0 || d.Visitors != 0 {
		t.Fatalf("crawlers or prefetches counted as views: %+v", d)
	}
	if d.Prefetch != 1 {
		t.Fatalf("the prefetch was not counted separately: %d", d.Prefetch)
	}
}

func TestReferrersAreOtherSitesAndCampaigns(t *testing.T) {
	c, _, _ := counter(t)
	visit(c, "/", "203.0.113.1", chrome, map[string]string{"Referer": "https://news.example/story"})
	visit(c, "/returns", "203.0.113.1", chrome, map[string]string{"Referer": "https://shop.example/"})
	visit(c, "/?utm_source=newsletter", "203.0.113.3", chrome, nil)
	d := c.Today()
	if d.Referrers["news.example"] != 1 || d.Referrers["newsletter"] != 1 || len(d.Referrers) != 2 {
		t.Fatalf("%+v", d.Referrers)
	}
}

// TestNothingIdentifyingIsWritten.
func TestNothingIdentifyingIsWritten(t *testing.T) {
	c, _, dir := counter(t)
	visit(c, "/", "203.0.113.77", chrome, nil)
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, bad := range []string{"203.0.113.77", "Chrome/149", string(c.salt)} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s holds %q", f, bad)
			}
		}
		if fi, _ := os.Stat(f); fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is readable by others", f)
		}
	}
}

func TestADayRollsOverWithANewSalt(t *testing.T) {
	c, cl, dir := counter(t)
	visit(c, "/", "203.0.113.1", chrome, nil)
	firstSalt := string(c.salt)
	cl.t = cl.t.Add(24 * time.Hour)
	visit(c, "/", "203.0.113.1", chrome, nil)
	if string(c.salt) == firstSalt {
		t.Fatal("the salt survived midnight, so visitors can be joined across days")
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	days, err := Read(dir, 3, cl.t)
	if err != nil {
		t.Fatal(err)
	}
	if len(days) != 3 || days[0].Views != 0 || days[1].Views != 1 || days[2].Views != 1 {
		t.Fatalf("%+v", days)
	}
	if s := Summarise(days); s.Views != 2 || s.Visitors != 2 {
		t.Fatalf("%+v", s)
	}
}

func TestARestartCarriesOnTheDay(t *testing.T) {
	c, cl, dir := counter(t)
	visit(c, "/", "203.0.113.1", chrome, nil)
	c.Flush()
	c2, err := Open(dir, cl.now)
	if err != nil {
		t.Fatal(err)
	}
	visit(c2, "/", "203.0.113.9", chrome, nil)
	if d := c2.Today(); d.Views != 2 {
		t.Fatalf("a restart lost the day: %+v", d)
	}
}

func TestAFloodCannotGrowTheDayWithoutLimit(t *testing.T) {
	c, _, _ := counter(t)
	for i := 0; i < MaxPaths+50; i++ {
		visit(c, fmt.Sprintf("/p%d", i), "203.0.113.1", chrome,
			map[string]string{"Referer": fmt.Sprintf("https://r%d.example/", i)})
	}
	d := c.Today()
	if len(d.Pages) > MaxPaths+1 || len(d.Referrers) > MaxReferrers+1 || d.Pages[Other].Views != 50 {
		t.Fatalf("pages %d referrers %d other %d", len(d.Pages), len(d.Referrers), d.Pages[Other].Views)
	}
}

func TestAConversionIsCountedOncePerVisitor(t *testing.T) {
	c, _, _ := counter(t)
	r := httptest.NewRequest("POST", "http://shop.example/form/contact", nil)
	r.RemoteAddr = "203.0.113.1:1"
	r.Header.Set("User-Agent", chrome)
	c.Convert(r, "form:contact")
	c.Convert(r, "form:contact")
	if d := c.Today(); d.Goals["form:contact"] != 1 {
		t.Fatalf("%+v", d.Goals)
	}
}
