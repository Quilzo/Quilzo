// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// servedSite is the public site as `quilzo site` serves it, for a store and
// a template directory in a test: the same run, the same builder, the same
// reloader. It looks at the settings files on every request rather than
// once a second, so a test does not wait.
func servedSite(t *testing.T, root, tpl string) *siteReloader {
	t.Helper()
	design, err := loadDesign(tpl)
	if err != nil {
		t.Fatal(err)
	}
	run := testRun(t, root)
	st, err := run.build(design, nil)
	if err != nil {
		t.Fatal(err)
	}
	rl := newSiteReloader(root, tpl, run.store, site.RefLive, design, st, run.build)
	rl.every = 0
	rl.say = func(string, ...any) {}
	return rl
}

func served(h http.Handler, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

// A setting reaches the public site without a restart.
//
// `quilzo events setup` sets site.events, and the site that was running
// kept answering /events.ics with 404 until somebody restarted it, because
// it had read its settings once when it started.
func TestASettingReachesTheSiteWithoutARestart(t *testing.T) {
	root, tpl := fontSite(t)
	seedPolicy(t, root, [2]string{"dana", "admin"})
	featureDesignDir = tpl
	rl := servedSite(t, root, tpl)
	if w := served(rl, "/events.ics"); w.Code != http.StatusNotFound {
		t.Fatalf("a site with no events served a calendar: %d", w.Code)
	}
	if err := eventsCmd(root, []string{"setup"}, asAdmin("dana")); err != nil {
		t.Fatal(err)
	}
	// No publish: the setting is what changed.
	w := served(rl, "/events.ics")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "BEGIN:VCALENDAR") {
		t.Fatalf("site.events was set and the site still says %d", w.Code)
	}
	recs := actions(t, root, "site.reload")
	if len(recs) != 1 || recs[0].Detail["trigger"] != reloadSettings ||
		recs[0].Detail["settings"] != "changed" || recs[0].Detail["design"] != "same" {
		t.Fatalf("the reload was recorded as %+v", recs)
	}
	// Nothing changed since, so nothing is built and nothing recorded.
	served(rl, "/")
	if n := len(actions(t, root, "site.reload")); n != 1 {
		t.Errorf("%d reloads recorded for one change", n)
	}
}

// A design change reaches readers with the publish the gate passed, and not
// before.
//
// The gate is what computes the theme's contrast and renders every page
// through the layouts. `quilzo theme set --force` saves a palette that fails
// it, and says the gate will refuse it; a site that served templates/ the
// moment it changed would put that palette in front of readers anyway.
func TestADesignReachesReadersWithThePublishNotBefore(t *testing.T) {
	root, tpl := fontSite(t)
	rl := servedSite(t, root, tpl)
	before := served(rl, "/site.css").Body.String()

	// A face added and named: the design changes on disk.
	ttf := writeTemp(t, "Aster.ttf", trueTypeFace(0))
	if err := cmdTheme(root, []string{"font", "add", ttf, "--dir", tpl, "--name", "Aster-400-700"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdTheme(root, []string{"set", "font-body", "Aster", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	if got := served(rl, "/site.css").Body.String(); got != before {
		t.Fatal("a design change reached readers before any publish")
	}
	if w := served(rl, "/fonts/Aster-400-700.woff"); w.Code != http.StatusNotFound {
		t.Fatalf("a face nobody has published was served: %d", w.Code)
	}

	// A palette that fails the gate, saved anyway.
	if err := cmdTheme(root, []string{"set", "on-surface", "#777777", "surface", "#808080", "--dir", tpl, "--force"}); err != nil {
		t.Fatal(err)
	}
	editDraft(t, root, "index", "Changed words.")
	if err := runPublish(t, root, "-templates", tpl); err == nil || !strings.Contains(err.Error(), "accessibility") {
		t.Fatalf("the gate on a palette that fails it: %v", err)
	}
	if got := served(rl, "/site.css").Body.String(); got != before {
		t.Fatal("a palette the gate refused reached readers")
	}

	// Put right, published: the face and its declaration arrive together.
	if err := cmdTheme(root, []string{"unset", "on-surface", "surface", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	if err := runPublish(t, root, "-templates", tpl); err != nil {
		t.Fatal(err)
	}
	css := served(rl, "/site.css").Body.String()
	if !strings.Contains(css, `url("/fonts/Aster-400-700.woff") format("woff")`) {
		t.Fatal("the published design is not the one served")
	}
	if w := served(rl, "/fonts/Aster-400-700.woff"); w.Code != http.StatusOK || w.Header().Get("Content-Type") != "font/woff" {
		t.Fatalf("the published face: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	recs := actions(t, root, "site.reload")
	last := recs[len(recs)-1]
	if last.Detail["trigger"] != reloadPublish || last.Detail["design"] != "changed" || last.Detail["commit"] == "" {
		t.Errorf("the publish's reload was recorded as %+v", last.Detail)
	}
}

// SIGHUP reads the design and the settings again, whatever has changed: the
// operator's say-so, as a restart was, without dropping a connection.
func TestSIGHUPReadsTheDesignAgain(t *testing.T) {
	root, tpl := fontSite(t)
	rl := servedSite(t, root, tpl)
	if err := cmdTheme(root, []string{"set", "radius", "3px", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(served(rl, "/site.css").Body.String(), "--radius: 3px") {
		t.Fatal("the design changed before anybody said so")
	}
	if runtime.GOOS == "windows" {
		if err := rl.Reload(); err != nil {
			t.Fatal(err)
		}
	} else {
		// The real signal, to this process, through the handler `quilzo site`
		// installs.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		onHangup(ctx, "site", func() error {
			err := rl.Reload()
			done <- err
			return err
		})
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("SIGHUP did nothing")
		}
	}
	if !strings.Contains(served(rl, "/site.css").Body.String(), "--radius: 3px") {
		t.Fatal("SIGHUP did not read the design again")
	}
	recs := actions(t, root, "site.reload")
	if len(recs) == 0 || recs[len(recs)-1].Detail["trigger"] != reloadSignal {
		t.Errorf("recorded %+v", recs)
	}
}

// A reload that fails changes nothing a reader gets, says why, and is not
// tried again until something changes again.
func TestAReloadThatFailsKeepsWhatWasServed(t *testing.T) {
	root, tpl := fontSite(t)
	rl := servedSite(t, root, tpl)
	page := served(rl, "/").Body.String()
	if !strings.Contains(page, "<h1>T</h1>") {
		t.Fatalf("the page: %.200s", page)
	}

	// A theme file that is not JSON, then a publish: the design is kept,
	// the publish is served.
	if err := os.WriteFile(filepath.Join(tpl, themeFile), []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	editDraft(t, root, "index", "Second words.")
	commitLive(t, root)
	if w := served(rl, "/"); w.Code != 200 || !strings.Contains(w.Body.String(), "Second words.") {
		t.Fatalf("the publish was not served when the design could not be read: %d", w.Code)
	}
	if served(rl, "/site.css").Code != http.StatusOK {
		t.Fatal("the stylesheet went with the design that could not be read")
	}
	recs := actions(t, root, "site.reload")
	if len(recs) != 1 || recs[0].Outcome != audit.Failure || recs[0].Detail["design"] != "kept" ||
		!strings.Contains(recs[0].Detail["why"], "not valid JSON") {
		t.Fatalf("recorded %+v", recs)
	}

	// Settings the site cannot be built from: the whole site is kept.
	if err := os.WriteFile(configPath(root), []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := served(rl, "/"); w.Code != 200 || !strings.Contains(w.Body.String(), "Second words.") {
		t.Fatalf("unreadable settings took the site down: %d", w.Code)
	}
	for i := 0; i < 3; i++ {
		served(rl, "/")
	}
	recs = actions(t, root, "site.reload")
	if len(recs) != 2 || recs[1].Outcome != audit.Failure || recs[1].Detail["trigger"] != reloadSettings {
		t.Fatalf("a failing reload was tried %d time(s): %+v", len(recs)-1, recs)
	}
}

// A rebuilt site keeps what visitors are in the middle of.
//
// Rebuilding the limiters would hand every visitor a fresh allowance at each
// publish; rebuilding the chatbots would forget which ratings were already
// used and the key they were signed with; rebuilding the newsletter would
// reset its count of mail sent this hour.
func TestAReloadKeepsWhatVisitorsAreInTheMiddleOf(t *testing.T) {
	root, tpl := fontSite(t)
	rl := servedSite(t, root, tpl)
	first := rl.Site()
	editDraft(t, root, "index", "Again.")
	commitLive(t, root)
	served(rl, "/")
	next := rl.Site()
	if next == first {
		t.Fatal("a publish did not build the site again")
	}
	for name, same := range map[string]bool{
		"forms":      next.Forms == first.Forms,
		"boards":     next.Boards == first.Boards,
		"bookings":   next.Bookings == first.Bookings,
		"newsletter": next.Newsletter == first.Newsletter,
		// The chatbots are built again, for their settings, and carry on
		// from the ones before: see the guardrail test below.
		"questions": next.Assistants.Questions == first.Assistants.Questions,
		"signals":   next.Signals == first.Signals,
		"fediverse": next.Federation == first.Federation,
	} {
		if !same {
			t.Errorf("the %s state was rebuilt rather than kept", name)
		}
	}
	if first.Forms == nil || first.Assistants == nil || first.Signals == nil {
		t.Fatal("the fixture has none of what is meant to be kept, so this checks nothing")
	}
}

// The share target takes its settings with a reload and keeps its count.
//
// It was carried whole while share.form was unchanged, field names and all,
// so a share mapped onto a field renamed in share.text_field arrived with
// the text in the field the form no longer had until the site restarted.
func TestAShareTargetTakesItsSettingsAndKeepsItsCount(t *testing.T) {
	root, tpl := fontSite(t)
	for _, kv := range [][2]string{{"share.form", "notes"}, {"share.text_field", "message"}} {
		if err := cmdConfig(root, []string{"set", kv[0], kv[1]}); err != nil {
			t.Fatal(err)
		}
	}
	rl := servedSite(t, root, tpl)
	first := rl.Site()
	if first.Share == nil || first.Share.TextField != "message" || first.Share.Limit == nil {
		t.Fatalf("the fixture has no share target: %+v", first.Share)
	}
	if err := cmdConfig(root, []string{"set", "share.text_field", "body"}); err != nil {
		t.Fatal(err)
	}
	served(rl, "/")
	next := rl.Site()
	if next == first || next.Share == nil {
		t.Fatalf("the settings did not build the site again: %+v", next.Share)
	}
	if next.Share.TextField != "body" {
		t.Errorf("the share target still maps the text onto %q", next.Share.TextField)
	}
	if next.Share.Limit != first.Share.Limit {
		t.Error("the share target's limit was handed out again")
	}
}

// A guardrail turned on reaches the site's chatbots with the settings, and a
// rating handed out before the rebuild still counts once and only once.
//
// The rebuilt site took the previous one's chatbots whole, to keep their
// rating keys, and with them the guardrail they had been built with: an
// operator who set guardrail.kind was told the site had read its settings
// again, and no visitor's question reached the classifier until a restart.
func TestAGuardrailTurnedOnReachesTheChatbotsWithoutARestart(t *testing.T) {
	root, tpl := fontSite(t)
	t.Setenv("QUILZO_GUARDRAIL_KEY", "")
	set, _ := assistant.Load(assistantsPath(root))
	if err := set.Put(assistant.Assistant{Name: "help", Title: "Ask us", Public: true}); err != nil {
		t.Fatal(err)
	}
	if err := assistant.Save(assistantsPath(root), set); err != nil {
		t.Fatal(err)
	}
	// Something it can answer, so the answer is offered for rating.
	editDraft(t, root, "index", "Our opening hours are nine until five on weekdays.")
	commitLive(t, root)
	// The guardrail screens what a chatbot answers from, its knowledge, as
	// the index is built; so what is counted is that it was asked at all.
	var mu sync.Mutex
	heard := 0
	classifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		heard++
		mu.Unlock()
		_, _ = w.Write([]byte(`{"flagged": false}`))
	}))
	defer classifier.Close()
	asked := func() int {
		mu.Lock()
		defer mu.Unlock()
		return heard
	}
	var rl *siteReloader
	ask := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/ask/help",
			strings.NewReader(url.Values{"q": {"what are your opening hours"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "198.51.100.4:1234"
		w := httptest.NewRecorder()
		rl.ServeHTTP(w, req)
		return w
	}

	rl = servedSite(t, root, tpl)
	first := ask()
	if first.Code != http.StatusOK || asked() != 0 {
		t.Fatalf("before any guardrail: %d, the classifier heard %d", first.Code, asked())
	}
	token := reRating.FindStringSubmatch(first.Body.String())

	for k, v := range map[string]string{"guardrail.kind": "generic", "guardrail.url": classifier.URL} {
		if err := cmdConfig(root, []string{"set", k, v}); err != nil {
			t.Fatal(err)
		}
	}
	if w := ask(); w.Code != http.StatusOK {
		t.Fatalf("asked after the guardrail was set: %d", w.Code)
	}
	recs := actions(t, root, "site.reload")
	if len(recs) == 0 || recs[len(recs)-1].Detail["settings"] != "changed" {
		t.Fatalf("the settings were not read again: %+v", recs)
	}
	if asked() == 0 {
		t.Fatal("the site said it had read its settings again, and the guardrail they turn on was never asked")
	}

	// The rating offered before the rebuild is the rebuilt site's to take,
	// once.
	if token == nil {
		t.Fatal("no rating was offered, so this checks nothing about the ratings")
	}
	rate := func() string {
		v := url.Values{"q": {"what are your opening hours"}, "t": {html.UnescapeString(token[1])}, "helpful": {"yes"}}
		req := httptest.NewRequest(http.MethodPost, "/ask/help/rate", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "198.51.100.4:1234"
		w := httptest.NewRecorder()
		rl.ServeHTTP(w, req)
		return w.Header().Get("Location")
	}
	if loc := rate(); !strings.Contains(loc, "rated=yes") {
		t.Errorf("a rating from before the rebuild: %q", loc)
	}
	if loc := rate(); !strings.Contains(loc, "rated=late") {
		t.Errorf("the same rating twice, across a rebuild: %q", loc)
	}
}

// reRating is the token an answer's rating form carries.
var reRating = regexp.MustCompile(`name="t" value="([^"]+)"`)

// A configuration file caught empty is not read as a configuration of
// nothing but defaults.
//
// A file written with `>`, by `cp`, or by an editor that writes in place is
// empty for a moment before it is whole, and config.Parse reads an empty file
// as every setting at its default. The site read its settings again whenever
// the file changed, so a request arriving in that moment rebuilt the site
// with no classification banner, no Strict-Transport-Security and no
// security.txt, recorded it as a change of settings that succeeded, and
// served that until it looked again.
func TestAConfigurationCaughtEmptyIsNotReadAsNoSettings(t *testing.T) {
	root, tpl := fontSite(t)
	for _, kv := range [][2]string{{"site.hsts", "24h"}, {"security.contact", "mailto:security@example.com"},
		{"marking.levels", "PUBLIC,OFFICIAL"}, {"marking.banner", "OFFICIAL"}} {
		if err := cmdConfig(root, []string{"set", kv[0], kv[1]}); err != nil {
			t.Fatal(err)
		}
	}
	rl := servedSite(t, root, tpl)
	protected := func(when string) {
		t.Helper()
		w := served(rl, "/")
		if w.Header().Get("Strict-Transport-Security") != "max-age=86400" ||
			!strings.Contains(w.Body.String(), "OFFICIAL") ||
			served(rl, "/.well-known/security.txt").Code != http.StatusOK {
			t.Fatalf("%s: hsts %q, banner %v, security.txt %d", when,
				w.Header().Get("Strict-Transport-Security"), strings.Contains(w.Body.String(), "OFFICIAL"),
				served(rl, "/.well-known/security.txt").Code)
		}
	}
	protected("as started")
	whole, err := os.ReadFile(configPath(root))
	if err != nil {
		t.Fatal(err)
	}

	// Caught empty, and a publish carrying a design arrives meanwhile.
	if err := os.WriteFile(configPath(root), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	protected("with the file caught empty")
	if err := cmdTheme(root, []string{"set", "radius", "3px", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	editDraft(t, root, "index", "Published while the file was empty.")
	commitLive(t, root)
	protected("with a publish while the file was empty")
	if w := served(rl, "/"); !strings.Contains(w.Body.String(), "Published while the file was empty.") {
		t.Fatal("the publish was not served while the settings were kept")
	}
	recs := actions(t, root, "site.reload")
	if len(recs) != 2 || recs[0].Outcome != audit.Failure || recs[1].Outcome != audit.Failure ||
		!strings.Contains(recs[0].Detail["why"], "empty") {
		t.Fatalf("recorded %+v", recs)
	}

	// Written whole: the settings are read, and the design the publish
	// brought comes with them.
	if err := os.WriteFile(configPath(root), whole, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdConfig(root, []string{"set", "site.hsts", "48h"}); err != nil {
		t.Fatal(err)
	}
	if w := served(rl, "/"); w.Header().Get("Strict-Transport-Security") != "max-age=172800" {
		t.Fatalf("the settings written whole were not read: %q", w.Header().Get("Strict-Transport-Security"))
	}
	if !strings.Contains(served(rl, "/site.css").Body.String(), "--radius: 3px") {
		t.Fatal("the design published while the settings could not be read never reached readers")
	}

	// The way back to the defaults, on purpose, still works.
	if err := os.WriteFile(configPath(root), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := served(rl, "/"); w.Header().Get("Strict-Transport-Security") != "" || strings.Contains(w.Body.String(), "OFFICIAL") {
		t.Fatal("a configuration of {} did not put the settings back to their defaults")
	}
}

// The design a refused publish leaves due is the one its check read, not one
// saved since.
//
// A publish whose build was refused (here, because the configuration was
// caught empty) brings its design with the next build that succeeds. That
// build read templates/ as it stood then, so a palette forced past the gate
// after the publish, and before the settings were whole again, went to
// readers as though the gate had passed it.
func TestADesignLeftDueIsNotOneSavedSince(t *testing.T) {
	root, tpl := fontSite(t)
	if err := cmdConfig(root, []string{"set", "site.hsts", "24h"}); err != nil {
		t.Fatal(err)
	}
	rl := servedSite(t, root, tpl)
	whole, err := os.ReadFile(configPath(root))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath(root), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	editDraft(t, root, "index", "Published while the file was empty.")
	commitLive(t, root)
	served(rl, "/")

	// After the publish, a palette that fails the gate, saved anyway.
	if err := cmdTheme(root, []string{"set", "on-surface", "#777777", "surface", "#808080", "--dir", tpl, "--force"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath(root), whole, 0o600); err != nil {
		t.Fatal(err)
	}
	if w := served(rl, "/"); w.Header().Get("Strict-Transport-Security") != "max-age=86400" {
		t.Fatalf("the settings written whole were not read: %q", w.Header().Get("Strict-Transport-Security"))
	}
	if strings.Contains(served(rl, "/site.css").Body.String(), "#808080") {
		t.Fatal("a palette saved after the publish was checked reached readers as the publish's design")
	}
}

// A site that started with no settings of its own has none to keep, so an
// empty configuration file is only what it already had.
func TestAnEmptyConfigurationIsRefusedOnlyWhenItHidesSettings(t *testing.T) {
	root, tpl := fontSite(t)
	_ = os.Remove(configPath(root))
	rl := servedSite(t, root, tpl)
	if err := os.WriteFile(configPath(root), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	served(rl, "/")
	for _, r := range actions(t, root, "site.reload") {
		if r.Outcome != audit.Success {
			t.Fatalf("a site with no settings refused an empty file: %+v", r)
		}
	}
}

// A publish is taken when it happens, not when somebody next visits.
//
// The site looked for a publish only as requests arrived, and read the
// design from disk when it found one. On a site nobody visited for an hour
// that was an hour after the gate had checked it, and whatever templates/
// held by then went to readers: a palette forced past the gate after the
// publish (`theme set --force`, an author's authority) rode in with it.
func TestAPublishIsTakenWhenItHappensNotWhenSomebodyNextVisits(t *testing.T) {
	root, tpl := fontSite(t)
	rl := servedSite(t, root, tpl)
	rl.every = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rl.Watch(ctx)
	first := rl.Site()

	if err := cmdTheme(root, []string{"set", "radius", "3px", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	editDraft(t, root, "index", "Published to nobody.")
	if err := runPublish(t, root, "-templates", tpl); err != nil {
		t.Fatal(err)
	}
	// Nobody visits; the site takes the publish anyway.
	deadline := time.Now().Add(10 * time.Second)
	for rl.Site() == first {
		if time.Now().After(deadline) {
			t.Fatal("a publish was not taken until somebody visited")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Then a palette that fails the gate, saved anyway, after the publish.
	if err := cmdTheme(root, []string{"set", "on-surface", "#777777", "surface", "#808080", "--dir", tpl, "--force"}); err != nil {
		t.Fatal(err)
	}
	css := served(rl, "/site.css").Body.String()
	if !strings.Contains(css, "--radius: 3px") {
		t.Fatal("the published design is not the one served")
	}
	if strings.Contains(css, "#808080") {
		t.Fatal("a palette saved after the publish was checked reached readers with it")
	}
}

// The admin sees a face added to templates/fonts/ without a restart.
//
// After a face was added, the Design screen said the site "does not serve a
// font by that name" until `quilzo serve` restarted, and the preview drew
// pages without it.
func TestTheAdminSeesANewFaceWithoutARestart(t *testing.T) {
	root, tpl := fontSite(t)
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	design, err := loadDesign(tpl)
	if err != nil {
		t.Fatal(err)
	}
	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	toks := &auth.TokenStore{}
	session, _, err := toks.IssueSession("t", "dana", auth.RoleAdmin, "/", time.Hour, auth.RoleAdmin, auth.MethodPasskey)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := admin.New(s, pol, toks, design.Layouts)
	if err != nil {
		t.Fatal(err)
	}
	srv.SiteCSS = design.Stylesheet
	dw := newDesignWatch(tpl, design, func(d *Design) { srv.SetDesign(d.Layouts, d.Stylesheet) })
	dw.every = 0
	dw.say = func(string, ...any) {}
	srv.DesignSet = adminDesignHooks(tpl, dw)
	h := dw.Wrap(srv.Handler())
	as := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+session)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	if strings.Contains(as("/design").Body.String(), "<code>Aster</code>") {
		t.Fatal("the screen lists a face before there is one")
	}

	// By hand, as somebody copying a file in would.
	woff, err := addFont(t.TempDir(), "Aster.ttf", trueTypeFace(0), "Aster-400-700", false)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(woff.Path)
	if err := os.MkdirAll(filepath.Join(tpl, "fonts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tpl, "fonts", "Aster-400-700.woff"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if page := as("/design").Body.String(); !strings.Contains(page, "<code>Aster</code>") {
		t.Fatal("the Design screen does not list a face added while it ran")
	}
	if w := as("/fonts/Aster-400-700.woff"); w.Code != 200 || w.Header().Get("Content-Type") != "font/woff" {
		t.Fatalf("the preview's copy of the face: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if css := as("/site.css").Body.String(); !strings.Contains(css, "Aster-400-700.woff") {
		// The stylesheet declares every face the site serves.
		t.Error("the preview's stylesheet does not declare the face")
	}
	if as("/design").Code != 200 {
		t.Fatal("the screen")
	}
	// And the font token now accepts it on this screen, as on the terminal.
	req := httptest.NewRequest(http.MethodPost, "/design/save", strings.NewReader("token=font-body&light=Aster"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+session)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if loc := w.Header().Get("Location"); strings.Contains(loc, "e=") {
		t.Fatalf("the screen refused the face it lists: %s", loc)
	}
	saved, _ := loadThemeFile(tpl)
	if saved["font-body"] != "Aster" {
		t.Errorf("saved %v", saved)
	}
}

// editDraft changes a page's words in the draft, as an author does.
func editDraft(t *testing.T, root, page, body string) {
	t.Helper()
	path := writeTemp(t, "p.json", mustJSON(t, map[string]any{"title": "T", "body": body}))
	if err := runCmd(t, root, "add", page+"="+path, "-m", "edit"); err != nil {
		t.Fatal(err)
	}
	if err := runCmd(t, root, "provenance", "set", page, "--source", "humanEdits", "--author", "someone"); err != nil {
		t.Fatal(err)
	}
}

// commitLive moves the live ref to the draft without the gates, for a test
// about what the site does when a publish arrives rather than about whether
// one is allowed.
func commitLive(t *testing.T, root string) {
	t.Helper()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.Publish(s, ""); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Requests served while the site is being built again get a whole site, the
// one before or the one after, and never wait on the build.
func TestRequestsDuringAReloadGetAWholeSite(t *testing.T) {
	root, tpl := fontSite(t)
	rl := servedSite(t, root, tpl)
	stop := make(chan struct{})
	failed := make(chan string, 64)
	var running sync.WaitGroup
	for i := 0; i < 8; i++ {
		running.Add(1)
		go func() {
			defer running.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, path := range []string{"/", "/site.css"} {
					if w := served(rl, path); w.Code != http.StatusOK {
						failed <- path
					}
				}
			}
		}()
	}
	for i := 0; i < 5; i++ {
		if err := cmdTheme(root, []string{"set", "radius", fmt.Sprintf("%dpx", i+2), "--dir", tpl}); err != nil {
			t.Fatal(err)
		}
		if err := rl.Reload(); err != nil {
			t.Fatal(err)
		}
		editDraft(t, root, "index", fmt.Sprintf("Words %d.", i))
		commitLive(t, root)
	}
	close(stop)
	running.Wait()
	close(failed)
	for path := range failed {
		t.Errorf("%s failed during a reload", path)
	}
}

// The agent card a site serves leads with the site's own sentence.
func TestTheServedAgentCardLeadsWithTheSitesSentence(t *testing.T) {
	root, tpl := fontSite(t)
	for k, v := range map[string]string{
		"site.agent_card": "true", "site.base_url": "https://nyxvale.example",
		"site.description": "An independent games studio making fast, bright games set after dark.",
	} {
		if err := cmdConfig(root, []string{"set", k, v}); err != nil {
			t.Fatal(err)
		}
	}
	rl := servedSite(t, root, tpl)
	w := served(rl, "/.well-known/agent-card.json")
	if w.Code != 200 {
		t.Fatalf("the card: %d %s", w.Code, w.Body)
	}
	var card struct {
		Description string `json:"description"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &card); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(card.Description, "An independent games studio making fast, bright games set after dark. Content held") {
		t.Errorf("the card says %q", card.Description)
	}
}
