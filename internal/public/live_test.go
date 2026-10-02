// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A reader of a thread is told when somebody posts in it.
func TestALiveStreamSaysWhenAThreadChanges(t *testing.T) {
	st, _, _ := boardSite(t, "post")
	srv := httptest.NewServer(st.Handler())
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/live/board/talk/index", nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("the stream answered %d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}

	ada := &visitor{t: t, st: st, site: "same-origin"}
	signUp(t, ada, newDevice(t), "Ada", "")
	go func() {
		time.Sleep(300 * time.Millisecond)
		say(ada, "index", "hello")
	}()
	lines := bufio.NewScanner(res.Body)
	for lines.Scan() {
		if lines.Text() == "event: changed" {
			return
		}
	}
	t.Fatal("no change was announced after a post")
}

// The page runs the script by its hash, and nothing else, even when it is
// answered "not modified" from a cache.
func TestALivePageAllowsOnlyItsScript(t *testing.T) {
	st, _, _ := boardSite(t, "post")
	v := &visitor{t: t, st: st}
	w := v.do(http.MethodGet, "/", nil, "")
	if !strings.Contains(w.Body.String(), "<script>"+liveJS+"</script>") {
		t.Fatal("the page does not carry the live script")
	}
	if !strings.Contains(w.Body.String(), `data-live="/live/board/talk/index"`) {
		t.Error("the posts list is not marked for live updates")
	}
	csp := w.Header().Get("Content-Security-Policy")
	if got := reScriptSrc.FindString(csp); got != "script-src "+liveHash {
		t.Errorf("script-src is %q", got)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("If-None-Match", w.Header().Get("ETag"))
	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("a conditional request answered %d", rec.Code)
	}
	if got := reScriptSrc.FindString(rec.Header().Get("Content-Security-Policy")); got != "script-src "+liveHash {
		t.Errorf("a 304 carries %q, which would stop the cached page's script", got)
	}
	// A page with no comments runs nothing.
	if strings.Contains(v.do(http.MethodGet, "/plain", nil, "").Body.String(), "<script>") {
		t.Error("a page with no thread carries the live script")
	}
}

func TestAStaticCopyHasNoLiveUpdates(t *testing.T) {
	st, _, _ := boardSite(t, "post")
	files, err := st.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(files["index.html"]), liveJS) {
		t.Error("a static copy carries a script for a server it does not have")
	}
}

func TestALiveStreamIsOnlyForAThreadAVisitorMayRead(t *testing.T) {
	st, _, _ := boardSite(t, "post")
	v := &visitor{t: t, st: st}
	for _, path := range []string{"/live/board/talk/plain", "/live/board/other/index",
		"/live/board/talk/lounge", "/live/board/talk/", "/live/board/"} {
		if w := v.do(http.MethodGet, path, nil, ""); w.Code != http.StatusNotFound {
			t.Errorf("%s answered %d", path, w.Code)
		}
	}
	// One address holds a handful of streams at most.
	for i := 0; i < livePerSource; i++ {
		if !st.liveAcquire("203.0.113.9") {
			t.Fatalf("stream %d was refused", i+1)
		}
	}
	if w := v.do(http.MethodGet, "/live/board/talk/index", nil, ""); w.Code != http.StatusTooManyRequests {
		t.Errorf("a stream over the limit answered %d", w.Code)
	}
}
