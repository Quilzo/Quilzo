// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"html/template"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Surface is where an address is served.
type Surface string

const (
	// AdminSurface is the admin, which only the people who run the store
	// reach: a refusal there says what is off and how to switch it back.
	AdminSurface Surface = "admin"
	// SiteSurface is the public site, where a refusal is a plain not found:
	// a visitor has no use for the installation's profile, and an attacker
	// has some.
	SiteSurface Surface = "site"
)

// OffHeader names the feature an admin address belongs to, on the answer
// that refuses it, so a program reading the admin can tell switched off from
// missing without parsing the page.
const OffHeader = "X-Quilzo-Switched-Off"

var refusalPage = template.Must(template.New("off").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Switched off: {{.Title}}</title>
<style>
:root{color-scheme:light dark}
body{font:1rem/1.5 system-ui,sans-serif;margin:0;padding:1rem;background:Canvas;color:CanvasText}
main{max-width:40rem;margin:2rem auto}
code{font-family:ui-monospace,monospace;overflow-wrap:anywhere}
a{color:LinkText}
a:focus-visible{outline:3px solid Highlight;outline-offset:2px}
</style></head>
<body><main>
<h1>Switched off: {{.Title}}</h1>
<p>This installation runs the security profile, which switches this feature off, because {{.Why}}.</p>
<p>Nothing is removed. An administrator can switch it back on, with a reason that is kept in the
record, on the <a href="/security/profile">Security profile</a> screen or with:</p>
<p><code>quilzo profile enable {{.Name}} --reason "why it is needed"</code></p>
</main></body></html>
`))

const siteRefusal = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Not found</title></head>
<body><main><h1>Not found</h1><p>Nothing is served at this address.</p></main></body></html>
`

// Gate answers the addresses of switched-off features with 404, and passes
// every other request to h. state is asked on every request, so a feature
// switched back on from the admin or the command line is served from the
// next request rather than the next restart.
func Gate(h http.Handler, on Surface, state func() *State) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, off := state().Refuses(on, r.URL.Path)
		if !off {
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if on != AdminSurface {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(siteRefusal))
			return
		}
		w.Header().Set(OffHeader, f.Name)
		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"` + f.Name + ` is switched off by the security profile",` +
				`"fix":"quilzo profile enable ` + f.Name + ` --reason WHY"}` + "\n"))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_ = refusalPage.Execute(w, f)
	})
}

// Watch is a store's state as its file says now, read again only when the
// file has changed, so the check on every request is one stat.
//
// A file that cannot be read is Closed: everything off.
func Watch(path string) func() *State {
	var (
		mu    sync.Mutex
		size  int64 = -1
		mtime time.Time
		held  = &State{}
	)
	return func() *State {
		mu.Lock()
		defer mu.Unlock()
		fi, err := os.Stat(path)
		switch {
		case os.IsNotExist(err):
			size, mtime, held = -1, time.Time{}, &State{}
			return held
		case err != nil:
			return Closed()
		}
		if fi.Size() == size && fi.ModTime().Equal(mtime) {
			return held
		}
		st, err := Load(path)
		if err != nil {
			// Not remembered: the next request reads it again, so a file
			// put right is served from then on.
			return Closed()
		}
		size, mtime, held = fi.Size(), fi.ModTime(), st
		return held
	}
}
