package public

import (
	"fmt"
	"html"
	"net/http"
	"strings"
)

// notFound serves a 404 that belongs to the site.
//
// Go's http.NotFound writes "404 page not found" as plain text. On a CMS whose
// entire visible surface is otherwise designed, that is the one page a visitor
// is most likely to reach from a stale link or a search result, rendered as a
// debugging string.
//
// It carries no content from the request. Reflecting the path a visitor asked
// for is the standard way a 404 page becomes a cross-site scripting hole, and
// the path is already in their address bar — showing it back adds nothing they
// cannot see.
func (st *Site) notFound(w http.ResponseWriter, r *http.Request) {
	name := st.Name
	if strings.TrimSpace(name) == "" {
		name = "This site"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	if r.Method == http.MethodHead {
		return
	}
	css := ""
	if st.Stylesheet != "" {
		css = `<link rel="stylesheet" href="/site.css">`
	}
	fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Page not found — %s</title>
%s
<style>
  .quilzo-404 { max-width: 40rem; margin: 12vh auto; padding: 0 1.5rem;
    font-family: system-ui, sans-serif; line-height: 1.6; }
  .quilzo-404 h1 { font-size: 2rem; margin: 0 0 .5rem; }
  .quilzo-404 p { margin: 0 0 1rem; }
</style>
</head>
<body>
<main class="quilzo-404">
  <h1>Page not found</h1>
  <p>There is nothing at this address on %s. It may have been moved or
     removed.</p>
  <p><a href="/">Go to the home page</a></p>
</main>
</body>
</html>
`, html.EscapeString(name), css, html.EscapeString(name))
}
