// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package public

import (
	"net/http"
	"strings"
)

// counted records a view of every page this site answered with, and nothing
// else: an HTML response with a 200, or a 304 to a navigation, to a GET. A stylesheet, a picture, a
// feed or a 404 is not somebody reading a page. See internal/analytics for
// what is and is not kept.
func (st *Site) counted(next http.Handler) http.Handler {
	if st.Analytics == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		if r.Method != http.MethodGet {
			return
		}
		page := sw.status == http.StatusOK &&
			strings.HasPrefix(sw.Header().Get("Content-Type"), "text/html")
		// A reader going back to a page they already have is answered 304
		// with no body and no content type — and is still a view. The
		// browser says a navigation is a document; a revalidated
		// stylesheet says otherwise.
		revisit := sw.status == http.StatusNotModified &&
			r.Header.Get("Sec-Fetch-Dest") == "document"
		path := countedAs(r.URL.Path)
		if page || revisit {
			st.Analytics.Visit(r, path)
			st.convertPage(r, path)
		}
		// An address a person asked for that is not here, as the site's own
		// 404 page answers it; not one somebody hunting for an admin or
		// another product's files asked for, which the shield counts.
		if sw.status == http.StatusNotFound && strings.HasPrefix(sw.Header().Get("Content-Type"), "text/html") &&
			!IsAdminPath(r.URL.Path) && !IsForeignProbe(r.URL.Path) {
			st.Analytics.NotFound(r, path)
		}
	})
}

// countedAs is the path a request is counted under: its own, except a
// shared draft's.
//
// A shared draft's address is the only key to it (shared.go), and the
// store keeps a digest of that key so that whoever reads the store, or a
// backup, opens nothing. Counted by its path, every link anybody opened
// went into the day's totals in clear, on the disk and on the admin's
// analytics screen, and every ended one into the addresses not found. So
// they are counted together, under the prefix.
func countedAs(path string) string {
	if strings.HasPrefix(path, "/shared/") {
		return "/shared/"
	}
	return path
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
