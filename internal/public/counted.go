// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

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
		if page || revisit {
			st.Analytics.Visit(r, r.URL.Path)
			st.convertPage(r, r.URL.Path)
		}
	})
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
