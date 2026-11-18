// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The routes that carry a file are named to the listener, with the limit
// each handler applies, and nothing else is. The admin has no deadline on
// the whole request so that a recording can take as long as the link
// takes; the listener gives these bodies the time their size takes and
// every other body thirty seconds, so a route missing from here is a slow
// upload refused, and one wrongly here is a form a dribbling sender may
// hold for hours.
func TestEveryRouteThatCarriesAFileIsNamedToTheListener(t *testing.T) {
	for path, want := range map[string]int64{
		uploadPath:       MaxUpload,
		exportUploadPath: MaxExportUpload + 1<<20,
		recordUploadPath: MaxRecordUpload + 1<<20,
	} {
		got := FileBody(httptest.NewRequest(http.MethodPost, path, nil))
		if got != want {
			t.Errorf("POST %s: %d, and its handler reads %d", path, got, want)
		}
		if got <= MaxRequestBody {
			t.Errorf("POST %s takes no more than a form", path)
		}
		if g := FileBody(httptest.NewRequest(http.MethodGet, path, nil)); g != 0 {
			t.Errorf("GET %s carries no file and was given %d", path, g)
		}
	}
	for _, path := range []string{"/signin", "/save", "/mcp", "/v1/chat/completions", "/api/v1/pages"} {
		if g := FileBody(httptest.NewRequest(http.MethodPost, path, nil)); g != 0 {
			t.Errorf("POST %s is a form, and was given %d as a file", path, g)
		}
	}
}
