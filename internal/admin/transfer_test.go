// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
)

// An export is the copy that ends up on removable media, and `quilzo export`
// puts the deployment's banner on every file it writes. The Transfer
// screen's export put none on anything, whatever the scheme said. It
// carries the banner it is given, and is refused when the scheme cannot be
// read, as the command line's is.
func TestAnExportFromTheScreenCarriesTheBanner(t *testing.T) {
	srv, tokens := scoped(t, auth.Binding{Principal: "ada", Role: auth.RoleAdmin, Resource: "/"})
	srv.Transfer = &Transfer{
		Pages: func() (map[string]any, error) {
			return map[string]any{"index": map[string]any{"title": "Home"}}, nil
		},
		Banner: func() (string, error) { return "OFFICIAL", nil },
	}
	w := postForm(t, srv, "/transfer/export", tokens["ada"], "format=markdown")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "OFFICIAL") {
		t.Errorf("an export from the Transfer screen carries no banner: %d\n%s", w.Code, w.Body.String())
	}

	srv.Transfer.Banner = func() (string, error) {
		return "", errors.New("the configuration cannot be read")
	}
	w = postForm(t, srv, "/transfer/export", tokens["ada"], "format=markdown")
	if w.Code == http.StatusOK || !strings.Contains(w.Header().Get("Location"), "configuration") {
		t.Errorf("an export went out with the scheme unreadable, so with no banner: %d %s",
			w.Code, w.Header().Get("Location"))
	}
}
