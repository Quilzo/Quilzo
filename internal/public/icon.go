// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"fmt"
	"net/http"

	"github.com/quilzo/quilzo/internal/media"
)

// The site's icon: the picture in a browser tab, a bookmark and an
// installed app.
//
// # Why
//
// A published site had none. Every page of every site asked for
// /favicon.ico and got a 404, the tab showed a blank square, and the
// manifest that makes a site installable declared an empty list of icons —
// so an installed site got a letter on a coloured tile, chosen by the
// platform.
//
// # How
//
// One picture from the media library, named by its id in site.icon, so it
// passes the same checks as every other picture on the site and is served
// the same way. Pages link it in their head, the manifest declares it with
// its real size, and /favicon.ico answers with it for the requests a
// browser makes before it has read a page — and for the static copy, which
// carries it as a file.

// iconFile is the configured icon, when it names a picture the library has.
func (st *Site) iconFile() (media.File, bool) {
	if st.Icon == "" || !reID.MatchString(st.Icon) || st.Media == nil {
		return media.File{}, false
	}
	f, err := st.stat(st.Icon)
	if err != nil || f.Kind != media.Image {
		return media.File{}, false
	}
	return f, true
}

// iconLink is the head markup for the icon, or nothing.
func (st *Site) iconLink() string {
	if _, ok := st.iconFile(); !ok {
		return ""
	}
	return `<link rel="icon" href="/media/` + st.Icon + `">` + "\n"
}

// iconManifest is the manifest's icon list.
func (st *Site) iconManifest() []map[string]any {
	f, ok := st.iconFile()
	if !ok {
		return []map[string]any{}
	}
	icon := map[string]any{"src": "/media/" + st.Icon, "type": f.MIME(), "purpose": "any"}
	if f.Width > 0 && f.Height > 0 {
		icon["sizes"] = fmt.Sprintf("%dx%d", f.Width, f.Height)
	}
	return []map[string]any{icon}
}

// favicon answers /favicon.ico with the site's icon.
func (st *Site) favicon(w http.ResponseWriter, r *http.Request) {
	if _, ok := st.iconFile(); !ok {
		http.NotFound(w, r)
		return
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/media/" + st.Icon
	st.mediaFile(w, r2)
}
