// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package studio

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
)

// Putting a recording in the library.
//
// # The same door
//
// Nothing here decides what a recording is. media.Accept parses it, bounds it
// and hashes it, and medialib.Put files it, measures it and takes a poster
// frame — the same functions the admin's upload and `quilzo media add` go
// through. A capture surface with its own idea of what an acceptable file
// looks like would be a third implementation of the format table, and on past
// form the one that drifted would be the one that accepted something.
//
// # What it refuses, and why each refusal is here rather than later
//
// A credential that cannot write, because an upload endpoint on an origin
// that runs script is the most attacker-interesting thing this program has.
//
// Anything that is not a recording. The browser sends video/webm and the
// browser is not the authority: the bytes are. A page could post a PNG or an
// HTML file to this endpoint, and both would be refused by the parse rather
// than by trusting the part somebody else filled in.
//
// A missing description, for images only. A recording's own description is
// useful and not load-bearing — what makes a page showing it publishable is
// captions, which are a separate file and a separate act. Requiring alt text
// here and calling it accessible would be the version of this that looks
// finished.

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	tok := s.caller(r)
	if !s.mayWrite(tok) {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return
	}
	if s.Library == nil {
		http.Error(w, "this build has no asset library wired in",
			http.StatusServiceUnavailable)
		return
	}
	lib, err := s.Library()
	if err != nil {
		http.Error(w, "the library could not be opened",
			http.StatusInternalServerError)
		return
	}

	// The body limit before the parse, not after. A limit applied to a
	// request already read into memory is a limit that did nothing.
	r.Body = http.MaxBytesReader(w, r.Body, MaxRecording)
	// Eight megabytes in memory and the rest spilled to a temporary file,
	// which for a recording is nearly all of it. The alternative is holding a
	// quarter of a gigabyte of somebody's screen in the heap to find out
	// whether it parses.
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		http.Error(w, fmt.Sprintf(
			"the recording did not arrive, or it is over the %d MB limit",
			MaxRecording>>20), http.StatusRequestEntityTooLarge)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "no recording in the request", http.StatusBadRequest)
		return
	}
	defer file.Close()

	body, err := io.ReadAll(file)
	if err != nil || len(body) == 0 {
		http.Error(w, "the recording could not be read", http.StatusBadRequest)
		return
	}

	// The name is used for display and for nothing else — the address is the
	// hash — but it still arrives from a browser, so the extension is the
	// only part read and media.Accept is what reads it.
	name := strings.TrimSpace(header.Filename)
	if name == "" {
		name = "screen-recording.webm"
	}
	f, err := media.Accept(name, body, s.now())
	if err != nil {
		http.Error(w, "that is not a recording this library accepts: "+
			err.Error(), http.StatusUnsupportedMediaType)
		return
	}
	// Recordings only. This endpoint exists to receive a capture, and a
	// general-purpose upload on an origin that runs script is a larger thing
	// than anybody asked for — the admin's form is where a photograph goes.
	if f.Kind != media.Video && f.Kind != media.Audio {
		http.Error(w, fmt.Sprintf(
			"this takes recordings, and that is not one — the bytes parse as "+
				"%s. A photograph goes in through the admin's own upload form",
			f.Kind), http.StatusUnsupportedMediaType)
		return
	}

	f.Alt = strings.TrimSpace(r.FormValue("alt"))
	f.Source = "studio"
	f.UploadedBy = tok.Principal

	if err := lib.Put(f, body); err != nil {
		http.Error(w, "the recording could not be stored: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	stored, err := lib.Stat(f.ID)
	if err != nil {
		stored = f
	}

	if s.Audit != nil {
		s.Audit("studio.upload", "/", map[string]string{
			"principal": tok.Principal, "id": medialib.ShortID(stored.ID),
			"format": stored.Format, "bytes": fmt.Sprint(stored.Size),
		})
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, describeStored(stored))
}

// describeStored is what the page shows when a recording lands.
//
// It says the next thing to do rather than only that it worked. A recording
// in the library is not yet a recording on a page, and the gate that will
// refuse the page is one nobody has met yet.
func describeStored(f media.File) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Stored as %s.\n", f.Name)
	fmt.Fprintf(&b, "In a page: /media/%s\n", f.ID)
	if f.Width > 0 {
		fmt.Fprintf(&b, "%dx%d", f.Width, f.Height)
		if f.Seconds > 0 {
			fmt.Fprintf(&b, ", %s", (time.Duration(f.Seconds * float64(time.Second))).
				Round(time.Second))
		}
		b.WriteString("\n")
	}
	if f.Poster != "" {
		fmt.Fprintf(&b, "A poster frame was taken: /media/%s\n", f.Poster)
	}
	b.WriteString("\nNext: attach captions, or a page showing this will not " +
		"publish.\n  quilzo media captions " + medialib.ShortID(f.ID) +
		" captions.vtt --lang en")
	return b.String()
}
