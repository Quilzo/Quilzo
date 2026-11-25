// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package outpost

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/quilzo/quilzo/internal/attest"
)

// IntakePath is where the internal instance posts a transfer.
const IntakePath = "/.well-known/quilzo/transfer"

// The policy every answer carries: nothing runs, nothing is framed, and the
// one stylesheet comes from here.
const policy = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; " +
	"form-action 'none'; frame-ancestors 'none'"

// Handler serves the projection and nothing else.
//
// A switch over five addresses rather than a router, so what this instance
// answers is a list somebody can read in one screen: the page, the file it
// is drawn from, the head feed, security.txt, the stylesheet, and the
// intake. Every other address is not found, whatever its method, and there
// is nothing else behind it to find.
func (in *Instance) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", policy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		read := r.Method == http.MethodGet || r.Method == http.MethodHead
		switch r.URL.Path {
		case "/":
			if !read {
				notAllowed(w, "GET, HEAD")
				return
			}
			in.page(w)
		case "/attestations.json", "/heads.json", "/.well-known/security.txt":
			if !read {
				notAllowed(w, "GET, HEAD")
				return
			}
			in.file(w, r)
		case "/public.css":
			if !read {
				notAllowed(w, "GET, HEAD")
				return
			}
			h.Set("Content-Type", "text/css; charset=utf-8")
			h.Set("Cache-Control", "public, max-age=3600")
			_, _ = w.Write(attest.Stylesheet)
		case IntakePath:
			if !in.Intake {
				http.NotFound(w, r)
				return
			}
			if r.Method != http.MethodPost {
				notAllowed(w, "POST")
				return
			}
			in.intake(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func notAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "not answered at this address", http.StatusMethodNotAllowed)
}

func (in *Instance) page(w http.ResponseWriter) {
	in.serving.RLock()
	cur := in.cur
	in.serving.RUnlock()
	var (
		file  *attest.File
		heads []attest.Head
	)
	if cur != nil {
		file = cur.file
		if cur.feed != nil {
			for _, sh := range cur.feed.Heads {
				at, _ := time.Parse(time.RFC3339, sh.At)
				heads = append(heads, attest.Head{Size: sh.Size, Root: sh.Root, At: at, KeyID: sh.KeyID})
			}
		}
	}
	body, err := attest.Page(file, heads, in.Now())
	if err != nil {
		http.Error(w, "the page could not be drawn", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(body)
}

func (in *Instance) file(w http.ResponseWriter, r *http.Request) {
	name, kind := AttestationsFile, "application/json"
	switch r.URL.Path {
	case "/heads.json":
		name = FeedFile
	case "/.well-known/security.txt":
		name, kind = SecurityTxtFile, "text/plain; charset=utf-8"
	}
	in.serving.RLock()
	cur := in.cur
	in.serving.RUnlock()
	if cur == nil {
		http.NotFound(w, r)
		return
	}
	body, ok := cur.raw[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", kind)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(body)
}

// intake takes one posted transfer at a time; a second while one is being
// checked is told to come back, rather than queued behind it.
func (in *Instance) intake(w http.ResponseWriter, r *http.Request) {
	if !in.busy.CompareAndSwap(false, true) {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "a transfer is being taken; send again shortly", http.StatusTooManyRequests)
		return
	}
	defer in.busy.Store(false)
	r.Body = http.MaxBytesReader(w, r.Body, MaxEnvelope)
	rc, err := in.ImportEnvelope(r.Body, in.Now())
	w.Header().Set("Content-Type", "application/json")
	var tooBig *http.MaxBytesError
	var no Refused
	switch {
	case err == nil:
		_ = json.NewEncoder(w).Encode(rc)
		return
	case errors.As(err, &tooBig), errors.Is(err, ErrTooLarge):
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	case errors.As(err, &no):
		w.WriteHeader(http.StatusForbidden)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
