// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
)

// Messages after an action, which only this server can write.
//
// Screens report the outcome of a form by redirecting to themselves with the
// sentence in the address: /media?m=Uploaded, /?e=that page is locked. Twenty
// eight places read those two parameters and put them on the screen, so
// anybody could send an administrator a link that made a trusted screen of
// this program say anything — "your session has expired, sign in again at …"
// — styled as the program's own notice. Escaped, so never markup; still words
// in the program's voice that the program did not write.
//
// Fixing it per screen is twenty-eight chances to miss one. So it is done
// here, once: a redirect this server sends that carries a message is signed
// on the way out, and a request whose message does not carry a valid
// signature has the message removed on the way in, before any handler sees
// it. A screen added next year is covered without anybody remembering.
//
// The key is per process. A message from before a restart simply does not
// show, which costs nothing: it was about a form submitted to the previous
// process.

// flashParams are the query parameters that carry a message.
var flashParams = []string{"e", "m"}

// flashSig is the parameter carrying the signature.
const flashSig = "fs"

// newFlashKey makes the per-process signing key.
func newFlashKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		// No randomness is no security anywhere in this process; refusing to
		// start is the only honest answer.
		panic("admin: cannot generate a key for signing messages: " + err.Error())
	}
	return k
}

// flashMAC is the signature over a message pair.
func flashMAC(key []byte, e, m string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("quilzo-flash\x00"))
	h.Write([]byte(e))
	h.Write([]byte{0})
	h.Write([]byte(m))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)[:18])
}

// hasFlash reports whether a query carries a message.
func hasFlash(q url.Values) bool {
	for _, p := range flashParams {
		if _, ok := q[p]; ok {
			return true
		}
	}
	return false
}

// signFlash adds a signature to a local redirect that carries a message.
// Anything off this origin is returned untouched.
func signFlash(key []byte, location string) string {
	u, err := url.Parse(location)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Opaque != "" {
		return location
	}
	q := u.Query()
	if !hasFlash(q) {
		return location
	}
	q.Set(flashSig, flashMAC(key, q.Get("e"), q.Get("m")))
	u.RawQuery = q.Encode()
	return u.String()
}

// verifyFlash strips a message this server did not sign.
func verifyFlash(key []byte, r *http.Request) {
	q := r.URL.Query()
	if !hasFlash(q) {
		if _, ok := q[flashSig]; ok {
			q.Del(flashSig)
			r.URL.RawQuery = q.Encode()
		}
		return
	}
	want := flashMAC(key, q.Get("e"), q.Get("m"))
	if hmac.Equal([]byte(q.Get(flashSig)), []byte(want)) {
		return
	}
	for _, p := range flashParams {
		q.Del(p)
	}
	q.Del(flashSig)
	r.URL.RawQuery = q.Encode()
}

// flashWriter signs the Location of a redirect as it is written.
type flashWriter struct {
	http.ResponseWriter
	key []byte
}

func (f *flashWriter) WriteHeader(code int) {
	if code >= 300 && code < 400 {
		if loc := f.Header().Get("Location"); loc != "" {
			f.Header().Set("Location", signFlash(f.key, loc))
		}
	}
	f.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (f *flashWriter) Unwrap() http.ResponseWriter { return f.ResponseWriter }

// signedFlash is the middleware: verify on the way in, sign on the way out.
func (s *Server) signedFlash(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verifyFlash(s.flashKey, r)
		next.ServeHTTP(&flashWriter{ResponseWriter: w, key: s.flashKey}, r)
	})
}
