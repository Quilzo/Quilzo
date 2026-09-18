// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/listen"
	"github.com/quilzo/quilzo/internal/media"
)

// deadlineWriter records what deadline the route asked for.
//
// http.NewResponseController finds SetWriteDeadline on the writer, which is
// the same seam it uses to reach a real connection.
type deadlineWriter struct {
	http.ResponseWriter
	asked []time.Time
}

func (d *deadlineWriter) SetWriteDeadline(t time.Time) error {
	d.asked = append(d.asked, t)
	return nil
}

// videoSite serves one recording of the given size.
func videoSite(size int64) (*Site, []byte, string) {
	body := bytes.Repeat([]byte("video payload "), 1000)
	f := media.File{
		ID: strings.Repeat("b", 64), Name: "talk.webm", Format: "webm",
		Kind: media.Video, Size: size, UploadedAt: 1,
	}
	st := &Site{
		MediaStat: func(string) (media.File, error) { return f, nil },
		MediaOpen: func(string) (media.File, io.ReadSeekCloser, error) {
			return f, nopCloser{bytes.NewReader(body)}, nil
		},
		Media: func(string) (media.File, []byte, error) { return f, body, nil },
	}
	return st, body, f.ID
}

type nopCloser struct{ io.ReadSeeker }

func (nopCloser) Close() error { return nil }

// The server that serves media sets no WriteTimeout, because a deadline on
// the whole response cannot be right for both a thumbnail and a
// ninety-minute recording. A route that knows the size has to set its own, or
// nothing at all bounds a client that asks for a video and then reads
// nothing except the connection limit.
func TestTheMediaRouteSetsItsOwnWriteDeadline(t *testing.T) {
	st, body, id := videoSite(14000)

	dw := &deadlineWriter{ResponseWriter: httptest.NewRecorder()}
	before := time.Now()
	st.Handler().ServeHTTP(dw, httptest.NewRequest("GET", "/media/"+id, nil))

	if len(dw.asked) == 0 {
		t.Fatal("no write deadline was set, so a stalled reader is bounded " +
			"only by the connection limit")
	}
	got := dw.asked[0].Sub(before)
	want := listen.ResponseFor(int64(len(body)))
	// A window rather than an equality, because the clock moves between the
	// two calls.
	if got < want-time.Second || got > want+time.Second {
		t.Errorf("the deadline is %v away; for %d bytes it should be about %v",
			got, len(body), want)
	}
}

// Bigger file, longer deadline. A fixed number is the thing this replaces.
func TestABiggerFileGetsLonger(t *testing.T) {
	deadlineFor := func(size int64) time.Duration {
		st, _, id := videoSite(size)
		dw := &deadlineWriter{ResponseWriter: httptest.NewRecorder()}
		before := time.Now()
		st.Handler().ServeHTTP(dw, httptest.NewRequest("GET", "/media/"+id, nil))
		if len(dw.asked) == 0 {
			t.Fatalf("no deadline for a %d byte file", size)
		}
		return dw.asked[0].Sub(before)
	}

	small := deadlineFor(10 << 10)
	large := deadlineFor(500 << 20)
	if large <= small {
		t.Errorf("a 500MB file got %v and a 10KB file got %v", large, small)
	}
	if small > time.Minute {
		t.Errorf("a 10KB file got %v", small)
	}
}

// A ResponseWriter that cannot take a deadline is one in a test or behind
// another wrapper. Refusing to serve the file would be the wrong answer to
// that, so the route serves it and says nothing.
func TestAWriterWithNoDeadlineStillServesTheFile(t *testing.T) {
	st, body, id := videoSite(14000)
	rec := httptest.NewRecorder()
	st.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/media/"+id, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("the file was refused (%d): %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), body) {
		t.Errorf("the body is %d bytes, wanted %d", rec.Body.Len(), len(body))
	}
}
