// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/listen"
)

// The routes that carry a file are named to the listener, with the limit
// each handler applies, and nothing else is. The admin has no deadline on
// the whole request so that a recording can take as long as the link
// takes; the listener gives these bodies the time their size takes, when
// their handler asks, and every other body thirty seconds, so a route
// missing from here is a slow upload refused.
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

// adminBehindTheListener is the admin's handler served as cmd/quilzo serves
// it, under listen.Uploads with the routes that carry a file named, and a
// body's deadline short enough for a test to wait out.
func adminBehindTheListener(t *testing.T, srv *Server, body time.Duration) string {
	t.Helper()
	l := listen.Uploads()
	l.Body = body
	l.Files = FileBody
	hs := &http.Server{Handler: srv.Handler()}
	l.Apply(hs)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	return ln.Addr().String()
}

// Somebody signed out who posts to a route that carries a file is waited
// on for a form's time, not a file's.
//
// The listener gave every body on these routes the time a file of the
// route's limit takes as the request arrived, before anybody knew who was
// sending. Each handler answers somebody signed out without reading what
// they send, and net/http then reads up to 256 KB of what is left, to keep
// the connection, under the deadline the listener had set: a sender with no
// credential, declaring no length, was waited on for four and a half hours
// at the media library and eighteen at a site's import.
func TestSomebodySignedOutIsNotWaitedOnForAFilesTime(t *testing.T) {
	srv, _ := setup(t)
	addr := adminBehindTheListener(t, srv, 300*time.Millisecond)
	for _, path := range []string{uploadPath, exportUploadPath, recordUploadPath} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		head := "POST " + path + " HTTP/1.1\r\nHost: example.com\r\nSec-Fetch-Site: same-origin\r\n" +
			"Content-Type: multipart/form-data; boundary=x\r\nTransfer-Encoding: chunked\r\n\r\n"
		if _, err := io.WriteString(c, head); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_ = c.SetReadDeadline(start.Add(5 * time.Second))
		_, err = io.Copy(io.Discard, c)
		c.Close()
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Errorf("POST %s signed out, sending nothing, was still held after five "+
				"seconds against a form's 300ms", path)
		} else if took := time.Since(start); took > 3*time.Second {
			t.Errorf("POST %s signed out was held %v against a form's 300ms", path, took)
		}
	}
}

// Somebody signed in still has the time their file takes, on each route
// that carries one: the handler gives it once it knows who is sending, and
// a handler that did not would cut every upload off at a form's deadline.
func TestSomebodySignedInIsGivenTheTimeTheirFileTakes(t *testing.T) {
	srv, tok := setup(t)
	withLibrary(t, srv)
	var imported, brought int
	srv.Features = &FeatureHooks{ImportFile: func(filename string, body []byte, where, name string,
		pictures bool, by Actor) ([]byte, []string, error) {
		imported = len(body)
		return nil, nil, errors.New("only counting")
	}}
	srv.Data = &Data{Tree: func() (string, error) { return "", nil },
		Commit: func(string, string, string) error { return nil },
		Bring: func(coll, filename string, body []byte, o BringOptions, by Actor) (*BringResult, error) {
			brought = len(body)
			return &BringResult{}, nil
		}}
	addr := adminBehindTheListener(t, srv, 300*time.Millisecond)

	var picture bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 40, 30))
	for i := range img.Pix {
		img.Pix[i] = uint8(i * 7)
	}
	if err := png.Encode(&picture, img); err != nil {
		t.Fatal(err)
	}
	slowly := func(path string, fields map[string]string) (int, string) {
		t.Helper()
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fw, _ := mw.CreateFormFile("file", "shot.png")
		_, _ = fw.Write(picture.Bytes())
		for k, v := range fields {
			_ = mw.WriteField(k, v)
		}
		_ = mw.Close()
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(20 * time.Second))
		_, _ = fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer %s\r\n"+
			"Content-Type: %s\r\nContent-Length: %d\r\n\r\n", path, tok, mw.FormDataContentType(), body.Len())
		// Six pieces with 200ms between them: four times a form's deadline.
		b := body.Bytes()
		step := len(b)/6 + 1
		for len(b) > 0 {
			n := min(step, len(b))
			if _, err := c.Write(b[:n]); err != nil {
				t.Fatalf("POST %s: the upload was cut off: %v", path, err)
			}
			b = b[n:]
			time.Sleep(200 * time.Millisecond)
		}
		res, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		res.Body.Close()
		loc, _ := url.QueryUnescape(res.Header.Get("Location"))
		return res.StatusCode, loc
	}

	if code, loc := slowly(uploadPath, nil); code != http.StatusSeeOther || strings.Contains(loc, "could not be read") {
		t.Errorf("a slow upload to the media library answered %d, %s", code, loc)
	}
	slowly(exportUploadPath, map[string]string{"site": "https://example.org"})
	if imported != picture.Len() {
		t.Errorf("a slow import of a site's export reached the importer as %d bytes of %d",
			imported, picture.Len())
	}
	slowly(recordUploadPath, map[string]string{"collection": "events"})
	if brought != picture.Len() {
		t.Errorf("a slow spreadsheet reached the records as %d bytes of %d", brought, picture.Len())
	}
}
