// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package compress

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync"
	"testing"
)

// page is a body large enough to be worth compressing and repetitive enough
// to compress well, which is what HTML is.
func page(n int) string {
	return "<!doctype html><html><body>" +
		strings.Repeat("<p>the same sentence, many times over</p>", n) +
		"</body></html>"
}

// serve runs one request through the middleware.
func serve(t *testing.T, accept string, h http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if accept != "" {
		req.Header.Set("Accept-Encoding", accept)
	}
	w := httptest.NewRecorder()
	Responses(h).ServeHTTP(w, req)
	return w
}

// ungzip is what the browser does, and the only proof that matters.
func ungzip(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("the body was labelled gzip and is not: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("truncated gzip stream: %v", err)
	}
	if err := zr.Close(); err != nil {
		t.Fatalf("gzip stream did not close: %v", err)
	}
	return string(out)
}

func html(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, body)
	}
}

func TestAPageIsCompressedAndSurvivesTheRoundTrip(t *testing.T) {
	body := page(200)
	res := serve(t, "gzip", html(body))

	if got := res.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding is %q", got)
	}
	if out := ungzip(t, res.Body.Bytes()); out != body {
		t.Fatalf("the page did not survive: %d bytes in, %d out",
			len(body), len(out))
	}
	if res.Body.Len() >= len(body) {
		t.Errorf("compressed to %d from %d, which is not a saving",
			res.Body.Len(), len(body))
	}
	t.Logf("%d -> %d bytes (%.0f%% saved)", len(body), res.Body.Len(),
		100*(1-float64(res.Body.Len())/float64(len(body))))
}

// The header that stops a shared cache handing a gzip body to a client that
// cannot read one. Its absence is invisible from the origin.
func TestVaryIsAnnounced(t *testing.T) {
	res := serve(t, "gzip", html(page(200)))
	if !announcesEncoding(res.Header().Values("Vary")) {
		t.Fatalf("Vary is %q", res.Header().Values("Vary"))
	}
}

// Not announced on a response that was not compressed, and the asymmetry is
// the reason. A cache holding a gzip body under an unvaried key hands binary
// to a client that cannot decode it; a cache holding an identity body under an
// unvaried key hands it to a client that asked for gzip, and every such client
// accepts identity too. So the header goes where omitting it breaks something.
//
// The case this buys: media served from a URL that is the hash of its own
// contents, cached forever, without a Vary dimension along which the answer
// never changes.
func TestVaryIsNotClaimedByAnUncompressedResponse(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"below the floor": html("<p>hi</p>"),
		"not text": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/jpeg")
			_, _ = w.Write(bytes.Repeat([]byte{0xff}, 4000))
		},
	}
	for name, h := range cases {
		res := serve(t, "gzip", h)
		if res.Header().Get("Content-Encoding") != "" {
			t.Fatalf("%s: was compressed after all", name)
		}
		if announcesEncoding(res.Header().Values("Vary")) {
			t.Errorf("%s: claimed to vary on an answer that does not: %q",
				name, res.Header().Values("Vary"))
		}
	}
}

func TestAClientThatDidNotAskGetsThePlainBody(t *testing.T) {
	body := page(200)
	for _, accept := range []string{"", "identity", "deflate", "br"} {
		res := serve(t, accept, html(body))
		if res.Header().Get("Content-Encoding") != "" {
			t.Errorf("Accept-Encoding: %q got a coding it did not ask for", accept)
		}
		if res.Body.String() != body {
			t.Errorf("Accept-Encoding: %q body changed", accept)
		}
	}
}

// `gzip;q=0` is a refusal. A server that greps the header for the word sends a
// body the client has said it will not decode.
func TestARefusalIsHonoured(t *testing.T) {
	for _, accept := range []string{"gzip;q=0", "gzip; q=0", "gzip;q=0.0", "gzip;q=0, *"} {
		res := serve(t, accept, html(page(200)))
		if got := res.Header().Get("Content-Encoding"); got != "" {
			t.Errorf("Accept-Encoding: %q was sent %q anyway", accept, got)
		}
	}
}

func TestQValuesAndWildcards(t *testing.T) {
	yes := []string{"gzip", "GZIP", "x-gzip", "gzip;q=1", "gzip;q=0.1",
		"br, gzip", "*", "*;q=0.5", "deflate, *", "identity;q=0, gzip"}
	no := []string{"*;q=0", "br", "identity", "deflate;q=1, *;q=0", ""}
	for _, h := range yes {
		if !acceptsGzip(h) {
			t.Errorf("%q should accept gzip", h)
		}
	}
	for _, h := range no {
		if acceptsGzip(h) {
			t.Errorf("%q should not accept gzip", h)
		}
	}
}

// A malformed parameter is not a refusal: treating it as one would silently
// drop compression for every client behind whatever produced it.
func TestAMalformedQualityIsNotARefusal(t *testing.T) {
	for _, h := range []string{"gzip;q=", "gzip;q=abc", "gzip;;q=1", "gzip;x=y"} {
		if !acceptsGzip(h) {
			t.Errorf("%q was read as a refusal", h)
		}
	}
}

// The floor. Below it deflate can make the body larger, and it was arriving in
// one segment either way.
func TestAShortBodyIsLeftAlone(t *testing.T) {
	res := serve(t, "gzip", html("<p>short</p>"))
	if res.Header().Get("Content-Encoding") != "" {
		t.Error("a short body was compressed")
	}
	if res.Body.String() != "<p>short</p>" {
		t.Errorf("body is %q", res.Body.String())
	}
}

// Written in pieces, which is how a template writes. The floor is about the
// whole response, not about any one Write.
func TestManySmallWritesStillCrossTheFloor(t *testing.T) {
	want := strings.Repeat("<p>a paragraph of some length</p>", 300)
	res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		for i := 0; i < 300; i++ {
			_, _ = io.WriteString(w, "<p>a paragraph of some length</p>")
		}
	})
	if res.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("not compressed; Content-Encoding %q", res.Header().Get("Content-Encoding"))
	}
	if got := ungzip(t, res.Body.Bytes()); got != want {
		t.Errorf("body did not survive being written in pieces: %d vs %d bytes",
			len(got), len(want))
	}
}

// Media is already compressed. Gzipping a JPEG spends CPU to make it bigger.
func TestAlreadyCompressedFormatsAreSkipped(t *testing.T) {
	for _, ct := range []string{"image/jpeg", "image/png", "image/webp",
		"video/mp4", "audio/mpeg", "font/woff2", "application/zip",
		"application/gzip", "application/pdf"} {
		res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", ct)
			_, _ = w.Write(bytes.Repeat([]byte("x"), 8000))
		})
		if got := res.Header().Get("Content-Encoding"); got != "" {
			t.Errorf("%s was compressed", ct)
		}
	}
}

// The types this program actually serves, named so a change to the allow list
// has to face them.
func TestTheTypesThisProgramServesAreCompressed(t *testing.T) {
	for _, ct := range []string{
		"text/html; charset=utf-8",
		"text/css; charset=utf-8",
		"text/plain; charset=utf-8",
		"text/javascript",
		"application/json",
		"application/xml",
		"image/svg+xml",
		"application/manifest+json",
		"application/activity+json",
		"application/ld+json",
		"application/atom+xml",
		"application/feed+json",
	} {
		res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", ct)
			_, _ = io.WriteString(w, page(200))
		})
		if res.Header().Get("Content-Encoding") != "gzip" {
			t.Errorf("%s was not compressed", ct)
		}
	}
}

// A handler that sets no type still gets a page compressed, because the
// browser is still going to render it as one. This is the mistake a wrapper
// that reads Content-Type before the first Write makes.
func TestAnUndeclaredPageIsStillRecognised(t *testing.T) {
	body := page(200)
	res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	})
	if res.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("an undeclared HTML body was not compressed")
	}
	if got := ungzip(t, res.Body.Bytes()); got != body {
		t.Error("the undeclared body did not survive")
	}
}

// Strong would now be a false promise: these are not the bytes the tag named.
func TestTheETagIsWeakenedWhenCompressed(t *testing.T) {
	res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("ETag", `"abc"`)
		_, _ = io.WriteString(w, page(200))
	})
	if got := res.Header().Get("ETag"); got != `W/"abc"` {
		t.Errorf("ETag is %q", got)
	}
}

func TestAnUncompressedResponseKeepsItsStrongETag(t *testing.T) {
	res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("ETag", `"abc"`)
		_, _ = io.WriteString(w, "<p>short</p>")
	})
	if got := res.Header().Get("ETag"); got != `"abc"` {
		t.Errorf("ETag is %q", got)
	}
}

func TestAnAlreadyWeakETagIsNotWeakenedTwice(t *testing.T) {
	res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("ETag", `W/"abc"`)
		_, _ = io.WriteString(w, page(200))
	})
	if got := res.Header().Get("ETag"); got != `W/"abc"` {
		t.Errorf("ETag is %q", got)
	}
}

// Left as it was, because it describes the uncompressed body and a corrected
// one cannot be known before compressing.
func TestContentLengthIsDroppedWhenCompressed(t *testing.T) {
	res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Length", "99999")
		_, _ = io.WriteString(w, page(200))
	})
	if got := res.Header().Get("Content-Length"); got != "" {
		t.Errorf("Content-Length survived as %q and describes nothing", got)
	}
}

// A body that is not there is not compressed, and the status is preserved.
func TestStatusesWithoutABodyPassThrough(t *testing.T) {
	for _, code := range []int{http.StatusNotModified, http.StatusNoContent,
		http.StatusResetContent} {
		res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", `"abc"`)
			w.WriteHeader(code)
		})
		if res.Code != code {
			t.Errorf("status %d became %d", code, res.Code)
		}
		if res.Header().Get("Content-Encoding") != "" {
			t.Errorf("%d was given a content coding", code)
		}
		if got := res.Header().Get("ETag"); got != `"abc"` {
			t.Errorf("%d: ETag became %q", code, got)
		}
	}
}

// A 304 must still say the response varies, because the cache that stores it
// is the cache that will serve the 200 it refers to.
func TestA304StillAnnouncesVary(t *testing.T) {
	res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	})
	if !announcesEncoding(res.Header().Values("Vary")) {
		t.Errorf("Vary is %q", res.Header().Values("Vary"))
	}
}

// A range is a piece of a representation the client reassembles. One
// compressed piece fits nowhere.
func TestAPartialResponseIsNotCompressed(t *testing.T) {
	res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Range", "bytes 0-7999/100000")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(bytes.Repeat([]byte("a"), 8000))
	})
	if got := res.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("a 206 was compressed as %q", got)
	}
	if res.Body.Len() != 8000 {
		t.Errorf("the range is %d bytes, not 8000", res.Body.Len())
	}
}

// Something further in already encoded it. Gzipping a gzip is larger.
func TestAnEncodedResponseIsLeftAlone(t *testing.T) {
	res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(bytes.Repeat([]byte("a"), 8000))
	})
	if got := res.Header().Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding became %q", got)
	}
	if res.Body.Len() != 8000 {
		t.Errorf("the body was re-encoded: %d bytes", res.Body.Len())
	}
	if announcesEncoding(res.Header().Values("Vary")) {
		t.Error("a response that was going out encoded regardless claimed to vary")
	}
}

// A HEAD must report the header fields a GET would have sent, and
// Content-Encoding is one of them: a client told `identity` by a HEAD and sent
// gzip by a GET has been lied to about the representation.
//
// Over a real connection, because the body is discarded by net/http on the
// way out and a recorder does not do that.
func TestHeadReportsWhatAGetWouldSend(t *testing.T) {
	srv := httptest.NewServer(Responses(html(page(200))))
	t.Cleanup(srv.Close)
	tr := &http.Transport{DisableCompression: true}

	get, err := request(tr, http.MethodGet, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	head, err := request(tr, http.MethodHead, srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	if got := head.Header.Get("Content-Encoding"); got != get.Header.Get("Content-Encoding") {
		t.Errorf("HEAD said Content-Encoding %q where GET says %q",
			got, get.Header.Get("Content-Encoding"))
	}
	if got := head.Header.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding is %q", got)
	}
	body, err := io.ReadAll(head.Body)
	if err != nil {
		t.Fatal(err)
	}
	head.Body.Close()
	get.Body.Close()
	if len(body) != 0 {
		t.Errorf("a HEAD was answered with %d bytes of body", len(body))
	}
}

// request makes one request that asks for gzip and does not decode it.
func request(tr *http.Transport, method, url string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "gzip")
	return tr.RoundTrip(req)
}

// The status the handler chose, not the one the wrapper assumed. An error page
// is HTML and is worth compressing.
func TestTheStatusSurvivesCompression(t *testing.T) {
	body := page(200)
	res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, body)
	})
	if res.Code != http.StatusNotFound {
		t.Fatalf("status is %d", res.Code)
	}
	if res.Header().Get("Content-Encoding") != "gzip" {
		t.Error("a 404 page was not compressed")
	}
	if ungzip(t, res.Body.Bytes()) != body {
		t.Error("the 404 body did not survive")
	}
}

// An Early Hints response arrives before the handler has a body and is not the
// final status. Held back it would be useless; treated as final it would
// replace the status.
//
// Over a real connection, because httptest.ResponseRecorder records the first
// WriteHeader and ignores the rest — it cannot model an informational
// response, so a recorder here would prove the opposite of what it looks like.
func TestEarlyHintsPassStraightThrough(t *testing.T) {
	body := page(200)
	srv := httptest.NewServer(Responses(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Link", "</site.css>; rel=preload; as=style")
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, body)
		})))
	t.Cleanup(srv.Close)

	var hinted []string
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	ctx := httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
			if code == http.StatusEarlyHints {
				hinted = h.Values("Link")
			}
			return nil
		},
	})
	// The default transport would decompress and delete the header, which is
	// the one thing under test.
	res, err := (&http.Transport{DisableCompression: true}).RoundTrip(
		req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("the informational status became the final one: %d", res.StatusCode)
	}
	if len(hinted) == 0 {
		t.Error("the Early Hints response did not reach the client")
	}
	if res.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("the page after the hints was not compressed: %q",
			res.Header.Get("Content-Encoding"))
	}
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if ungzip(t, raw) != body {
		t.Error("the body did not survive")
	}
}

// A handler with a reason to want bytes out now. Holding them to see whether a
// kilobyte arrives would defeat it.
func TestAFlushSendsWhatThereIs(t *testing.T) {
	res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<p>first</p>")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.WriteString(w, "<p>second</p>")
	})
	if res.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("a flushed response was not compressed: %q",
			res.Header().Get("Content-Encoding"))
	}
	if got := ungzip(t, res.Body.Bytes()); got != "<p>first</p><p>second</p>" {
		t.Errorf("body is %q", got)
	}
}

// A handler that writes nothing still gets Go's own answer.
func TestAHandlerThatWritesNothing(t *testing.T) {
	res := serve(t, "gzip", func(w http.ResponseWriter, r *http.Request) {})
	if res.Code != http.StatusOK {
		t.Errorf("status is %d", res.Code)
	}
	if res.Body.Len() != 0 {
		t.Errorf("body is %q", res.Body.String())
	}
}

// The writers are pooled, so a leak between responses would be a page served
// into another reader's connection. This is the test that would catch it.
func TestPooledWritersDoNotBleedBetweenResponses(t *testing.T) {
	h := Responses(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, page(50)+r.URL.Path)
	}))
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/p"+strings.Repeat("x", i), nil)
			req.Header.Set("Accept-Encoding", "gzip")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			want := page(50) + req.URL.Path
			zr, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
			if err != nil {
				t.Errorf("%s: %v", req.URL.Path, err)
				return
			}
			got, err := io.ReadAll(zr)
			if err != nil {
				t.Errorf("%s: %v", req.URL.Path, err)
				return
			}
			if string(got) != want {
				t.Errorf("%s got another response's body", req.URL.Path)
			}
		}(i)
	}
	wg.Wait()
}

// An unparseable type is an unknown type, and unknown is left alone.
func TestAnUnparseableContentTypeIsLeftAlone(t *testing.T) {
	if compressible("text/html; charset=") {
		t.Error("a malformed type was treated as text")
	}
	if compressible("") {
		t.Error("an empty type was treated as text")
	}
}

// counter is a ResponseWriter that can take a reader, like net/http's own.
type counter struct {
	http.ResponseWriter
	readFroms int
	got       bytes.Buffer
}

func (c *counter) ReadFrom(src io.Reader) (int64, error) {
	c.readFroms++
	return io.Copy(&c.got, src)
}

func (c *counter) Write(p []byte) (int, error) {
	return c.got.Write(p)
}

// Serving a video is mostly copying a file to a socket, which net/http does
// with sendfile — but only if it is asked through io.ReaderFrom. A wrapper
// that hides that method turns every video into a userspace copy, and nobody
// would look for the cause in a compression middleware.
func TestAnUncompressedBodyKeepsTheKernelFastPath(t *testing.T) {
	want := bytes.Repeat([]byte("mp4 payload "), 20000)
	rec := httptest.NewRecorder()
	c := &counter{ResponseWriter: rec}

	Responses(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		// What http.ServeContent does: io.CopyN wraps the source in an
		// io.LimitedReader, which is not an io.WriterTo, so the copy asks
		// the destination instead. A plain io.Copy from a bytes.Reader
		// would be answered by the reader's own WriteTo and never reach
		// ReadFrom at all.
		_, _ = io.CopyN(w, bytes.NewReader(want), int64(len(want)))
	})).ServeHTTP(c, requestFor("gzip"))

	if c.readFroms == 0 {
		t.Fatal("the remainder was copied in userspace; sendfile is gone")
	}
	if !bytes.Equal(c.got.Bytes(), want) {
		t.Errorf("the body changed: %d bytes, wanted %d", c.got.Len(), len(want))
	}
}

// The same path, but the body is text this time, so it must be compressed
// rather than handed to the kernel.
func TestACompressibleBodyIsNotHandedToTheKernel(t *testing.T) {
	want := bytes.Repeat([]byte("<p>a paragraph</p>"), 5000)
	rec := httptest.NewRecorder()
	c := &counter{ResponseWriter: rec}

	Responses(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.CopyN(w, bytes.NewReader(want), int64(len(want)))
	})).ServeHTTP(c, requestFor("gzip"))

	if c.readFroms != 0 {
		t.Error("a compressible body was passed through uncompressed")
	}
	if got := ungzip(t, c.got.Bytes()); got != string(want) {
		t.Errorf("the body did not survive: %d bytes", len(got))
	}
}

// A body shorter than the floor, arriving through the same path.
func TestAShortBodyThroughReadFrom(t *testing.T) {
	rec := httptest.NewRecorder()
	c := &counter{ResponseWriter: rec}
	Responses(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.CopyN(w, strings.NewReader("<p>short</p>"), 12)
	})).ServeHTTP(c, requestFor("gzip"))

	if got := c.got.String(); got != "<p>short</p>" {
		t.Errorf("body is %q", got)
	}
}

func requestFor(accept string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", accept)
	return req
}
