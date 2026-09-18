// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package compress gzips the responses that are worth gzipping.
//
// # Why this was missing and why it is the largest single win
//
// This server honoured no Accept-Encoding at all. Every page, stylesheet,
// feed, sitemap and JSON document went out as the bytes the template produced,
// to clients that had all asked for less. Measured on this program's own
// output, a rendered page compresses by about three quarters — which is three
// quarters of the bytes, three quarters of the time on a slow connection, and
// three quarters of what the operator pays for egress, for one middleware.
//
// It is also the one optimisation that helps the reader rather than the
// server. Everything else on the performance list makes this machine do less
// work; this makes the network carry less, and the network is the part of the
// path that is slow.
//
// # Why gzip only
//
// Because the standard library has gzip and does not have brotli or zstd, and
// this program has no dependencies. That is a real cost — brotli at its higher
// levels beats gzip on HTML by roughly a further fifth — and it is the price
// of the dependency policy rather than an oversight. Nothing here forecloses
// it: the negotiation reads a q-value list, so adding a coding later is adding
// a branch.
//
// # Why the ETag becomes weak
//
// A compressed response is not the bytes the strong validator named. A strong
// entity tag promises byte-for-byte identity, which is what makes it safe to
// apply a range request or a conditional update against; keeping it strong
// across a content-coding would make that promise false. A weak tag promises
// semantic equivalence, which is exactly what is true here and is all a cache
// needs. This is also what nginx does, and for the same reason.
//
// That weakening is why internal/etag exists: a client sent `W/"abc"` back, a
// server comparing the whole If-None-Match header against `"abc"` found they
// were not equal, and every revalidation of every compressed page re-sent the
// whole body while looking completely correct.
//
// # Why BREACH is not a reason to skip this here
//
// Compressing a response that mixes a secret with attacker-controlled input
// leaks the secret, one byte at a time, by watching the compressed length.
// That attack needs a secret in the body. The public server has no session, no
// cookie and no CSRF token — internal/public/forms.go explains at length why
// it has no token to leak — so a page that reflects a search term reflects it
// into a document containing nothing worth guessing.
//
// This is why the middleware is applied to the public server and not to the
// admin, which has all three of those things and reflects input into pages
// that carry them.
package compress

import (
	"compress/gzip"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// MinSize is the response size below which gzip is not attempted.
//
// Under about a kilobyte compression is a loss twice over: the deflate header
// and the ratio on a short string can make the result larger than the input,
// and the body was going to fit in one segment either way, so nothing arrives
// sooner. The floor is applied to the bytes the handler actually wrote, not to
// a Content-Length it may not have set.
const MinSize = 1024

// Level is the deflate level used.
//
// The default rather than BestSpeed, measured on a rendered page from this
// program's own demo (7,242 bytes):
//
//	level 1   2,241 bytes   69.1% saved    39µs
//	level 3   2,153 bytes   70.3% saved    56µs
//	level 6   2,069 bytes   71.4% saved    72µs
//	level 9   2,040 bytes   71.8% saved   199µs
//
// Level 6 costs 33µs more than level 1 on a response that took about 2.2ms to
// render — a one and a half percent increase in the server's work for two
// points of the reader's bandwidth. Level 9 is 2.8 times the CPU for four
// tenths of a point, which is the wrong trade in both directions at once.
const Level = gzip.DefaultCompression

// pool holds gzip writers, which are expensive to make and cheap to keep.
//
// A gzip.Writer allocates its window and hash tables on creation — tens of
// kilobytes — so a server that made one per response would spend more time in
// the allocator under load than in deflate. Reset makes one reusable.
var pool = sync.Pool{New: func() any {
	zw, err := gzip.NewWriterLevel(nil, Level)
	if err != nil {
		// Only a level outside the permitted range reaches this, which is a
		// compile-time constant above.
		panic(err)
	}
	return zw
}}

// Responses returns next with gzip applied to whatever is worth compressing.
//
// Placed outermost, so it sees the bytes that are actually going to be sent:
// the headers, the crawl gate's refusals and the marking banner's rewritten
// body are all inside it. A wrapper that sat further in would compress a body
// something else then modified.
func Responses(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !acceptsGzip(r.Header.Get("Accept-Encoding")) {
			next.ServeHTTP(w, r)
			return
		}
		cw := &writer{ResponseWriter: w, code: http.StatusOK}
		defer cw.close()
		next.ServeHTTP(cw, r)
	})
}

// writer decides, once, whether this response is compressed.
//
// A HEAD goes through this too, which looks wasteful and is not: RFC 9110
// §9.3.2 requires a HEAD to report the header fields a GET would have sent,
// and Content-Encoding is one of them. A client that asks HEAD and is told
// `identity`, then asks GET and is sent gzip, has been lied to about the
// representation. So the handler writes its body as normal, the compressor
// compresses it, and net/http discards the bytes on the way out because the
// method is HEAD — the cost is the deflate, and the result is a truthful
// answer.
//
// The decision cannot be made when the handler starts, because the thing it
// depends on — the content type — is often not set until the handler writes,
// and sometimes never set at all. So the first Write holds its bytes, and by
// the time the floor is crossed the header is as complete as it is going to
// get. This is the same reasoning as the banner writer next door, arrived at
// independently: a wrapper that reads Content-Type too early reads nothing.
type writer struct {
	http.ResponseWriter
	code        int
	wroteHeader bool

	// held is the body so far, while the decision is still open.
	held []byte
	// decided is set once the question has been answered either way.
	decided bool
	// gz is nil when this response is passing through uncompressed.
	gz *gzip.Writer
}

// WriteHeader records the status. Informational responses pass straight
// through: a 103 Early Hints carries no body, must reach the client before the
// handler has produced one, and is not the final status.
func (c *writer) WriteHeader(code int) {
	if code >= 100 && code < 200 {
		c.ResponseWriter.WriteHeader(code)
		return
	}
	if c.wroteHeader {
		return
	}
	c.code, c.wroteHeader = code, true
	// A response with no body has no decision coming, so this is the only
	// place it can be said — and it has to be said. The cache that stores a
	// 304 is the cache that will serve the 200 it refers to, and this wrapper
	// does not know from here whether that 200 was compressed.
	if c.bodyless() {
		c.announceVary()
	}
}

// bodyless reports that no body is coming, so no decision will be made.
func (c *writer) bodyless() bool {
	switch c.code {
	case http.StatusNotModified, http.StatusNoContent,
		http.StatusResetContent:
		return true
	}
	return false
}

// announceVary says the response depends on Accept-Encoding.
//
// # Why this is on the compressed responses and not on all of them
//
// Because the two mistakes are not the same size, and they point in opposite
// directions. A cache holding a gzip response under a key with no Vary hands
// it to a client that cannot decode it, and the page is a screenful of
// binary. A cache holding an identity response under a key with no Vary hands
// it to a client that asked for gzip — and every client that asks for gzip
// also accepts identity, so nothing breaks. The header goes where omitting it
// could send bytes nobody can read, and not where it would only cost a cache
// an extra dimension.
//
// That difference matters for media. This program serves images and video
// from URLs that are the hash of their contents, cacheable forever with
// nothing to purge; a Vary on those multiplies what every intermediate cache
// has to store, along a dimension where the answer never changes.
func (c *writer) announceVary() {
	if announcesEncoding(c.Header().Values("Vary")) {
		return
	}
	c.Header().Add("Vary", "Accept-Encoding")
}

// announcesEncoding reports whether Vary already names Accept-Encoding.
//
// Several field lines are equivalent to one comma list, so this looks in
// both shapes. A duplicate would be harmless to a correct cache and is still
// worth not sending.
func announcesEncoding(vary []string) bool {
	for _, line := range vary {
		for _, name := range strings.Split(line, ",") {
			if strings.EqualFold(strings.TrimSpace(name), "Accept-Encoding") {
				return true
			}
		}
	}
	return false
}

func (c *writer) Write(p []byte) (int, error) {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	if c.decided {
		if c.gz != nil {
			return c.gz.Write(p)
		}
		return c.ResponseWriter.Write(p)
	}
	// Still holding. Only the size question is open once there are enough
	// bytes to answer it.
	c.held = append(c.held, p...)
	if len(c.held) < MinSize {
		return len(p), nil
	}
	if err := c.start(); err != nil {
		return 0, err
	}
	return len(p), nil
}

// start answers the question and writes everything held so far.
func (c *writer) start() error {
	c.decided = true
	body := c.held
	c.held = nil

	if !c.worthIt(body) {
		c.ResponseWriter.WriteHeader(c.code)
		_, err := c.ResponseWriter.Write(body)
		return err
	}

	h := c.Header()
	c.announceVary()
	h.Set("Content-Encoding", "gzip")
	// The handler computed this for the uncompressed body. Correcting it would
	// mean knowing the compressed length before compressing.
	h.Del("Content-Length")
	// See the package comment: strong would now be a false promise.
	if tag := h.Get("ETag"); tag != "" && !strings.HasPrefix(tag, "W/") {
		h.Set("ETag", "W/"+tag)
	}

	c.gz = pool.Get().(*gzip.Writer)
	c.gz.Reset(c.ResponseWriter)
	c.ResponseWriter.WriteHeader(c.code)
	_, err := c.gz.Write(body)
	return err
}

// worthIt reports whether this response should be compressed.
func (c *writer) worthIt(body []byte) bool {
	h := c.Header()
	// Something upstream already encoded it, and gzipping a gzip is larger.
	if h.Get("Content-Encoding") != "" {
		return false
	}
	// A partial response is a range of a representation the client will
	// reassemble. Compressing one piece of it produces bytes that fit
	// nowhere.
	if c.code == http.StatusPartialContent || h.Get("Content-Range") != "" {
		return false
	}
	switch c.code {
	case http.StatusNoContent, http.StatusResetContent,
		http.StatusNotModified:
		return false
	}
	declared := h.Get("Content-Type")
	if declared == "" {
		// The same question Go asks when a handler sets no type, asked of the
		// same bytes. A handler that writes a page and forgets the header
		// still gets a page compressed, because the browser is still going to
		// render it as one.
		declared = http.DetectContentType(body)
	}
	return compressible(declared)
}

// compressible reports whether a media type is text under the skin.
//
// An allow list, not a deny list. Getting this wrong in the permissive
// direction means spending CPU to make a JPEG slightly bigger, on a format
// nobody thought to exclude — and the list of formats that are already
// compressed grows every year, while the list of text formats does not.
func compressible(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		// Unparseable, so unknown, so left alone.
		return false
	}
	mt = strings.ToLower(mt)
	if strings.HasPrefix(mt, "text/") {
		return true
	}
	// Structured syntax suffixes, which is how the registry says "this is
	// JSON" or "this is XML" for a type nobody has heard of. It covers
	// image/svg+xml, application/manifest+json, application/activity+json,
	// application/ld+json and every feed format, without naming them.
	if strings.HasSuffix(mt, "+json") || strings.HasSuffix(mt, "+xml") {
		return true
	}
	switch mt {
	case "application/json",
		"application/xml",
		"application/javascript",
		"application/x-javascript",
		"application/wasm",
		"application/rss+xml",
		"application/pgp-keys",
		"image/x-icon",
		"application/vnd.api+json":
		return true
	}
	return false
}

// Flush forces the decision and pushes what there is.
//
// A handler that flushes has a reason to want the bytes out now, and holding
// them back to see whether a kilobyte arrives would defeat it. So a flush
// below the floor compresses anyway rather than passing through: the
// alternative is deciding not to compress a response whose length is not yet
// known, which is the wrong way to be wrong about a long one.
func (c *writer) Flush() {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	if !c.decided {
		if err := c.start(); err != nil {
			return
		}
	}
	if c.gz != nil {
		_ = c.gz.Flush()
	}
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ReadFrom keeps the kernel's fast path for the bodies that are not going to
// be compressed.
//
// net/http's own ResponseWriter implements io.ReaderFrom, and that is what
// turns http.ServeContent on an open file into a sendfile: the bytes go from
// the page cache to the socket without ever entering this process. Wrapping
// the writer hides that method, and io.Copy silently falls back to copying
// through a buffer in userspace — which is exactly what serving video does
// most of, and a regression nobody would attribute to a compression
// middleware.
//
// So the decision is made from the head of the stream, and then the remainder
// is handed to whoever can do it fastest.
func (c *writer) ReadFrom(src io.Reader) (int64, error) {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	var total int64
	if !c.decided {
		// Through the ordinary Write path, because that is what crosses the
		// floor and answers the question. writeOnly hides this method from
		// io.CopyN, which would otherwise call it again.
		n, err := io.CopyN(writeOnly{c}, src, MinSize)
		total += n
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
	if c.gz != nil {
		n, err := io.Copy(c.gz, src)
		return total + n, err
	}
	if rf, ok := c.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(src)
		return total + n, err
	}
	n, err := io.Copy(c.ResponseWriter, src)
	return total + n, err
}

// writeOnly exposes Write and nothing else.
type writeOnly struct{ w io.Writer }

func (o writeOnly) Write(p []byte) (int, error) { return o.w.Write(p) }

// Unwrap gives http.ResponseController the real writer, so a handler can still
// set a write deadline or take the connection. Flush is implemented above and
// found first, so unwrapping does not route a flush around the compressor.
func (c *writer) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// close finishes the response, whichever way it went.
func (c *writer) close() {
	if !c.wroteHeader {
		// A handler that wrote nothing at all. Go's own behaviour is to send
		// 200 with an empty body, and that is preserved rather than improved.
		c.ResponseWriter.WriteHeader(http.StatusOK)
		return
	}
	if !c.decided {
		// Never reached the floor, so it was never worth compressing. The
		// headers the handler set — including its Content-Length, which is
		// still correct — go out untouched.
		c.decided = true
		c.ResponseWriter.WriteHeader(c.code)
		_, _ = c.ResponseWriter.Write(c.held)
		c.held = nil
		return
	}
	if c.gz != nil {
		_ = c.gz.Close()
		// Reset before returning it, so a pooled writer is not holding a
		// reference to a finished response's ResponseWriter.
		c.gz.Reset(nil)
		pool.Put(c.gz)
		c.gz = nil
	}
}

// acceptsGzip reports whether the client asked for gzip.
//
// Accept-Encoding is a q-value list, and the values matter: `gzip;q=0` means
// "not gzip", and a server that greps the header for the word sends a body the
// client said it would not decode. This has to parse.
func acceptsGzip(header string) bool {
	if header == "" {
		return false
	}
	star := -1.0
	for _, part := range strings.Split(header, ",") {
		coding, q := codingAndQuality(part)
		switch coding {
		case "gzip", "x-gzip":
			if q > 0 {
				return true
			}
			// Explicitly refused. A later wildcard does not undo a specific
			// refusal — the specific rule wins, which is the whole point of
			// naming it.
			return false
		case "*":
			star = q
		}
	}
	return star > 0
}

// codingAndQuality splits one element of an Accept-Encoding list.
func codingAndQuality(part string) (string, float64) {
	fields := strings.Split(part, ";")
	coding := strings.ToLower(strings.TrimSpace(fields[0]))
	q := 1.0
	for _, param := range fields[1:] {
		name, value, ok := strings.Cut(param, "=")
		if !ok || strings.ToLower(strings.TrimSpace(name)) != "q" {
			continue
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil {
			// A malformed q is not a refusal. Treating it as one would drop
			// compression for every client behind whatever produced it.
			continue
		}
		q = parsed
	}
	return coding, q
}
