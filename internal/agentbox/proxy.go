// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agentbox

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/quilzo/quilzo/internal/egress"
	"github.com/quilzo/quilzo/internal/fetch"
)

// Proxy is the box's only way out: an HTTP proxy to the hosts the run may
// reach, and nowhere else, with every connection recorded, refused ones
// included.
//
// It is asked before each connection by the run's own gate, so reaching a
// host is a decision of the same kind as calling a tool: the manifest
// names the host, the attempt taints the run (what comes back is somebody
// else's words), and a host the manifest does not name is refused and
// recorded rather than quietly unreachable.
type Proxy struct {
	// Allow decides a host and port. Nil allows nothing.
	Allow func(host string, port int) error
	// Dial connects to a host already allowed. Nil is the network, never
	// to an address inside it.
	Dial func(ctx context.Context, host string, port int) (net.Conn, error)
	// Record is told about every connection.
	Record func(Egress)
	// Secret is the run's own; the proxy asks for it as the password of
	// the user "run", so nothing else on this machine can borrow the run's
	// reach.
	Secret string
}

// Egress is one connection the box asked for.
type Egress struct {
	Host    string
	Port    int
	Method  string
	Allowed bool
	Why     string
	Up      int64
	Down    int64
	Took    time.Duration
}

// The ports a program may reach the outside on: the web's. A manifest names
// hosts, and a host's other ports are not what was named.
var webPorts = map[int]bool{80: true, 443: true}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.authorised(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="quilzo run"`)
		http.Error(w, "the run's proxy needs the run's credential", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		p.tunnel(w, r)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, "a proxy request names an absolute http:// address, or CONNECTs", http.StatusBadRequest)
		return
	}
	p.forward(w, r)
}

func (p *Proxy) authorised(r *http.Request) bool {
	h := r.Header.Get("Proxy-Authorization")
	enc, ok := strings.CutPrefix(h, "Basic ")
	if !ok || p.Secret == "" {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return false
	}
	user, pass, _ := strings.Cut(string(raw), ":")
	return user == "run" && subtle.ConstantTimeCompare([]byte(pass), []byte(p.Secret)) == 1
}

// decide is the gate for one host and port, recorded when it refuses.
func (p *Proxy) decide(host string, port int, method string) error {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var err error
	switch {
	case !webPorts[port]:
		err = fmt.Errorf("port %d is not one a program reaches the outside on (80 and 443)", port)
	case net.ParseIP(strings.Trim(host, "[]")) != nil:
		err = errors.New("an address rather than a host: a manifest names hosts")
	case p.Allow == nil:
		err = errors.New("this run may reach nothing")
	default:
		err = p.Allow(host, port)
	}
	if err != nil && p.Record != nil {
		p.Record(Egress{Host: host, Port: port, Method: method, Why: err.Error()})
	}
	return err
}

func (p *Proxy) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	if p.Dial != nil {
		return p.Dial(ctx, host, port)
	}
	return safeDial(ctx, host, port)
}

// safeDial resolves a host and connects to the first address, having
// refused every answer inside the network: a public name that resolves to
// a private address is how a proxy is turned on its own side.
func safeDial(ctx context.Context, host string, port int) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if err := egress.Allowed("agents", addr); err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s does not resolve", host)
	}
	for _, ip := range ips {
		if why := fetch.CheckIP(ip.IP); why != "" {
			return nil, fmt.Errorf("refusing to connect: %s", why)
		}
	}
	d := net.Dialer{Timeout: 15 * time.Second}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(ips[0].IP.String(), strconv.Itoa(port)))
}

func splitHostPort(hostport string, def int) (string, int, error) {
	host, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		if strings.Contains(err.Error(), "missing port") {
			return hostport, def, nil
		}
		return "", 0, err
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("%q is not a port", ps)
	}
	return host, port, nil
}

// counter counts bytes through a stream.
type counter struct {
	io.Reader
	n atomic.Int64
}

func (c *counter) Read(b []byte) (int, error) {
	n, err := c.Reader.Read(b)
	c.n.Add(int64(n))
	return n, err
}

func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitHostPort(r.Host, 443)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := p.decide(host, port, "CONNECT"); err != nil {
		http.Error(w, "refused: "+err.Error(), http.StatusForbidden)
		return
	}
	start := time.Now()
	up, err := p.dial(r.Context(), host, port)
	if err != nil {
		if p.Record != nil {
			p.Record(Egress{Host: host, Port: port, Method: "CONNECT", Allowed: true, Why: "could not connect: " + err.Error()})
		}
		http.Error(w, "could not connect: "+err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		up.Close()
		http.Error(w, "this server cannot tunnel", http.StatusInternalServerError)
		return
	}
	down, buf, err := hj.Hijack()
	if err != nil {
		up.Close()
		return
	}
	if _, err := down.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		up.Close()
		down.Close()
		return
	}
	sent := &counter{Reader: io.MultiReader(bufferedOf(buf), down)}
	got := &counter{Reader: up}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, sent); closeWrite(up); done <- struct{}{} }()
	go func() { _, _ = io.Copy(down, got); closeWrite(down); done <- struct{}{} }()
	<-done
	<-done
	up.Close()
	down.Close()
	if p.Record != nil {
		p.Record(Egress{Host: host, Port: port, Method: "CONNECT", Allowed: true,
			Up: sent.n.Load(), Down: got.n.Load(), Took: time.Since(start)})
	}
}

func bufferedOf(rw *bufio.ReadWriter) io.Reader {
	if rw == nil || rw.Reader.Buffered() == 0 {
		return strings.NewReader("")
	}
	b, _ := rw.Reader.Peek(rw.Reader.Buffered())
	return strings.NewReader(string(b))
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// hopHeaders are the connection's own, never forwarded.
var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitHostPort(r.URL.Host, 80)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := p.decide(host, port, r.Method); err != nil {
		http.Error(w, "refused: "+err.Error(), http.StatusForbidden)
		return
	}
	start := time.Now()
	out := r.Clone(r.Context())
	out.RequestURI = ""
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	sent := &counter{Reader: r.Body}
	out.Body = io.NopCloser(sent)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return p.dial(ctx, host, port) },
		Proxy:       nil,
	}
	defer tr.CloseIdleConnections()
	res, err := tr.RoundTrip(out)
	if err != nil {
		if p.Record != nil {
			p.Record(Egress{Host: host, Port: port, Method: r.Method, Allowed: true, Why: "could not connect: " + err.Error()})
		}
		http.Error(w, "could not connect: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	for _, h := range hopHeaders {
		res.Header.Del(h)
	}
	for k, vs := range res.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(res.StatusCode)
	n, _ := io.Copy(w, res.Body)
	if p.Record != nil {
		p.Record(Egress{Host: host, Port: port, Method: r.Method, Allowed: true,
			Up: sent.n.Load(), Down: n, Took: time.Since(start)})
	}
}
