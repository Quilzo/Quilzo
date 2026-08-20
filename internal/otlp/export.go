package otlp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Exporter posts spans to an OTLP/HTTP collector.
//
// # Why this does not go through internal/fetch
//
// fetch exists to stop an attacker-influenced URL reaching the inside of a
// network, so it refuses loopback and RFC1918 outright. A collector is almost
// always on loopback — the OTel agent pattern is a sidecar on :4318 — so
// routing through fetch would refuse exactly the correct configuration.
//
// The distinction is who chose the address. SSRF is a URL the request supplied;
// this is a URL the operator set in configuration, which is the same reasoning
// internal/assist applies to a model endpoint. So the check here is the inverse
// of fetch's: resolve the host and require it to be local, unless the operator
// has explicitly allowed a remote one.
//
// That default is the conservative one. Traces from an agent run carry the
// content types it read and the names of the pages it touched; posting them to
// a hosted observability vendor is a disclosure, and it should be a sentence
// somebody typed rather than a consequence of pasting a URL.
type Exporter struct {
	// Endpoint is the collector's base URL. /v1/traces is appended.
	Endpoint string
	// Headers are sent with each export, for a collector that wants an API key.
	Headers map[string]string
	// AllowRemote permits a non-local collector. Off by default; see above.
	AllowRemote bool
	// Timeout bounds one export. Telemetry must not outlive the thing it
	// describes.
	Timeout time.Duration
	// Service is what these traces are attributed to.
	Service string
	// Version is the build.
	Version string

	client *http.Client
}

// Check validates the configuration without sending anything.
//
// Called at startup so a misconfigured collector is a line on the console
// rather than a silent failure discovered when somebody goes looking for
// traces that were never sent.
func (e *Exporter) Check() error {
	if strings.TrimSpace(e.Endpoint) == "" {
		return fmt.Errorf("no collector endpoint")
	}
	u, err := url.Parse(e.Endpoint)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not a collector URL", e.Endpoint)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("a collector is reached over http or https, not %q", u.Scheme)
	}
	if e.AllowRemote {
		return nil
	}
	local, why := isLocal(u.Hostname())
	if !local {
		return fmt.Errorf(
			"the collector at %s is not local: %s.\n"+
				"  Traces from an agent run name the pages it read and the "+
				"types it was scoped to, so sending them off this machine is "+
				"a disclosure. Set the remote flag if that is what you mean",
			u.Hostname(), why)
	}
	return nil
}

// isLocal resolves a host and requires every address to be local.
//
// Every address, not the first: a name resolving to both a loopback address
// and a public one is not local, and taking the first answer would make the
// decision depend on resolver ordering.
func isLocal(host string) (bool, string) {
	if host == "" {
		return false, "it names no host"
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return false, "its address could not be resolved"
	}
	for _, ip := range ips {
		if !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
			return false, "it resolves to " + ip.String() + ", which is public"
		}
	}
	return true, ""
}

// Export sends one batch and returns.
//
// No queue, no retry, no background flush. A failed export is reported to the
// caller and dropped: telemetry that blocks a run has made the run worse, and
// telemetry that buffers until the process dies has made the outage worse.
func (e *Exporter) Export(ctx context.Context, spans []Span) error {
	if len(spans) == 0 {
		return nil
	}
	for _, s := range spans {
		if err := s.Validate(); err != nil {
			return err
		}
	}
	if err := e.Check(); err != nil {
		return err
	}

	body, err := json.Marshal(Encode(spans, e.Service, e.Version))
	if err != nil {
		return err
	}
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(e.Endpoint, "/")+"/v1/traces", bytes.NewReader(body))
	if err != nil {
		return err
	}
	// application/json, which is what selects the JSON encoding. A collector
	// receiving this with the protobuf content type reads the bytes as a
	// protobuf message and fails in a way that names neither cause.
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.Headers {
		req.Header.Set(k, v)
	}

	if e.client == nil {
		e.client = &http.Client{}
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("the collector could not be reached: %w", err)
	}
	defer resp.Body.Close()
	// Read and discard a bounded amount, so a collector answering with a
	// stream cannot hold this open.
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the collector answered %d: %s",
			resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
