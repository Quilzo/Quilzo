// Package otlp emits agent runs as OpenTelemetry traces.
//
// # Why this exists, and why it is not a dependency
//
// Observability is the thing every 2026 agent-engineer job description asks
// for, and the data it wants is what a Receipt already holds — what the agent
// tried, what was refused, what it spent. Quilzo had all of it and no way to
// get it out of the process.
//
// The obvious answer is go.opentelemetry.io/otel, which is a require block, a
// transitive tree, and the end of the property this project actually sells. The
// less obvious answer is that OTLP has a JSON encoding: the same protobuf
// message, mapped to JSON, posted to /v1/traces. That is encoding/json and an
// HTTP POST.
//
// # The details that make an implementation invalid
//
// OTLP/HTTP+JSON is proto3 JSON with four deviations, and getting any of them
// wrong produces something a collector rejects or, worse, silently misreads:
//
//   - traceId and spanId are hex strings, not base64. Standard proto3 JSON
//     would base64 a bytes field; OTLP overrides that.
//   - 64-bit integers are decimal STRINGS. A nanosecond timestamp as a JSON
//     number loses precision past 2^53, which is every timestamp since 1970.
//   - enums are integers. Proto3 JSON allows the name; OTLP forbids it.
//   - keys are lowerCamelCase, never the original snake_case field names.
//
// Each is asserted by a test, because none of them is visible by looking at
// the output and thinking it seems reasonable.
//
// # What is deliberately not here
//
// No metrics and no logs. Traces answer "what did this agent do and what did
// it cost", which is the question; metrics would need aggregation state and a
// push loop, and logs already have a home in the audit log that is far better
// than anything this would build. A partial implementation of three signals is
// worse than a complete implementation of one.
//
// No batching queue, no retry, no background flush. An export that fails is
// reported and dropped: telemetry that blocks a run, or that grows a buffer
// until the process dies, has made the observability worse than not having it.
package otlp

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// SpanKind values, as the enum integers OTLP requires.
//
// Named constants rather than raw numbers at the call site, and integers on the
// wire rather than the names — proto3 JSON would accept "SPAN_KIND_INTERNAL"
// and OTLP explicitly forbids it.
const (
	KindUnspecified = 0
	KindInternal    = 1
	KindServer      = 2
	KindClient      = 3
	KindProducer    = 4
	KindConsumer    = 5
)

// Status codes.
const (
	StatusUnset = 0
	StatusOK    = 1
	StatusError = 2
)

// TraceID is 16 bytes; SpanID is 8. Both are hex on the wire.
type TraceID [16]byte
type SpanID [8]byte

func (t TraceID) String() string { return hex.EncodeToString(t[:]) }
func (s SpanID) String() string  { return hex.EncodeToString(s[:]) }

// Zero reports an unset id, which is how a root span says it has no parent.
func (s SpanID) Zero() bool {
	for _, b := range s {
		if b != 0 {
			return false
		}
	}
	return true
}

// NewTraceID and NewSpanID draw from crypto/rand.
//
// Not math/rand: a trace id collision merges two unrelated runs in whatever
// backend receives them, and the id is also the thing somebody correlates a
// support ticket against.
func NewTraceID() (TraceID, error) {
	var t TraceID
	_, err := rand.Read(t[:])
	return t, err
}

func NewSpanID() (SpanID, error) {
	var s SpanID
	_, err := rand.Read(s[:])
	return s, err
}

// Attr is one key/value on a span.
//
// String, int and bool only. OTLP's AnyValue can carry arrays, maps and bytes;
// none of them is needed to describe an agent step, and each is another shape
// to encode correctly for no gain.
type Attr struct {
	Key   string
	Str   string
	Int   int64
	Bool  bool
	which byte // 's', 'i', 'b'
}

func String(k, v string) Attr { return Attr{Key: k, Str: v, which: 's'} }
func Int(k string, v int64) Attr {
	return Attr{Key: k, Int: v, which: 'i'}
}
func Bool(k string, v bool) Attr { return Attr{Key: k, Bool: v, which: 'b'} }

// Span is one unit of work.
type Span struct {
	TraceID    TraceID
	SpanID     SpanID
	ParentID   SpanID
	Name       string
	Kind       int
	Start      time.Time
	End        time.Time
	Attrs      []Attr
	StatusCode int
	StatusMsg  string
}

// -- the wire shape -----------------------------------------------------------
//
// Written as explicit types with json tags rather than assembled from maps, so
// the lowerCamelCase keys OTLP requires are checked by the compiler rather than
// by whoever typed the string.

type payload struct {
	ResourceSpans []resourceSpans `json:"resourceSpans"`
}

type resourceSpans struct {
	Resource   resource     `json:"resource"`
	ScopeSpans []scopeSpans `json:"scopeSpans"`
}

type resource struct {
	Attributes []keyValue `json:"attributes"`
}

type scopeSpans struct {
	Scope scope      `json:"scope"`
	Spans []wireSpan `json:"spans"`
}

type scope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type wireSpan struct {
	TraceID string `json:"traceId"`
	SpanID  string `json:"spanId"`
	// Omitted entirely for a root span. An empty string here is a parent id of
	// "", which some collectors read as a malformed reference rather than as
	// absent.
	ParentSpanID      string     `json:"parentSpanId,omitempty"`
	Name              string     `json:"name"`
	Kind              int        `json:"kind"`
	StartTimeUnixNano string     `json:"startTimeUnixNano"`
	EndTimeUnixNano   string     `json:"endTimeUnixNano"`
	Attributes        []keyValue `json:"attributes,omitempty"`
	Status            *status    `json:"status,omitempty"`
}

type status struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

type keyValue struct {
	Key   string   `json:"key"`
	Value anyValue `json:"value"`
}

// anyValue carries exactly one of its fields, which is why they are all
// pointers with omitempty: OTLP's AnyValue is a oneof, and emitting two would
// be ambiguous rather than merely redundant.
type anyValue struct {
	StringValue *string `json:"stringValue,omitempty"`
	IntValue    *string `json:"intValue,omitempty"`
	BoolValue   *bool   `json:"boolValue,omitempty"`
}

func attrsToWire(in []Attr) []keyValue {
	if len(in) == 0 {
		return nil
	}
	out := make([]keyValue, 0, len(in))
	for _, a := range in {
		kv := keyValue{Key: a.Key}
		switch a.which {
		case 'i':
			// A decimal string, not a number. A nanosecond timestamp or a byte
			// count past 2^53 silently loses precision as a JSON number, and
			// every timestamp since 1970 is past it.
			s := strconv.FormatInt(a.Int, 10)
			kv.Value.IntValue = &s
		case 'b':
			b := a.Bool
			kv.Value.BoolValue = &b
		default:
			s := a.Str
			kv.Value.StringValue = &s
		}
		out = append(out, kv)
	}
	return out
}

// Encode renders spans as an OTLP/HTTP+JSON ExportTraceServiceRequest.
//
// service is what the traces are attributed to; version is the build.
func Encode(spans []Span, service, version string) payload {
	ws := make([]wireSpan, 0, len(spans))
	for _, s := range spans {
		w := wireSpan{
			TraceID: s.TraceID.String(),
			SpanID:  s.SpanID.String(),
			Name:    s.Name,
			Kind:    s.Kind,
			// Decimal strings, for the reason above.
			StartTimeUnixNano: strconv.FormatInt(s.Start.UnixNano(), 10),
			EndTimeUnixNano:   strconv.FormatInt(s.End.UnixNano(), 10),
			Attributes:        attrsToWire(s.Attrs),
		}
		if !s.ParentID.Zero() {
			w.ParentSpanID = s.ParentID.String()
		}
		if s.StatusCode != StatusUnset || s.StatusMsg != "" {
			w.Status = &status{Code: s.StatusCode, Message: s.StatusMsg}
		}
		ws = append(ws, w)
	}
	svc := service
	if svc == "" {
		svc = "quilzo"
	}
	return payload{ResourceSpans: []resourceSpans{{
		Resource: resource{Attributes: attrsToWire([]Attr{
			// The one attribute every backend groups by. Omitting it produces
			// traces filed under "unknown_service", which is where telemetry
			// goes to be ignored.
			String("service.name", svc),
			String("service.version", nonEmpty(version, "dev")),
		})},
		ScopeSpans: []scopeSpans{{
			Scope: scope{Name: "quilzo/agent", Version: nonEmpty(version, "dev")},
			Spans: ws,
		}},
	}}}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// Validate refuses a span that would be misread rather than rejected.
//
// A collector will take a span with a zero trace id and file it somewhere
// useless; the failure is silent and shows up as missing data weeks later.
func (s Span) Validate() error {
	var zero TraceID
	if s.TraceID == zero {
		return fmt.Errorf("span %q has a zero trace id, so nothing can "+
			"correlate it with the run it belongs to", s.Name)
	}
	if s.SpanID.Zero() {
		return fmt.Errorf("span %q has a zero span id", s.Name)
	}
	if s.Name == "" {
		return fmt.Errorf("a span with no name is a row nobody can read")
	}
	if s.End.Before(s.Start) {
		return fmt.Errorf(
			"span %q ends before it starts, which a backend renders as a "+
				"negative duration rather than refusing", s.Name)
	}
	return nil
}
