package otlp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
)

func sample(t *testing.T) []Span {
	t.Helper()
	tr, err := NewTraceID()
	if err != nil {
		t.Fatal(err)
	}
	root, _ := NewSpanID()
	kid, _ := NewSpanID()
	start := time.Unix(1787000000, 123456789)
	return []Span{
		{TraceID: tr, SpanID: root, Name: "agent.run", Kind: KindInternal,
			Start: start, End: start.Add(time.Second),
			Attrs:      []Attr{String("quilzo.agent", "support"), Int("quilzo.did", 4), Bool("quilzo.tainted", true)},
			StatusCode: StatusOK},
		{TraceID: tr, SpanID: kid, ParentID: root, Name: "agent.step",
			Kind: KindInternal, Start: start, End: start.Add(time.Millisecond)},
	}
}

// The four OTLP/HTTP+JSON deviations from proto3 JSON.
//
// None of them is visible by looking at the output and thinking it seems
// reasonable, and each produces a payload a collector either rejects or, worse,
// silently misreads.
func TestTheJSONEncodingFollowsOTLPAndNotProto3(t *testing.T) {
	b, err := json.Marshal(Encode(sample(t), "quilzo", "1.0.0"))
	if err != nil {
		t.Fatal(err)
	}
	raw := string(b)

	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	rs := doc["resourceSpans"].([]any)[0].(map[string]any)
	ss := rs["scopeSpans"].([]any)[0].(map[string]any)
	spans := ss["spans"].([]any)
	root := spans[0].(map[string]any)

	// 1. Hex ids, not base64. Standard proto3 JSON would base64 a bytes field;
	//    OTLP overrides that, and a base64 id is silently filed under a
	//    different trace.
	id, _ := root["traceId"].(string)
	if len(id) != 32 {
		t.Errorf("traceId is %q (%d chars); OTLP wants 32 hex characters",
			id, len(id))
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			t.Errorf("traceId %q is not hex — base64 would be accepted by "+
				"proto3 JSON and rejected here", id)
			break
		}
	}

	// 2. 64-bit integers as decimal strings. As a JSON number, a nanosecond
	//    timestamp loses precision past 2^53 — which is every timestamp since
	//    1970.
	if _, isString := root["startTimeUnixNano"].(string); !isString {
		t.Errorf("startTimeUnixNano is %T, not a string. As a number it "+
			"loses precision past 2^53, which is every real timestamp",
			root["startTimeUnixNano"])
	}
	if !strings.Contains(raw, `"startTimeUnixNano":"1787000000123456789"`) {
		t.Errorf("the timestamp did not survive as an exact decimal string:\n%s",
			raw[:min(300, len(raw))])
	}

	// 3. Enums as integers, never names.
	if _, isNumber := root["kind"].(float64); !isNumber {
		t.Errorf("kind is %T; OTLP forbids the enum name and requires the "+
			"integer", root["kind"])
	}

	// 4. lowerCamelCase keys. The original snake_case field names are not
	//    valid JSON keys in OTLP.
	for _, wrong := range []string{
		"resource_spans", "scope_spans", "trace_id", "span_id",
		"start_time_unix_nano", "end_time_unix_nano", "parent_span_id",
	} {
		if strings.Contains(raw, `"`+wrong+`"`) {
			t.Errorf("the payload uses the snake_case key %q, which OTLP "+
				"does not accept", wrong)
		}
	}

	// An int attribute is also a decimal string, for the same reason.
	attrs := root["attributes"].([]any)
	var sawIntString bool
	for _, a := range attrs {
		v := a.(map[string]any)["value"].(map[string]any)
		if iv, there := v["intValue"]; there {
			if _, isString := iv.(string); !isString {
				t.Errorf("intValue is %T, not a decimal string", iv)
			}
			sawIntString = true
		}
	}
	if !sawIntString {
		t.Error("no int attribute in the fixture, so the rule above was not " +
			"exercised")
	}
}

// A root span omits parentSpanId rather than sending an empty one.
func TestARootSpanHasNoParentField(t *testing.T) {
	b, _ := json.Marshal(Encode(sample(t), "quilzo", "1.0.0"))
	var doc map[string]any
	_ = json.Unmarshal(b, &doc)
	spans := doc["resourceSpans"].([]any)[0].(map[string]any)["scopeSpans"].([]any)[0].(map[string]any)["spans"].([]any)
	root := spans[0].(map[string]any)
	if _, there := root["parentSpanId"]; there {
		t.Error("the root span carries a parentSpanId; an empty one reads as " +
			"a malformed reference rather than as absent")
	}
	child := spans[1].(map[string]any)
	if p, _ := child["parentSpanId"].(string); len(p) != 16 {
		t.Errorf("the child's parentSpanId is %q; want 16 hex characters", p)
	}
}

// service.name is present, or every trace lands under "unknown_service".
func TestTheServiceNameIsAlwaysSet(t *testing.T) {
	for _, given := range []string{"marginalia", ""} {
		b, _ := json.Marshal(Encode(sample(t), given, ""))
		if !strings.Contains(string(b), `"service.name"`) {
			t.Errorf("service=%q produced no service.name attribute", given)
		}
	}
}

// A span that would be misread is refused rather than sent.
func TestSpansThatWouldBeMisreadAreRefused(t *testing.T) {
	good := sample(t)[0]
	for name, break_ := range map[string]func(*Span){
		"zero trace id": func(s *Span) { s.TraceID = TraceID{} },
		"zero span id":  func(s *Span) { s.SpanID = SpanID{} },
		"no name":       func(s *Span) { s.Name = "" },
		"ends before it starts": func(s *Span) {
			s.End = s.Start.Add(-time.Second)
		},
	} {
		s := good
		break_(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("the unbroken span is invalid, so the cases above prove "+
			"nothing: %v", err)
	}
}

// A remote collector is refused unless the operator said so.
//
// Traces from an agent run name the pages it read and the types it was scoped
// to. Posting them to a hosted vendor is a disclosure, and it should be a
// sentence somebody typed rather than a consequence of pasting a URL.
func TestARemoteCollectorNeedsSayingSo(t *testing.T) {
	e := &Exporter{Endpoint: "https://collector.example.com"}
	err := e.Check()
	if err == nil {
		t.Fatal("a public collector was accepted by default")
	}
	if !strings.Contains(err.Error(), "disclosure") {
		t.Errorf("the refusal does not say why it matters: %v", err)
	}
	e.AllowRemote = true
	if err := e.Check(); err != nil {
		t.Errorf("an explicitly allowed remote collector was still refused: %v", err)
	}
	// Loopback is the ordinary case and must not need the flag.
	if err := (&Exporter{Endpoint: "http://127.0.0.1:4318"}).Check(); err != nil {
		t.Errorf("a sidecar collector on loopback was refused: %v", err)
	}
}

// The export reaches a collector, with the content type that selects JSON.
func TestExportPostsJSONToV1Traces(t *testing.T) {
	var gotPath, gotType string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			gotPath, gotType = r.URL.Path, r.Header.Get("Content-Type")
			gotBody, _ = readAll(r)
			w.WriteHeader(http.StatusOK)
		}))
	defer srv.Close()

	e := &Exporter{Endpoint: srv.URL, Service: "quilzo", Version: "1.0.0"}
	if err := e.Export(context.Background(), sample(t)); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/traces" {
		t.Errorf("posted to %q, want /v1/traces", gotPath)
	}
	if gotType != "application/json" {
		t.Errorf("content type %q; a collector reads the body as protobuf "+
			"without application/json and fails naming neither cause", gotType)
	}
	if !strings.Contains(string(gotBody), `"resourceSpans"`) {
		t.Errorf("the body is not an ExportTraceServiceRequest: %s",
			string(gotBody[:min(200, len(gotBody))]))
	}
}

// A collector that refuses is reported, not swallowed.
func TestACollectorErrorIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "bad span", http.StatusBadRequest)
		}))
	defer srv.Close()
	err := (&Exporter{Endpoint: srv.URL}).Export(context.Background(), sample(t))
	if err == nil {
		t.Fatal("a 400 from the collector was swallowed, so traces would " +
			"vanish with nothing said")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("the error does not name the status: %v", err)
	}
}

// A refusal is not an error, on the span or on the run.
//
// The gate working is the system behaving correctly. A backend that renders it
// red teaches operators to silence exactly the signal worth watching.
func TestARefusalIsNotAnError(t *testing.T) {
	now := time.Unix(1787000000, 0)
	tr := agent.Trace{
		Agent: "support",
		Steps: []agent.Step{
			{N: 1, Action: agent.Action{Op: "read_page"}, Allowed: true, At: now},
			{N: 2, Action: agent.Action{Op: "publish"}, Allowed: false,
				Why: "this agent does not publish", At: now.Add(time.Second)},
		},
	}
	m := agent.Manifest{Name: "support", Kind: agent.KindRetrieval,
		Autonomy: agent.AutonomyPropose,
		Budget:   agent.Budget{Steps: 8, Tools: 2, Duration: agent.Duration(time.Minute)}}
	r := agent.Receipt{Did: 1, Refused: 1, Tainted: true}

	spans, err := FromTrace(tr, r, m, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 3 {
		t.Fatalf("want a root and two steps, got %d spans", len(spans))
	}
	root := spans[0]
	if root.StatusCode == StatusError {
		t.Error("a run that refused something is marked as an error; the " +
			"gate working is not a failure")
	}
	var refused Span
	for _, s := range spans[1:] {
		for _, a := range s.Attrs {
			if a.Key == "quilzo.step.refused" && a.Bool {
				refused = s
			}
		}
	}
	if refused.Name == "" {
		t.Fatal("the refused step carries no quilzo.step.refused attribute")
	}
	if refused.StatusCode == StatusError {
		t.Error("the refused step is marked as an error")
	}
	if refused.StatusMsg == "" {
		t.Error("the refused step does not say why, which is the useful part")
	}
	// Taint is on the root, because that is what somebody filters on when
	// asking which runs needed a person.
	var sawTaint bool
	for _, a := range root.Attrs {
		if a.Key == "quilzo.tainted" && a.Bool {
			sawTaint = true
		}
	}
	if !sawTaint {
		t.Error("a tainted run is not marked as tainted on the root span")
	}
	// Every span validates, or the exporter refuses the batch at runtime.
	for _, s := range spans {
		if err := s.Validate(); err != nil {
			t.Errorf("a generated span is invalid: %v", err)
		}
	}
}

func readAll(r *http.Request) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, err := r.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
