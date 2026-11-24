// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package siem

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
)

// stored is the log as audit.Export writes it: the bytes on disk.
func stored(t *testing.T, events []audit.Event) string {
	t.Helper()
	var b bytes.Buffer
	if err := audit.Export(events, &b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// The log as it is stored and the JSON Lines export are one export: the
// same bytes, from one serializer, and recorded the same way.
//
// `quilzo auditlog export` was an exporter of its own beside this one. It
// wrote with audit.Export where `quilzo siem jsonl` wrote with its own
// encoder, and recorded nothing where this recorded auditlog.export, so
// the two copies of one log could drift apart in what they wrote and one of
// them left no trace of having been taken.
func TestTheLogAsStoredIsTheJSONLinesExport(t *testing.T) {
	events := log(t, []byte("0123456789abcdef0123456789abcdef"))
	var details []map[string]string
	rec := func(d map[string]string) { details = append(details, d) }

	asStored, err := ExportRecorded(JSONL, events, Options{AsStored: true}, now, rec)
	if err != nil {
		t.Fatal(err)
	}
	jsonl, err := ExportRecorded(JSONL, events, Options{}, now, rec)
	if err != nil {
		t.Fatal(err)
	}
	if asStored.Body != stored(t, events) || jsonl.Body != asStored.Body {
		t.Error("the log as stored and the JSON Lines export are not the same bytes")
	}
	if len(details) != 2 {
		t.Fatalf("two exports were recorded %d time(s)", len(details))
	}
	if a, b := slices.Sorted(maps.Keys(details[0])), slices.Sorted(maps.Keys(details[1])); !slices.Equal(a, b) {
		t.Errorf("the two exports were recorded with %v and %v", a, b)
	}
	if details[0]["format"] != "raw" || details[1]["format"] != "jsonl" {
		t.Errorf("the formats were recorded as %q and %q", details[0]["format"], details[1]["format"])
	}
	for _, d := range details {
		if d["events"] != "4" || d["range"] != "1-4" || d["identifiers_requested"] != "false" {
			t.Errorf("an export was recorded as %v", d)
		}
	}
}

// A log whose chain is broken is exported as it is stored, in the order it
// is stored, when that is what was asked for, so it can be taken away and
// examined; the export to a SIEM still refuses it, and neither refusal nor
// failure is recorded as an export.
func TestABrokenChainIsExportedAsStoredAndOnlySo(t *testing.T) {
	events := log(t, nil)
	events[1].Resource = "/altered"
	events[2], events[3] = events[3], events[2]
	var recorded int
	rec := func(map[string]string) { recorded++ }

	res, err := ExportRecorded(JSONL, events, Options{AsStored: true}, now, rec)
	if err != nil {
		t.Fatalf("a broken chain was not exported as stored: %v", err)
	}
	if res.Body != stored(t, events) {
		t.Error("the broken chain was not written as it is stored")
	}
	if _, err := ExportRecorded(JSONL, events, Options{}, now, rec); err == nil {
		t.Error("a broken chain was exported to a SIEM")
	}
	if _, err := ExportRecorded(OCSF, events, Options{AsStored: true}, now, rec); err == nil ||
		!strings.Contains(err.Error(), "jsonl") {
		t.Errorf("the log as stored was rendered as OCSF: %v", err)
	}
	if recorded != 1 {
		t.Errorf("one export and two refusals were recorded %d time(s)", recorded)
	}
}

// An empty log is an empty export as it is stored, recorded with no
// events, as `quilzo auditlog export` has always answered it with success.
func TestAnEmptyLogIsAnEmptyExportAsStored(t *testing.T) {
	var detail map[string]string
	res, err := ExportRecorded(JSONL, nil, Options{AsStored: true}, now, func(d map[string]string) { detail = d })
	if err != nil || res.Body != "" || res.Count != 0 {
		t.Fatalf("an empty log exported as %+v, %v", res, err)
	}
	if detail["events"] != "0" || detail["range"] != "0-0" {
		t.Errorf("an empty export was recorded as %v", detail)
	}
}

// The log as it is stored says what it holds as every other export does:
// pseudonymous when every identifier in it is a handle, whether or not
// identifiers were asked for, and not when it names people as they are, and
// its record says the same.
func TestTheLogAsStoredSaysWhatItHolds(t *testing.T) {
	key, _ := audit.NewKey()
	for _, c := range []struct {
		key    []byte
		reveal bool
		want   bool
	}{{key, true, true}, {key, false, true}, {nil, false, false}, {nil, true, false}} {
		var detail map[string]string
		res, err := ExportRecorded(JSONL, log(t, c.key), Options{AsStored: true, Reveal: c.reveal}, now,
			func(d map[string]string) { detail = d })
		if err != nil {
			t.Fatal(err)
		}
		if res.Chain.Pseudonymous != c.want || res.Redacted != c.want || detail["pseudonymous"] != fmt.Sprint(c.want) {
			t.Errorf("keyed %v, identifiers asked for %v: pseudonymous %v, redacted %v, recorded %v",
				c.key != nil, c.reveal, res.Chain.Pseudonymous, res.Redacted, detail)
		}
	}
}
