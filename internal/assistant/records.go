// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assistant

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Records a chatbot may answer from: the site's structured data (products,
// events, opening times, a menu), chosen by collection, published records
// only.
//
// A record is one passage: what it is called, then each field as "name:
// value". Fields whose names say they are about a person (an email
// address, a telephone number, an address, a password or a token) are left
// out whatever the collection is, since a chatbot is something anybody
// asks, and the rest are cut short. A record has no page of its own to
// cite, so its citation names it and links nowhere.

// RecordText is one record as a chatbot reads it.
type RecordText struct {
	ID     string
	Fields map[string]any
}

// Bounds on what records give a chatbot.
const (
	MaxRecordsPerCollection = 1000
	MaxRecordText           = 1500
	MaxCollections          = 10
)

var (
	reCollection = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	rePersonal   = regexp.MustCompile(`(?i)(e-?mail|phone|mobile|tel$|address|postcode|zip|password|passcode|secret|token|birth|dob|ssn|national|passport|iban|account|card)`)
	titleFields  = []string{"title", "name", "label", "heading"}
)

// ChunkRecords is a collection's records as passages.
func ChunkRecords(collection string, records []RecordText) []Passage {
	if len(records) > MaxRecordsPerCollection {
		records = records[:MaxRecordsPerCollection]
	}
	out := make([]Passage, 0, len(records))
	for _, r := range records {
		title := ""
		for _, k := range titleFields {
			if v, ok := r.Fields[k].(string); ok && strings.TrimSpace(v) != "" {
				title = oneLine(v)
				break
			}
		}
		keys := make([]string, 0, len(r.Fields))
		for k := range r.Fields {
			if !rePersonal.MatchString(k) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			v := fieldText(r.Fields[k])
			if v == "" {
				continue
			}
			fmt.Fprintf(&b, "%s: %s\n", strings.ReplaceAll(k, "_", " "), v)
			if b.Len() > MaxRecordText {
				break
			}
		}
		text := strings.TrimSpace(b.String())
		if len(text) > MaxRecordText {
			text = strings.ToValidUTF8(text[:MaxRecordText], "")
		}
		if text == "" {
			continue
		}
		if title == "" {
			title = collection + " " + r.ID
		}
		out = append(out, Passage{ID: "rec:" + collection + "/" + r.ID, Title: title,
			Heading: strings.ReplaceAll(collection, "_", " "), Text: text, Record: collection + "/" + r.ID})
	}
	return out
}

// fieldText is a field's value in words, or nothing for what is not a
// plain value. A file in the media library is not words: a product's
// picture was a passage line of 64 hexadecimal characters.
func fieldText(v any) string {
	switch t := v.(type) {
	case string:
		if storedFile(t) {
			return ""
		}
		return oneLine(t)
	case float64:
		return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.4f", t), "0"), ".")
	case bool:
		if t {
			return "yes"
		}
		return "no"
	case []any:
		var parts []string
		for _, x := range t {
			if s := fieldText(x); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	}
	return ""
}
