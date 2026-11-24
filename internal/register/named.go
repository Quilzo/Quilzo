// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"encoding/json"
	"strings"

	"github.com/quilzo/quilzo/internal/register/side"
)

// What a record names beside it, as every screen of a record says it.
//
// A record holds a person as a pseudonym and words or a file as a digest.
// Shown alone, a pseudonym of somebody erased looks like a pseudonym of
// somebody nobody has asked about, and a digest of words that went at the
// end of their retention looks like one of words that are there. Every
// surface that shows a record shows this beside it, so "subject erased" and
// "text erased" are said where the erasure is, and the record itself is
// unchanged and still checks.

// Named is one person, piece of text or file a record names.
type Named struct {
	// Field is where it is in the record, as a dotted path.
	Field string `json:"field"`
	// What is "subject", "text" or "file".
	What string `json:"what"`
	// Value is the pseudonym or the digest, as the record holds it.
	Value string `json:"value"`
	// State is what the side store holds of it (SubjectState, TextOf),
	// and Said the same as a screen says it: "subject erased", "text held".
	State string `json:"state"`
	Said  string `json:"said"`
	// Words is the text, when it is held; never a person's name.
	Words string `json:"words,omitempty"`
	// Erased says when and on what basis, when it was erased.
	Erased *side.Erased `json:"erased,omitempty"`
}

// Named is every person, piece of text and file a record names, in the
// order of its schema, each with what the side store holds of it.
func (r *Register) Named(rec Record) []Named {
	spec, ok := kinds[rec.Kind()]
	if !ok {
		return nil
	}
	raw, _ := json.Marshal(rec)
	var out []Named
	r.named(spec.Fields, json.RawMessage(raw), "", spec.Kind == KindSubject, &out)
	return out
}

func (r *Register) named(fields []Field, v json.RawMessage, prefix string, subjectKind bool, out *[]Named) {
	var values map[string]json.RawMessage
	if json.Unmarshal(v, &values) != nil {
		return
	}
	for _, f := range fields {
		path := prefix + f.Name
		val, set := values[f.Name]
		if !set || string(val) == "null" {
			continue
		}
		if len(f.Fields) > 0 {
			var list []json.RawMessage
			if strings.HasPrefix(f.Type, "list of ") && json.Unmarshal(val, &list) == nil {
				for _, item := range list {
					r.named(f.Fields, item, path+".", false, out)
				}
				continue
			}
			r.named(f.Fields, val, path+".", false, out)
			continue
		}
		base := strings.TrimPrefix(f.Type, "list of ")
		what := ""
		switch {
		case base == "id" && (f.Ref == KindSubject || (subjectKind && path == "pseudonym")):
			what = "subject"
		case base == "text":
			what = "text"
		case base == "digest" && f.Name == rawField:
			what = "file"
		default:
			continue
		}
		var each []string
		if strings.HasPrefix(f.Type, "list of ") {
			_ = json.Unmarshal(val, &each)
		} else {
			var one string
			if json.Unmarshal(val, &one) == nil && one != "" {
				each = []string{one}
			}
		}
		for _, value := range each {
			*out = append(*out, r.nameOf(path, what, value))
		}
	}
}

// nameOf is what the side store holds of one value, and how it is said.
func (r *Register) nameOf(field, what, value string) Named {
	var h Held
	switch what {
	case "subject":
		h = r.SubjectState(ID(value))
	case "text":
		h = r.TextOf(Text(value))
	default:
		h = r.RawOf(Digest(value))
	}
	n := Named{Field: field, What: what, Value: value, State: h.State, Erased: h.Erased, Words: h.Words}
	switch {
	case what == "subject" && h.State == SubjectHeld:
		n.Said = "subject in the map"
	case what == "subject" && h.State == SubjectUnmapped:
		n.Said = "subject not in the map"
	default:
		n.Said = what + " " + h.State
	}
	return n
}
