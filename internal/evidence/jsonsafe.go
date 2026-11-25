// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
)

// JSON from a file, read as hostile.
//
// encoding/json reads a document nested ten thousand deep, and takes the
// last of two values given under one key. The first is a way to spend a
// reader's stack and time; the second is a way to show one value to the tool
// that checked a file and another to the one that reads it, which is how a
// signed document is made to say something its signer did not. So before a
// document is decoded it is walked once, token by token: it is refused if it
// nests deeper than MaxDepth, if any object gives a key twice, if it holds
// more than maxValues values, or if anything follows its end.
//
// Twice is as the decoder that reads the document sees it. Read as a
// generic value, its keys are exact, as every other reader's are. Decoded
// into a structure, encoding/json matches a key to a field whatever its
// case, and keeps the last: "Payload" after "payload" is the same field to
// it, while a reader that goes by the format's spelling reads the first.
// So a document decoded into a structure is refused for two keys that
// fold to one.

const maxValues = 4_000_000

// checkJSON walks one JSON document, or with lines set a document on each
// line, and refuses what a hostile file would use.
func checkJSON(b []byte, lines bool) error { return walkJSON(b, lines, false) }

// walkJSON is checkJSON, and with fold set it takes two keys that differ
// only in case for one, as decoding into a structure does.
func walkJSON(b []byte, lines, fold bool) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	type frame struct {
		object bool
		keys   map[string]bool
		key    bool // the next string is a key
	}
	var stack []frame
	values, docs := 0, 0
	for {
		tok, err := d.Token()
		if err == io.EOF {
			if len(stack) > 0 {
				return errors.New("it ends before its JSON document does")
			}
			break
		}
		if err != nil {
			return fmt.Errorf("it is not well-formed JSON: %v", err)
		}
		if len(stack) == 0 {
			if docs > 0 && !lines {
				return errors.New("something follows the end of the JSON document")
			}
			docs++
		}
		values++
		if values > maxValues {
			return fmt.Errorf("it holds more than %d values", maxValues)
		}
		top := len(stack) - 1
		if k, isKey := tok.(string); isKey && top >= 0 && stack[top].object && stack[top].key {
			name := k
			if fold {
				name = foldKey(k)
			}
			if stack[top].keys[name] {
				return fmt.Errorf("an object gives the key %q twice, and two readers would read different values", label(k))
			}
			stack[top].keys[name] = true
			stack[top].key = false
			continue
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if len(stack) >= MaxDepth {
					return fmt.Errorf("it nests deeper than %d, which no export does", MaxDepth)
				}
				stack = append(stack, frame{object: t == '{', keys: map[string]bool{}, key: t == '{'})
				continue
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
		}
		if top := len(stack) - 1; top >= 0 && stack[top].object {
			stack[top].key = true
		}
	}
	if docs == 0 {
		return errors.New("it holds no JSON")
	}
	return nil
}

// foldKey is a key as encoding/json matches it to a field: each letter
// folded to the least of the letters Unicode folds it with, so that
// "Payload", "PAYLOAD" and a "payload" spelled with any letter Unicode
// takes for one of its letters are one key.
func foldKey(k string) string {
	var b strings.Builder
	for _, r := range k {
		for {
			next := unicode.SimpleFold(r)
			if next <= r {
				r = next
				break
			}
			r = next
		}
		b.WriteRune(r)
	}
	return b.String()
}

// decodeJSON checks a document and decodes it into v: as a generic value
// when v is one, by exact keys, and into a structure by keys folded as the
// decoder folds them.
func decodeJSON(b []byte, v any) error {
	_, generic := v.(*any)
	if err := walkJSON(b, false, !generic); err != nil {
		return fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	return nil
}

// jsonDocs is a file that is one JSON document, or a document on each line
// (JSON Lines), each checked and decoded as a generic value. A file that is
// one array is its elements.
func jsonDocs(b []byte) ([]any, error) {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) > 0 && (trimmed[0] == '[' || checkJSON(trimmed, false) == nil) {
		var v any
		if err := decodeJSON(trimmed, &v); err != nil {
			return nil, err
		}
		if list, ok := v.([]any); ok {
			return list, nil
		}
		return []any{v}, nil
	}
	if err := checkJSON(trimmed, true); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
	}
	var out []any
	d := json.NewDecoder(bytes.NewReader(trimmed))
	d.UseNumber()
	for {
		var v any
		err := d.Decode(&v)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnreadable, err)
		}
		out = append(out, v)
	}
}

// pointer is the value an RFC 6901 JSON pointer names in a generic value,
// or false when there is none.
func pointer(v any, p string) (any, bool) {
	if p == "" {
		return v, true
	}
	if !strings.HasPrefix(p, "/") {
		return nil, false
	}
	for _, tok := range strings.Split(p[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch c := v.(type) {
		case map[string]any:
			var ok bool
			if v, ok = c[tok]; !ok {
				return nil, false
			}
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(c) || (len(tok) > 1 && tok[0] == '0') {
				return nil, false
			}
			v = c[i]
		default:
			return nil, false
		}
	}
	return v, true
}

// escapeToken is a key as one step of a JSON pointer.
func escapeToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// str is a generic value as text: a string as it is, a number as it was
// written, true or false, and nothing for anything else.
func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

// obj is a generic value as an object, or nil.
func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// arr is a generic value as a list, or nil.
func arr(v any) []any {
	a, _ := v.([]any)
	return a
}

// at is the value under a path of keys in nested objects.
func at(v any, keys ...string) any {
	for _, k := range keys {
		m := obj(v)
		if m == nil {
			return nil
		}
		v = m[k]
	}
	return v
}

// scalarJSON is a generic value as a fact's value: a string, a number or a
// yes or no, and false for anything else.
func scalarJSON(v any) (bool, string, any) {
	switch t := v.(type) {
	case string:
		return true, t, t
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return false, "", nil
		}
		return true, t.String(), f
	case bool:
		return true, strconv.FormatBool(t), t
	}
	return false, "", nil
}
