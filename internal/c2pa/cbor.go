package c2pa

import (
	"fmt"
	"math"
	"sort"
)

// Just enough CBOR to write a claim and a signature, and read one back.
//
// # Why this is here rather than a dependency
//
// C2PA is CBOR all the way down: the claim, the assertions, the COSE signature
// envelope. Every Go implementation of it pulls in a CBOR library, and this
// project's whole argument is that it has no require block. So the subset that
// C2PA actually uses is written out — integers, byte strings, text strings,
// arrays, maps — which is a few hundred lines and no supply chain.
//
// # Deterministic, because the bytes are signed
//
// A claim is hashed and signed, and an assertion is referenced by the hash of
// its bytes. Two encodings of the same structure would produce two hashes, and
// a verifier rebuilding the structure would compute the wrong one. So map keys
// are sorted by their encoded form — the canonical rule from RFC 8949 §4.2 —
// and every integer takes the shortest form that holds it. There is no float
// encoding at all: nothing in a C2PA claim is a float, and a float that arrived
// by accident would be a value whose bytes depend on how it was rounded.

// Value is anything this encoder writes.
//
// A closed set on purpose. `any` with a type switch would accept an int8 or a
// json.Number and encode it in whatever way seemed reasonable at the time, and
// the bytes are signed.
type Value interface{ encode(*encoder) error }

type (
	// Uint is a non-negative integer, major type 0.
	Uint uint64
	// Int is a negative integer, major type 1. Positive values are Uint.
	Int int64
	// Bytes is a byte string, major type 2.
	Bytes []byte
	// Text is a UTF-8 string, major type 3.
	Text string
	// Array is an ordered list, major type 4.
	Array []Value
	// Map is a map with text keys, major type 5, written in canonical order.
	Map map[string]Value
	// Bool is a simple value, major type 7.
	Bool bool
	// Null is the absent value, major type 7 value 22.
	Null struct{}
	// Tagged wraps a value in a semantic tag, major type 6.
	Tagged struct {
		Tag   uint64
		Value Value
	}
)

// Encode writes a value as deterministic CBOR.
func Encode(v Value) ([]byte, error) {
	e := &encoder{}
	if err := v.encode(e); err != nil {
		return nil, err
	}
	return e.out, nil
}

type encoder struct{ out []byte }

// head writes a major type and an argument in the shortest form that holds it.
func (e *encoder) head(major byte, arg uint64) {
	m := major << 5
	switch {
	case arg < 24:
		e.out = append(e.out, m|byte(arg))
	case arg <= math.MaxUint8:
		e.out = append(e.out, m|24, byte(arg))
	case arg <= math.MaxUint16:
		e.out = append(e.out, m|25, byte(arg>>8), byte(arg))
	case arg <= math.MaxUint32:
		e.out = append(e.out, m|26,
			byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	default:
		e.out = append(e.out, m|27,
			byte(arg>>56), byte(arg>>48), byte(arg>>40), byte(arg>>32),
			byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	}
}

func (v Uint) encode(e *encoder) error { e.head(0, uint64(v)); return nil }

func (v Int) encode(e *encoder) error {
	if v >= 0 {
		e.head(0, uint64(v))
		return nil
	}
	// Major type 1 encodes -1-n, so -1 is argument 0.
	e.head(1, uint64(-1-int64(v)))
	return nil
}

func (v Bytes) encode(e *encoder) error {
	e.head(2, uint64(len(v)))
	e.out = append(e.out, v...)
	return nil
}

func (v Text) encode(e *encoder) error {
	e.head(3, uint64(len(v)))
	e.out = append(e.out, v...)
	return nil
}

func (v Array) encode(e *encoder) error {
	e.head(4, uint64(len(v)))
	for _, item := range v {
		if item == nil {
			return fmt.Errorf("an array holds a nil value, which has no encoding")
		}
		if err := item.encode(e); err != nil {
			return err
		}
	}
	return nil
}

func (v Map) encode(e *encoder) error {
	// Canonical order: keys sorted by their encoded bytes, which for text keys
	// of the same length is lexicographic and otherwise shortest first. The
	// claim is signed, so two encoders have to agree byte for byte.
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) < len(keys[j])
		}
		return keys[i] < keys[j]
	})

	e.head(5, uint64(len(v)))
	for _, k := range keys {
		if err := Text(k).encode(e); err != nil {
			return err
		}
		if v[k] == nil {
			return fmt.Errorf("the key %q holds a nil value", k)
		}
		if err := v[k].encode(e); err != nil {
			return err
		}
	}
	return nil
}

func (v Bool) encode(e *encoder) error {
	if v {
		e.out = append(e.out, 0xf5)
	} else {
		e.out = append(e.out, 0xf4)
	}
	return nil
}

func (Null) encode(e *encoder) error { e.out = append(e.out, 0xf6); return nil }

func (v Tagged) encode(e *encoder) error {
	e.head(6, v.Tag)
	if v.Value == nil {
		return fmt.Errorf("a tag wraps nothing")
	}
	return v.Value.encode(e)
}

// -- reading ------------------------------------------------------------------

// Decode reads one value. Trailing bytes are an error: a claim is exactly one
// structure, and something after it is a message this program did not
// understand rather than one it should ignore.
func Decode(b []byte) (Value, error) {
	d := &decoder{in: b}
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	if d.at != len(b) {
		return nil, fmt.Errorf("%d bytes left after the value", len(b)-d.at)
	}
	return v, nil
}

type decoder struct {
	in []byte
	at int
}

// maxNesting bounds recursion. Content arrives from other people's software,
// and a deeply nested value is a stack this program agreed to spend.
const maxNesting = 24

func (d *decoder) value(depth int) (Value, error) {
	if depth > maxNesting {
		return nil, fmt.Errorf("this value nests deeper than %d, which is not a "+
			"claim but a way to spend a stack", maxNesting)
	}
	if d.at >= len(d.in) {
		return nil, fmt.Errorf("the value ends before it is complete")
	}
	b := d.in[d.at]
	major, minor := b>>5, b&0x1f
	d.at++

	if major == 7 {
		switch minor {
		case 20:
			return Bool(false), nil
		case 21:
			return Bool(true), nil
		case 22, 23:
			return Null{}, nil
		}
		return nil, fmt.Errorf("simple value %d is not one this reads", minor)
	}

	arg, err := d.argument(minor)
	if err != nil {
		return nil, err
	}

	switch major {
	case 0:
		return Uint(arg), nil
	case 1:
		return Int(-1 - int64(arg)), nil
	case 2, 3:
		if arg > uint64(len(d.in)-d.at) {
			return nil, fmt.Errorf("a string claims %d bytes and %d remain",
				arg, len(d.in)-d.at)
		}
		raw := d.in[d.at : d.at+int(arg)]
		d.at += int(arg)
		if major == 2 {
			return Bytes(append([]byte(nil), raw...)), nil
		}
		return Text(raw), nil
	case 4:
		out := make(Array, 0, min(int(arg), 1024))
		for i := uint64(0); i < arg; i++ {
			item, ierr := d.value(depth + 1)
			if ierr != nil {
				return nil, ierr
			}
			out = append(out, item)
		}
		return out, nil
	case 5:
		out := make(Map, min(int(arg), 1024))
		for i := uint64(0); i < arg; i++ {
			k, kerr := d.value(depth + 1)
			if kerr != nil {
				return nil, kerr
			}
			key, ok := k.(Text)
			if !ok {
				return nil, fmt.Errorf("a map key is not text, which no C2PA " +
					"structure uses")
			}
			v, verr := d.value(depth + 1)
			if verr != nil {
				return nil, verr
			}
			out[string(key)] = v
		}
		return out, nil
	case 6:
		inner, ierr := d.value(depth + 1)
		if ierr != nil {
			return nil, ierr
		}
		return Tagged{Tag: arg, Value: inner}, nil
	}
	return nil, fmt.Errorf("major type %d is not one this reads", major)
}

func (d *decoder) argument(minor byte) (uint64, error) {
	switch {
	case minor < 24:
		return uint64(minor), nil
	case minor == 24:
		return d.take(1)
	case minor == 25:
		return d.take(2)
	case minor == 26:
		return d.take(4)
	case minor == 27:
		return d.take(8)
	}
	return 0, fmt.Errorf("argument form %d is not one this reads: indefinite "+
		"lengths are refused because a signed structure has a length", minor)
}

func (d *decoder) take(n int) (uint64, error) {
	if d.at+n > len(d.in) {
		return 0, fmt.Errorf("a length field runs past the end")
	}
	var out uint64
	for i := 0; i < n; i++ {
		out = out<<8 | uint64(d.in[d.at+i])
	}
	d.at += n
	return out, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
