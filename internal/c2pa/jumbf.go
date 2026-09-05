package c2pa

import (
	"encoding/binary"
	"fmt"
)

// JUMBF boxes, which is how a C2PA manifest is shaped.
//
// JPEG Universal Metadata Box Format: a box is a four-byte big-endian length
// including the header, a four-character type, and a payload. A superbox is a
// box whose payload is more boxes, the first of which describes it.
//
// A manifest store is therefore a tree:
//
//	jumb (c2pa)              the manifest store
//	  jumd                   description: UUID + label "c2pa"
//	  jumb (c2ma)            one manifest
//	    jumd                 description: UUID + the manifest's label
//	    jumb (c2as)          the assertion store
//	      jumd
//	      jumb (cbor)        one assertion, labelled c2pa.hash.data
//	        jumd
//	        cbor             the assertion's own bytes
//	    jumb (c2cl)          the claim
//	      jumd
//	      cbor
//	    jumb (c2cs)          the claim signature
//	      jumd
//	      cbor               a COSE_Sign1 structure
//
// The labels matter: a claim refers to an assertion by a URI built from the
// labels of the boxes above it, and the hash in that URI is over the assertion
// box's own payload. Getting a label wrong produces a manifest that parses and
// does not validate, which is worse than one that does not parse.

// The content-type UUIDs C2PA defines. Every one shares the JUMBF suffix
// 0011-0010-8000-00AA00389B71; the first four bytes are the type's own name in
// ASCII — 63 32 70 61 is "c2pa" — which is a nice property of the registry and
// not something to rely on.
var (
	uuidManifestStore  = uuidOf(0x63, 0x32, 0x70, 0x61) // c2pa
	uuidManifest       = uuidOf(0x63, 0x32, 0x6d, 0x61) // c2ma
	uuidAssertionStore = uuidOf(0x63, 0x32, 0x61, 0x73) // c2as
	uuidClaim          = uuidOf(0x63, 0x32, 0x63, 0x6c) // c2cl
	uuidSignature      = uuidOf(0x63, 0x32, 0x63, 0x73) // c2cs
	uuidCBOR           = uuidOf(0x63, 0x62, 0x6f, 0x72) // cbor
)

func uuidOf(a, b, c, d byte) [16]byte {
	return [16]byte{a, b, c, d,
		0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71}
}

// box is one JUMBF box.
type box struct {
	kind    string // the four-character TBox
	payload []byte
}

// bytes writes the box: length, type, payload.
func (b box) bytes() ([]byte, error) {
	if len(b.kind) != 4 {
		return nil, fmt.Errorf("%q is not a four-character box type", b.kind)
	}
	total := 8 + len(b.payload)
	if total > 0xffffffff {
		return nil, fmt.Errorf("a box of %d bytes does not fit its length field",
			total)
	}
	out := make([]byte, 0, total)
	out = binary.BigEndian.AppendUint32(out, uint32(total))
	out = append(out, b.kind...)
	out = append(out, b.payload...)
	return out, nil
}

// description builds the jumd box every superbox opens with.
//
// The toggles byte says what the description carries. Bit 1 (value 2) means a
// label is present and NUL-terminated, which is the only form C2PA uses: the
// alternatives are an ID or a signature over the box, and nothing in this
// manifest needs either.
func description(kind [16]byte, label string) (box, error) {
	if label == "" {
		return box{}, fmt.Errorf("a described box needs a label, because a " +
			"claim refers to its assertions by one")
	}
	payload := make([]byte, 0, 16+1+len(label)+1)
	payload = append(payload, kind[:]...)
	payload = append(payload, 0x03) // requestable, label present
	payload = append(payload, label...)
	payload = append(payload, 0x00)
	return box{kind: "jumd", payload: payload}, nil
}

// superbox builds a jumb box: a description followed by contents.
func superbox(kind [16]byte, label string, contents ...[]byte) ([]byte, error) {
	desc, err := description(kind, label)
	if err != nil {
		return nil, err
	}
	head, err := desc.bytes()
	if err != nil {
		return nil, err
	}
	payload := head
	for _, c := range contents {
		payload = append(payload, c...)
	}
	return box{kind: "jumb", payload: payload}.bytes()
}

// cborBox wraps CBOR bytes as a described content box.
func cborBox(label string, body []byte) ([]byte, error) {
	return superbox(uuidCBOR, label, box{kind: "cbor", payload: body}.payload8())
}

// payload8 renders a content box with its own header, for nesting inside a
// superbox. Named for what it is doing rather than what it returns, because a
// bare payload and a framed box are easy to mix up and the result is a manifest
// that parses to the wrong shape.
func (b box) payload8() []byte {
	out, err := b.bytes()
	if err != nil {
		return nil
	}
	return out
}

// -- reading ------------------------------------------------------------------

// parsed is a box read back out of a file.
type parsed struct {
	kind string
	// uuid and label are set for a superbox, from its description.
	uuid  [16]byte
	label string
	// body is the payload of a content box.
	body []byte
	// children are the boxes inside a superbox, after the description.
	children []parsed
}

// parseBoxes reads a sequence of boxes.
func parseBoxes(in []byte, depth int) ([]parsed, error) {
	if depth > 16 {
		return nil, fmt.Errorf("boxes nest deeper than 16, which is not a manifest")
	}
	var out []parsed
	for len(in) > 0 {
		if len(in) < 8 {
			return nil, fmt.Errorf("%d bytes left, which is less than a box header",
				len(in))
		}
		length := binary.BigEndian.Uint32(in[:4])
		if length < 8 || int(length) > len(in) {
			return nil, fmt.Errorf("a box claims %d bytes and %d remain",
				length, len(in))
		}
		p := parsed{kind: string(in[4:8])}
		payload := in[8:length]

		if p.kind == "jumb" {
			kids, err := parseBoxes(payload, depth+1)
			if err != nil {
				return nil, err
			}
			if len(kids) == 0 || kids[0].kind != "jumd" {
				return nil, fmt.Errorf("a superbox does not open with a description")
			}
			d := kids[0].body
			if len(d) < 17 {
				return nil, fmt.Errorf("a description box is too short to hold a UUID")
			}
			copy(p.uuid[:], d[:16])
			if d[16]&0x02 != 0 {
				label := d[17:]
				for i, c := range label {
					if c == 0 {
						label = label[:i]
						break
					}
				}
				p.label = string(label)
			}
			p.children = kids[1:]
		} else {
			p.body = payload
		}
		out = append(out, p)
		in = in[length:]
	}
	return out, nil
}

// find returns the first child superbox with this UUID.
func (p parsed) find(kind [16]byte) (parsed, bool) {
	for _, c := range p.children {
		if c.uuid == kind {
			return c, true
		}
	}
	return parsed{}, false
}

// content returns the payload of a superbox's single content box.
func (p parsed) content() ([]byte, error) {
	for _, c := range p.children {
		if c.kind == "cbor" || c.kind == "json" {
			return c.body, nil
		}
	}
	return nil, fmt.Errorf("the box labelled %q carries no content", p.label)
}
