package c2pa

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// Reading a manifest back, and deciding whether to believe it.
//
// Four things have to hold, and each one is a way a manifest can be a lie:
//
//  1. The claim signature verifies against the key. Otherwise nothing else in
//     the manifest is evidence of anything.
//  2. Each assertion's bytes hash to what the claim says. Otherwise an
//     assertion was swapped for another under the same label.
//  3. The data hash matches the file. Otherwise the manifest describes
//     different pixels.
//  4. The excluded range is exactly where the manifest sits. Otherwise the
//     hash was computed over less than the file, and a manifest can be moved
//     onto content it never described.
//
// The fourth is the one that is easy to leave out, because a manifest without
// it still validates -- and validates against anything.

// Statement is what a verified manifest says.
type Statement struct {
	Title             string
	Format            string
	DigitalSourceType string
	SoftwareAgent     string
	Author            string
	Model             string
	Instruction       string
	When              string

	// DerivedFrom is the hash of the asset this one was made from, when the
	// manifest carries an ingredient. A caller holding the original can check
	// it; a caller who is not can at least say what this claims to be a copy
	// of.
	DerivedFrom []byte
	ParentTitle string
}

// GeneratedByModel reports whether the file was made or altered by a trained
// model, which is what the Article 50 marking obligation attaches to.
func (s Statement) GeneratedByModel() bool {
	switch s.DigitalSourceType {
	case "trainedAlgorithmicMedia", "compositeWithTrainedAlgorithmicMedia":
		return true
	}
	return false
}

// Verify reads the manifest out of a file and checks it against the file.
func Verify(file []byte, key ed25519.PublicKey) (Statement, error) {
	raw, where, err := extract(file)
	if err != nil {
		return Statement{}, err
	}

	boxes, err := parseBoxes(raw, 0)
	if err != nil {
		return Statement{}, fmt.Errorf("the manifest does not parse: %w", err)
	}
	store, err := manifestStore(boxes)
	if err != nil {
		return Statement{}, err
	}
	manifest, ok := store.find(uuidManifest)
	if !ok {
		return Statement{}, fmt.Errorf("the store holds no manifest")
	}

	claimBox, ok := manifest.find(uuidClaim)
	if !ok {
		return Statement{}, fmt.Errorf("the manifest holds no claim")
	}
	sigBox, ok := manifest.find(uuidSignature)
	if !ok {
		return Statement{}, fmt.Errorf("the manifest holds no claim signature")
	}
	assertions, ok := manifest.find(uuidAssertionStore)
	if !ok {
		return Statement{}, fmt.Errorf("the manifest holds no assertions")
	}

	claimBytes, err := claimBox.content()
	if err != nil {
		return Statement{}, err
	}
	sigBytes, err := sigBox.content()
	if err != nil {
		return Statement{}, err
	}

	// (1) The signature, first. Everything below reads values out of the
	// claim, and reading them before knowing they were signed would mean
	// acting on an attacker's numbers.
	signedClaim, err := Verify1(sigBytes, key)
	if err != nil {
		return Statement{}, err
	}
	if !bytes.Equal(signedClaim, claimBytes) {
		return Statement{}, fmt.Errorf(
			"the signature covers a different claim than the one in the " +
				"manifest, so the signed claim is not the one that would be read")
	}

	claim, err := decodeMap(claimBytes)
	if err != nil {
		return Statement{}, fmt.Errorf("the claim does not parse: %w", err)
	}

	// (2) Each assertion the claim lists, by the hash of its own bytes.
	byLabel, err := assertionBytes(assertions)
	if err != nil {
		return Statement{}, err
	}
	listed, err := checkAssertions(claim, byLabel)
	if err != nil {
		return Statement{}, err
	}

	// (3) and (4): the hard binding, and where it excludes.
	if err := checkBinding(file, byLabel[labelHash], where); err != nil {
		return Statement{}, err
	}

	return statementFrom(claim, byLabel[labelActions],
		byLabel[labelIngredient], listed)
}

// manifestStore picks the store out of the boxes at the top of the manifest.
//
// This program puts its padding inside the store, so it writes exactly one box
// here. A padding box beside the store is still tolerated, because another
// writer may reserve space that way and it carries nothing. Anything else is
// refused rather than skipped: a box a reader ignores is a place to put
// something no verifier ever looked at.
func manifestStore(boxes []parsed) (parsed, error) {
	var found parsed
	seen := false
	for _, b := range boxes {
		switch {
		case b.uuid == uuidManifestStore:
			if seen {
				return parsed{}, fmt.Errorf(
					"there are two manifest stores, so which one describes " +
						"this file depends on which is read first")
			}
			found, seen = b, true
		case b.kind == paddingKind:
			// Reserved space. Its contents are inside the excluded range.
		default:
			return parsed{}, fmt.Errorf(
				"there is a %q box beside the manifest, which this program "+
					"does not read and will not ignore", b.kind)
		}
	}
	if !seen {
		return parsed{}, fmt.Errorf("this is not a C2PA manifest store")
	}
	return found, nil
}

// where the manifest sits in the file: the range that must be excluded.
type placement struct {
	start  int
	length int
}

// extract finds the manifest store and where it sits, for whichever container
// this is.
func extract(file []byte) ([]byte, placement, error) {
	switch {
	case bytes.HasPrefix(file, pngMagic):
		return extractPNG(file)
	case bytes.HasPrefix(file, []byte{0xff, 0xd8}):
		return extractJPEG(file)
	}
	return nil, placement{}, fmt.Errorf("this is not a PNG or a JPEG")
}

func extractPNG(file []byte) ([]byte, placement, error) {
	at := len(pngMagic)
	for at+12 <= len(file) {
		length := int(binary.BigEndian.Uint32(file[at : at+4]))
		kind := string(file[at+4 : at+8])
		next := at + 12 + length
		if next <= at || next > len(file) {
			return nil, placement{}, fmt.Errorf(
				"a PNG chunk at byte %d claims %d bytes", at, length)
		}
		if kind == pngChunk {
			data := file[at+8 : at+8+length]
			// The CRC, because a chunk that fails it is a chunk a PNG reader
			// would reject, and a manifest only a lenient reader can see is
			// not a manifest the file carries.
			crc := binary.BigEndian.Uint32(file[at+8+length : next])
			if got := chunkCRC(data); got != crc {
				return nil, placement{}, fmt.Errorf(
					"the manifest chunk's CRC is %08x and it claims %08x",
					got, crc)
			}
			return data, placement{start: at, length: next - at}, nil
		}
		at = next
	}
	return nil, placement{}, fmt.Errorf("this PNG carries no manifest")
}

func extractJPEG(file []byte) ([]byte, placement, error) {
	at := 2
	for at+4 <= len(file) {
		if file[at] != 0xff {
			return nil, placement{}, fmt.Errorf("byte %d is not a marker", at)
		}
		marker := file[at+1]
		if marker < 0xe0 || marker > 0xef {
			break
		}
		length := int(binary.BigEndian.Uint16(file[at+2 : at+4]))
		next := at + 2 + length
		if length < 2 || next > len(file) {
			return nil, placement{}, fmt.Errorf(
				"a JPEG segment at byte %d claims %d bytes", at, length)
		}
		if marker == jpegAPP11 {
			payload := file[at+4 : next]
			if len(payload) < 8 {
				return nil, placement{}, fmt.Errorf(
					"an APP11 segment is too short to hold a JUMBF header")
			}
			if binary.BigEndian.Uint16(payload[:2]) != jpegCI {
				return nil, placement{}, fmt.Errorf(
					"this APP11 segment is not JUMBF")
			}
			return payload[8:], placement{start: at, length: next - at}, nil
		}
		at = next
	}
	return nil, placement{}, fmt.Errorf("this JPEG carries no manifest")
}

// chunkCRC is the PNG chunk checksum: CRC-32/IEEE over the type and the data,
// the type included because that is what the format specifies.
func chunkCRC(data []byte) uint32 {
	c := crc32.NewIEEE()
	c.Write([]byte(pngChunk))
	c.Write(data)
	return c.Sum32()
}

// checkBinding is (3) and (4): the file hashes to what the claim says, over
// exactly the bytes the manifest does not occupy.
func checkBinding(file, assertion []byte, where placement) error {
	if assertion == nil {
		return fmt.Errorf("the manifest carries no c2pa.hash.data assertion, " +
			"so it says nothing about this file's bytes and would validate " +
			"against any file at all")
	}
	m, err := decodeMap(assertion)
	if err != nil {
		return fmt.Errorf("the data hash assertion does not parse: %w", err)
	}
	if alg, _ := m["alg"].(Text); alg != "sha256" {
		return fmt.Errorf("the data hash uses %q, and this checks sha256", alg)
	}
	want, ok := m["hash"].(Bytes)
	if !ok {
		return fmt.Errorf("the data hash assertion holds no hash")
	}

	ranges, ok := m["exclusions"].(Array)
	if !ok {
		return fmt.Errorf("the data hash assertion lists no exclusions, and a " +
			"file containing its own manifest cannot hash to a value computed " +
			"over all of it")
	}

	// (4) The range has to be exactly the manifest. Not a superset: a claim
	// excluding more than it occupies is a claim over fewer bytes than the
	// file has, and those bytes can then be anything.
	if len(ranges) != 1 {
		return fmt.Errorf("the manifest claims %d excluded ranges; it occupies "+
			"one, and any other range is bytes hidden from the hash",
			len(ranges))
	}
	r, ok := ranges[0].(Map)
	if !ok {
		return fmt.Errorf("an exclusion is not a map")
	}
	start, sok := r["start"].(Uint)
	length, lok := r["length"].(Uint)
	if !sok || !lok {
		return fmt.Errorf("an exclusion has no start and length")
	}
	if int(start) != where.start || int(length) != where.length {
		return fmt.Errorf(
			"the manifest excludes bytes %d-%d and sits at %d-%d. A manifest "+
				"whose exclusion does not match where it is has a hash over "+
				"the wrong bytes, and can be moved onto content it never "+
				"described",
			start, int(start)+int(length),
			where.start, where.start+where.length)
	}

	got, err := hashExcluding(file, []exclusion{
		{start: where.start, length: where.length},
	})
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf(
			"this file hashes to %s and the manifest claims %s, so the "+
				"manifest describes different content",
			shortDigest(got), shortDigest(want))
	}
	return nil
}

// assertionBytes collects each assertion's own encoded bytes by label. The
// bytes, not the parsed value: the claim commits to a hash of these, and
// re-encoding a parsed value would compare against something else.
func assertionBytes(store parsed) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, child := range store.children {
		if child.kind != "jumb" {
			continue
		}
		body, err := child.content()
		if err != nil {
			return nil, err
		}
		if _, seen := out[child.label]; seen {
			return nil, fmt.Errorf(
				"two assertions are labelled %q, so which one the claim "+
					"commits to depends on which is read first", child.label)
		}
		out[child.label] = body
	}
	return out, nil
}

// checkAssertions is (2): every assertion the claim lists is present and
// hashes to what the claim recorded. Returns the labels checked.
func checkAssertions(claim Map, byLabel map[string][]byte) ([]string, error) {
	listed, ok := claim["assertions"].(Array)
	if !ok || len(listed) == 0 {
		return nil, fmt.Errorf("the claim lists no assertions")
	}
	var labels []string
	for _, entry := range listed {
		ref, rok := entry.(Map)
		if !rok {
			return nil, fmt.Errorf("an assertion reference is not a map")
		}
		url, uok := ref["url"].(Text)
		want, wok := ref["hash"].(Bytes)
		if !uok || !wok {
			return nil, fmt.Errorf("an assertion reference has no url and hash")
		}
		label := labelFromURI(string(url))
		body, present := byLabel[label]
		if !present {
			return nil, fmt.Errorf(
				"the claim commits to an assertion at %q and the store does "+
					"not hold it", url)
		}
		sum := sha256.Sum256(body)
		if !bytes.Equal(sum[:], want) {
			return nil, fmt.Errorf(
				"the assertion %q does not hash to what the claim signed, so "+
					"it was changed after signing", label)
		}
		labels = append(labels, label)
	}
	return labels, nil
}

// labelFromURI takes the label off a self#jumbf= reference.
func labelFromURI(uri string) string {
	if i := bytes.LastIndexByte([]byte(uri), '/'); i >= 0 {
		return uri[i+1:]
	}
	return uri
}

// statementFrom reads the human-facing values out of a claim that has already
// been verified.
func statementFrom(claim Map, actions, ingredient []byte,
	listed []string) (Statement, error) {
	s := Statement{}
	if v, ok := claim["title"].(Text); ok {
		s.Title = string(v)
	}
	if v, ok := claim["format"].(Text); ok {
		s.Format = string(v)
	}
	if v, ok := claim["claim_generator"].(Text); ok {
		s.SoftwareAgent = string(v)
	}
	if actions == nil {
		return s, nil
	}
	m, err := decodeMap(actions)
	if err != nil {
		return s, fmt.Errorf("the actions assertion does not parse: %w", err)
	}
	list, ok := m["actions"].(Array)
	if !ok || len(list) == 0 {
		return s, fmt.Errorf("the actions assertion lists no actions")
	}
	first, ok := list[0].(Map)
	if !ok {
		return s, fmt.Errorf("an action is not a map")
	}
	if v, ok := first["when"].(Text); ok {
		s.When = string(v)
	}
	if v, ok := first["digitalSourceType"].(Text); ok {
		s.DigitalSourceType = termOf(string(v))
	}
	if a, ok := first["author"].(Map); ok {
		if n, ok := a["name"].(Text); ok {
			s.Author = string(n)
		}
	}
	if p, ok := first["parameters"].(Map); ok {
		if v, ok := p["com.quilzo.model"].(Text); ok {
			s.Model = string(v)
		}
		if v, ok := p["com.quilzo.instruction"].(Text); ok {
			s.Instruction = string(v)
		}
	}

	// The ingredient, if this file says it was made from another. Read after
	// the assertion hashes were checked, so what it names was signed.
	if ingredient != nil {
		m, ierr := decodeMap(ingredient)
		if ierr != nil {
			return s, fmt.Errorf("the ingredient assertion does not parse: %w",
				ierr)
		}
		if alg, ok := m["alg"].(Text); ok && alg != "sha256" {
			return s, fmt.Errorf(
				"the ingredient names algorithm %q and this checks sha256", alg)
		}
		if h, ok := m["hash"].(Bytes); ok {
			s.DerivedFrom = append([]byte(nil), h...)
		}
		if v, ok := m["dc:title"].(Text); ok {
			s.ParentTitle = string(v)
		}
	}
	return s, nil
}

// termOf takes the bare term off an IPTC vocabulary URI, so a caller compares
// against the same strings internal/provenance stores.
func termOf(uri string) string {
	if i := bytes.LastIndexByte([]byte(uri), '/'); i >= 0 {
		return uri[i+1:]
	}
	return uri
}

func decodeMap(b []byte) (Map, error) {
	v, err := Decode(b)
	if err != nil {
		return nil, err
	}
	m, ok := v.(Map)
	if !ok {
		return nil, fmt.Errorf("this structure is not a map")
	}
	return m, nil
}
