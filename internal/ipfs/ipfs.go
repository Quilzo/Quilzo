// Package ipfs computes IPFS content identifiers, without an IPFS library.
//
// # Why this exists at all
//
// Scrivet already stores every object under the SHA-256 of its own bytes, in
// nested trees, and publishes by moving a pointer at a root hash. IPFS names
// content by the SHA-256 of its own bytes, in nested DAG nodes, and addresses a
// site by its root. These are the same idea arriving from two directions, so
// publishing to IPFS is a serialisation format rather than a new architecture.
//
// # Why it computes the identifier rather than asking
//
// The obvious way to put a site on IPFS is to POST it to a pinning service and
// use whatever identifier comes back. That makes the service the authority on
// what your content is. It can return an identifier for something else — by
// bug, by compromise, or because it re-chunked the upload — and nothing in the
// pipeline would notice, because the only copy of the answer came from the
// party being checked.
//
// So the identifier is computed here, before anything is uploaded, and the
// service's answer is compared against it. A mismatch is a refusal. That is the
// same reasoning the rest of this program applies to the store: the name of a
// thing is a fact about its bytes, and anybody claiming otherwise is wrong in a
// way you can prove.
//
// # Why not the reference library
//
// This project has no third-party dependencies, and CI fails if one appears.
// The relevant part of go-ipfs is a protobuf runtime, a multiformats stack and
// a DAG builder; what is actually needed is about two hundred lines of encoding
// against a specification that has not changed in years. The trade is real and
// it is stated plainly: the cost is that a specification change is our problem,
// and the benefit is that a supply-chain compromise in the IPFS ecosystem is
// not.
//
// # The format, exactly
//
// A CIDv1 in text form is a multibase prefix and then four things:
//
//	'b'         base32, lowercase, unpadded
//	0x01        CID version 1
//	<codec>     0x55 raw, or 0x70 dag-pb
//	0x12 0x20   multihash: sha2-256, 32 bytes
//	<32 bytes>  the digest
//
// A file of at most one chunk is a raw block: the bytes themselves, under the
// raw codec. There is no wrapper, no metadata and nothing to disagree about.
//
// A larger file is a dag-pb node whose links are the raw chunks in order, whose
// UnixFS payload is Type=File with a filesize and one blocksize per link.
//
// A directory is a dag-pb node whose links are named, sorted by name as bytes,
// with a UnixFS payload of Type=Directory.
//
// Two details in that are easy to get wrong and are both load-bearing. DAG-PB
// requires the PBNode fields to be serialised in schema order — Links, then
// Data — which is *not* field-number order, and a decoder that accepts the
// natural order will still produce a different hash. And link names sort by
// byte value rather than by any locale-aware string comparison.
//
// The implementation is checked against published identifiers: the empty file,
// the empty directory, and a known small file. Those are the values every other
// implementation produces, so agreeing with them is the whole test.
package ipfs

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// ChunkSize is where a file stops being one block.
//
// 256 KiB, which is what every implementation has defaulted to for years.
// Changing it changes every identifier this produces, so it is a constant
// rather than an option: an identifier that depends on a setting is an
// identifier two people with the same file can disagree about.
const ChunkSize = 256 * 1024

// MaxLinks bounds the fan-out of a directory node.
//
// A real implementation shards a directory past this point into a HAMT, which
// is a different node type with a different identifier. Rather than produce
// something subtly wrong for a large directory, this refuses — a site with more
// than this many files in one directory is unusual, and being told so is better
// than getting an identifier nothing else agrees with.
const MaxLinks = 1024

// Codecs. The multicodec table is large; these are the two this needs.
const (
	codecRaw   = 0x55
	codecDagPB = 0x70
)

// Block is one addressable piece of content.
type Block struct {
	// CID is the text form, ready to use in a URL or an ENS record.
	CID string
	// Bytes are what must be uploaded for this CID to resolve.
	Bytes []byte
	// Size is the cumulative size of this block and everything under it,
	// which is what a parent link records as Tsize.
	Size uint64
}

// Node is a file or directory in a built DAG.
type Node struct {
	// Name is the entry name inside its parent. Empty at the root.
	Name string
	// Block is this node's own block.
	Block Block
	// Children are the blocks beneath it, in the order they must be uploaded.
	// A parent must not be pinned before its children exist, or a resolver
	// following it finds a hole.
	Children []Block
}

// File builds the DAG for one file's contents.
//
// Small files — which is nearly every page a CMS renders — become a single raw
// block, so the identifier is the hash of the bytes and nothing else. That is
// worth knowing when reasoning about what is stored: for a small file there is
// no metadata on IPFS at all, not even a name.
func File(body []byte) Node {
	if len(body) <= ChunkSize {
		b := rawBlock(body)
		return Node{Block: b}
	}

	var (
		links  []link
		chunks []Block
		total  uint64
	)
	for off := 0; off < len(body); off += ChunkSize {
		end := off + ChunkSize
		if end > len(body) {
			end = len(body)
		}
		c := rawBlock(body[off:end])
		chunks = append(chunks, c)
		links = append(links, link{cid: c.Bytes, hash: cidBytes(codecRaw, c.Bytes),
			tsize: c.Size, raw: uint64(end - off)})
		total += uint64(end - off)
	}

	// UnixFS Data for a chunked file: the type, the total size, and one
	// blocksize per link. The blocksizes are the *raw* contribution of each
	// child, not the size of the child's block — the distinction only shows up
	// when a child is itself a dag-pb node, and getting it wrong makes byte
	// offsets in a range request point at the wrong place.
	data := unixFS(2 /* File */, total, rawSizes(links))

	node := pbNode(links, data)
	root := block(codecDagPB, node)
	// Tsize is cumulative: this node's own bytes plus everything below.
	for _, c := range chunks {
		root.Size += c.Size
	}
	return Node{Block: root, Children: chunks}
}

// Dir builds a directory node over already-built entries.
//
// Entries are sorted here rather than trusted from the caller, because the sort
// is part of the identifier: two people with the same files must get the same
// directory, and a map iteration order is the classic way for that to stop
// being true.
func Dir(entries []Node) (Node, error) {
	if len(entries) > MaxLinks {
		return Node{}, fmt.Errorf(
			"%d entries in one directory; this builds a plain directory node "+
				"and real implementations shard past about %d into a HAMT, "+
				"which is a different node with a different identifier. "+
				"Producing one nothing else agrees with would be worse than "+
				"refusing", len(entries), MaxLinks)
	}

	sorted := append([]Node(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	var (
		links    []link
		children []Block
		below    uint64
	)
	for _, e := range sorted {
		if e.Name == "" {
			return Node{}, fmt.Errorf("a directory entry has no name")
		}
		if strings.ContainsRune(e.Name, '/') {
			return Node{}, fmt.Errorf(
				"%q contains a slash; a directory entry is one path segment", e.Name)
		}
		links = append(links, link{
			name: e.Name, hash: cidBytesOf(e.Block), tsize: e.Block.Size,
		})
		children = append(children, e.Children...)
		children = append(children, e.Block)
		below += e.Block.Size
	}

	root := block(codecDagPB, pbNode(links, unixFS(1 /* Directory */, 0, nil)))
	root.Size += below
	return Node{Block: root, Children: children}, nil
}

// Tree builds a whole site from a map of path to content.
//
// Paths use forward slashes and are split into directories, so
// "blog/post/index.html" produces the two intermediate nodes without the caller
// arranging anything. The result's Children are in upload order: every child
// before the parent that names it.
func Tree(files map[string][]byte) (Node, error) {
	if len(files) == 0 {
		return Node{}, fmt.Errorf("nothing to publish")
	}
	// Grouped by first segment, recursively. A map at each level, walked in
	// sorted order by Dir, so the shape of the input cannot change the answer.
	here := map[string][]byte{}
	sub := map[string]map[string][]byte{}
	for path, body := range files {
		clean := strings.Trim(path, "/")
		if clean == "" {
			return Node{}, fmt.Errorf("a file has an empty path")
		}
		if i := strings.IndexByte(clean, '/'); i >= 0 {
			dir, rest := clean[:i], clean[i+1:]
			if sub[dir] == nil {
				sub[dir] = map[string][]byte{}
			}
			sub[dir][rest] = body
			continue
		}
		here[clean] = body
	}

	var entries []Node
	for name, body := range here {
		if _, clash := sub[name]; clash {
			return Node{}, fmt.Errorf(
				"%q is both a file and a directory", name)
		}
		n := File(body)
		n.Name = name
		entries = append(entries, n)
	}
	for name, inner := range sub {
		n, err := Tree(inner)
		if err != nil {
			return Node{}, err
		}
		n.Name = name
		entries = append(entries, n)
	}
	return Dir(entries)
}

// All returns every block in a tree, children before parents.
//
// Upload order matters: pinning a directory whose children are not yet stored
// gives a resolver a link into nothing, and depending on the service that is
// either an error or a pin that silently never completes.
func (n Node) All() []Block {
	out := append([]Block(nil), n.Children...)
	return append(out, n.Block)
}

// -- encoding ---------------------------------------------------------------

// link is one PBLink, before serialisation.
type link struct {
	name  string
	hash  []byte // the child's CID, in binary form
	tsize uint64
	cid   []byte // retained only for raw children, for rawSizes
	raw   uint64
}

func rawSizes(links []link) []uint64 {
	out := make([]uint64, 0, len(links))
	for _, l := range links {
		out = append(out, l.raw)
	}
	return out
}

// rawBlock wraps bytes as a raw-codec block: no metadata, no wrapper.
func rawBlock(body []byte) Block {
	b := block(codecRaw, body)
	return b
}

func block(codec byte, body []byte) Block {
	return Block{
		CID:   encodeCID(codec, body),
		Bytes: body,
		Size:  uint64(len(body)),
	}
}

// cidBytes is the binary CID for a block, which is what a link holds.
func cidBytes(codec byte, body []byte) []byte {
	sum := sha256.Sum256(body)
	out := make([]byte, 0, 36)
	out = append(out, 0x01, codec, 0x12, 0x20)
	return append(out, sum[:]...)
}

// cidBytesOf recovers the binary CID from a block's text form.
//
// Decoding what we just encoded rather than keeping both around: one
// representation is the source of truth, and a struct carrying two that could
// disagree is a struct where they eventually do.
func cidBytesOf(b Block) []byte {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(b.CID[1:]))
	if err != nil {
		// Unreachable: this decodes a string this package encoded a moment ago.
		panic("ipfs: a CID this package produced does not decode: " + err.Error())
	}
	return raw
}

// encodeCID renders the text form.
func encodeCID(codec byte, body []byte) string {
	// Lowercase unpadded base32 with a 'b' prefix. RFC 4648 alphabet, which is
	// what multibase calls base32 — not the z-base-32 or Crockford variants,
	// which look similar and produce identifiers nothing resolves.
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return "b" + strings.ToLower(enc.EncodeToString(cidBytes(codec, body)))
}

// -- the two protobuf messages ----------------------------------------------
//
// Hand-encoded rather than generated. The schemas are four fields and three
// fields, they are frozen, and a protobuf runtime is a dependency this project
// does not take. Only the wire types actually used are implemented: varint for
// numbers and length-delimited for bytes.

// unixFS builds the UnixFS Data message that sits inside a PBNode.
func unixFS(kind uint64, filesize uint64, blocksizes []uint64) []byte {
	var out []byte
	out = appendVarintField(out, 1, kind) // Type
	if filesize > 0 || len(blocksizes) > 0 {
		out = appendVarintField(out, 3, filesize) // filesize
	}
	for _, n := range blocksizes {
		out = appendVarintField(out, 4, n) // blocksizes, repeated
	}
	return out
}

// pbNode serialises a DAG-PB node.
//
// Links before Data, which is schema order and not field-number order. The
// specification is explicit about this and it is the single most likely thing
// to get wrong: a node written in the natural order still decodes, and hashes
// to something no other implementation will produce.
func pbNode(links []link, data []byte) []byte {
	var out []byte
	for _, l := range links {
		out = appendBytesField(out, 2, pbLink(l))
	}
	if len(data) > 0 {
		out = appendBytesField(out, 1, data)
	}
	return out
}

// pbLink serialises one link, in field-number order — which for PBLink is also
// schema order, unlike PBNode.
func pbLink(l link) []byte {
	var out []byte
	out = appendBytesField(out, 1, l.hash)         // Hash
	out = appendBytesField(out, 2, []byte(l.name)) // Name
	out = appendVarintField(out, 3, l.tsize)       // Tsize
	return out
}

func appendVarintField(dst []byte, field int, v uint64) []byte {
	dst = binary.AppendUvarint(dst, uint64(field)<<3|0) // wire type 0
	return binary.AppendUvarint(dst, v)
}

func appendBytesField(dst []byte, field int, v []byte) []byte {
	dst = binary.AppendUvarint(dst, uint64(field)<<3|2) // wire type 2
	dst = binary.AppendUvarint(dst, uint64(len(v)))
	return append(dst, v...)
}

// Valid reports whether a string is a CID this package could have produced.
//
// Used to check what a pinning service claims. Deliberately strict: it accepts
// the one form this writes and nothing else, because the question being asked
// is "is this the identifier I computed", and a lenient parser answering "well,
// it is *a* valid identifier" answers a different question.
func Valid(cid string) error {
	if len(cid) < 2 || cid[0] != 'b' {
		return fmt.Errorf("%q is not a base32 CIDv1: it must begin with 'b'", cid)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(cid[1:]))
	if err != nil {
		return fmt.Errorf("%q is not valid base32: %w", cid, err)
	}
	if len(raw) != 36 {
		return fmt.Errorf("%q decodes to %d bytes; a sha2-256 CIDv1 is 36",
			cid, len(raw))
	}
	if raw[0] != 0x01 {
		return fmt.Errorf("%q is CID version %d; this writes version 1", cid, raw[0])
	}
	if raw[1] != codecRaw && raw[1] != codecDagPB {
		return fmt.Errorf("%q uses codec 0x%02x; this writes raw or dag-pb",
			cid, raw[1])
	}
	if raw[2] != 0x12 || raw[3] != 0x20 {
		return fmt.Errorf("%q does not use sha2-256", cid)
	}
	return nil
}
