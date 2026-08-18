package ipfs

import (
	"bytes"
	"strings"
	"testing"
)

// The whole test of a content identifier is whether everybody else computes the
// same one.
//
// There is nothing to unit-test about "did we hash correctly" in isolation — a
// wrong-but-consistent implementation passes every internal check and produces
// identifiers that resolve to nothing. So these are known-answer tests against
// values published by the IPFS project and reproduced by every implementation.
// If one of these changes, this package is wrong, whatever else it says.
func TestKnownIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		what string
		got  string
		want string
	}{
		{
			// The empty file. Raw codec, so the identifier is the SHA-256 of
			// nothing at all, which is the most reproducible value in
			// computing.
			"the empty file",
			File(nil).Block.CID,
			"bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
		},
		{
			"a small file",
			File([]byte("hello world")).Block.CID,
			"bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e",
		},
		{
			// The empty directory. This one exercises the part most likely to
			// be wrong: a dag-pb node whose UnixFS payload says Directory, with
			// the PBNode fields in schema order.
			"the empty directory",
			mustDir(t).Block.CID,
			"bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354",
		},
	} {
		if tc.got != tc.want {
			t.Errorf("%s\n  got  %s\n  want %s", tc.what, tc.got, tc.want)
		}
	}
}

// The empty directory's block, byte for byte.
//
// Checked directly as well as through its hash, because when the hash is wrong
// this is the test that says why: four bytes, and each one is a decision the
// specification made.
func TestTheEmptyDirectoryBlockIsExactlyFourBytes(t *testing.T) {
	got := mustDir(t).Block.Bytes
	want := []byte{
		0x0a, // field 1 (Data), wire type 2
		0x02, // two bytes of payload
		0x08, // UnixFS field 1 (Type), wire type 0
		0x01, // Directory
	}
	if !bytes.Equal(got, want) {
		t.Errorf("empty directory block\n  got  %x\n  want %x", got, want)
	}
}

// Links come before Data, which is not field-number order.
//
// The single most likely thing to get wrong in DAG-PB, and it fails silently:
// a node written the natural way still decodes, and hashes to something no
// resolver will find. This asserts the byte order directly so a future
// "tidy-up" that sorts the fields numerically fails here rather than in
// production.
func TestLinksAreSerialisedBeforeData(t *testing.T) {
	child := File([]byte("x"))
	child.Name = "a"
	dir, err := Dir([]Node{child})
	if err != nil {
		t.Fatal(err)
	}
	raw := dir.Block.Bytes
	if len(raw) == 0 || raw[0] != 0x12 {
		t.Fatalf("a directory node must begin with a Links field (0x12), "+
			"got 0x%02x — the fields are in field-number order, which produces "+
			"an identifier nothing else agrees with", raw[0])
	}
}

// Entries sort by byte value, and the sort is part of the identifier.
//
// Two people with the same files must get the same directory. Map iteration
// order in Go is deliberately randomised, so without an explicit sort this
// would produce a different identifier on most runs — which is the kind of bug
// that passes once and fails in front of a customer.
func TestDirectoryIdentifierDoesNotDependOnInputOrder(t *testing.T) {
	build := func(names ...string) string {
		var entries []Node
		for _, n := range names {
			f := File([]byte("body of " + n))
			f.Name = n
			entries = append(entries, f)
		}
		d, err := Dir(entries)
		if err != nil {
			t.Fatal(err)
		}
		return d.Block.CID
	}
	forward := build("a", "b", "c", "Z")
	backward := build("Z", "c", "b", "a")
	if forward != backward {
		t.Errorf("the same directory built in two orders got two identifiers:"+
			"\n  %s\n  %s", forward, backward)
	}
}

// A file larger than one chunk becomes a dag-pb node over raw leaves.
func TestALargeFileIsChunked(t *testing.T) {
	body := bytes.Repeat([]byte("quilzo"), ChunkSize) // comfortably over
	n := File(body)

	if len(n.Children) < 2 {
		t.Fatalf("a %d byte file produced %d chunk(s); it should be split",
			len(body), len(n.Children))
	}
	if !strings.HasPrefix(n.Block.CID, "bafybe") {
		t.Errorf("a chunked file should be a dag-pb node (bafybe…), got %s",
			n.Block.CID)
	}
	// Every chunk is a raw block, and they reassemble to the original.
	var rebuilt []byte
	for _, c := range n.Children {
		if !strings.HasPrefix(c.CID, "bafkre") {
			t.Errorf("a chunk should be a raw block (bafkre…), got %s", c.CID)
		}
		rebuilt = append(rebuilt, c.Bytes...)
	}
	if !bytes.Equal(rebuilt, body) {
		t.Error("the chunks do not reassemble to the original file")
	}
	// Cumulative size includes the children, or a parent's Tsize lies.
	if n.Block.Size <= uint64(len(body)) {
		t.Errorf("root size %d does not include the %d bytes below it",
			n.Block.Size, len(body))
	}
}

// A tree splits paths into real directory nodes.
func TestATreeBuildsIntermediateDirectories(t *testing.T) {
	n, err := Tree(map[string][]byte{
		"index.html":            []byte("<h1>home</h1>"),
		"blog/index.html":       []byte("<h1>blog</h1>"),
		"blog/first/index.html": []byte("<h1>first</h1>"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(n.Block.CID, "bafybe") {
		t.Errorf("the root of a tree is a directory, got %s", n.Block.CID)
	}
	// Three files, two intermediate directories, one root: every one of them
	// has to be uploaded or the site has a hole in it.
	if got := len(n.All()); got < 6 {
		t.Errorf("the tree yielded %d blocks; three files plus two "+
			"directories plus a root is six at minimum", got)
	}
	// Children before parents, so nothing is pinned before what it points at.
	all := n.All()
	if all[len(all)-1].CID != n.Block.CID {
		t.Error("the root must be last, or a resolver can follow a link into " +
			"content that has not been stored yet")
	}
}

// The same input always produces the same identifier.
func TestTreesAreDeterministic(t *testing.T) {
	files := map[string][]byte{
		"a.html": []byte("a"), "b/c.html": []byte("c"), "b/d.html": []byte("d"),
	}
	first, err := Tree(files)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := Tree(files)
		if err != nil {
			t.Fatal(err)
		}
		if again.Block.CID != first.Block.CID {
			t.Fatalf("run %d produced a different identifier:\n  %s\n  %s",
				i, first.Block.CID, again.Block.CID)
		}
	}
}

// Valid accepts what this writes and rejects what it does not.
//
// It exists to check a pinning service's answer, so the interesting cases are
// the near-misses — a real identifier of the wrong kind, and a plausible string
// that is not one at all.
func TestValidChecksWhatAServiceClaims(t *testing.T) {
	good := File([]byte("anything")).Block.CID
	if err := Valid(good); err != nil {
		t.Errorf("refused an identifier this package produced: %v", err)
	}

	for _, bad := range []struct {
		cid, why string
	}{
		{"", "empty"},
		{"QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn", "a CIDv0, which this does not write"},
		{"bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyk", "one character short"},
		{"zdj7WgYfWbmcYXCJZZ2yZaMDQzGSHmUZ8ZKZKrJQPZeYcNPvE", "base58, not base32"},
		{"bafkrei!!!", "not base32 at all"},
		{"hello", "not an identifier"},
	} {
		if err := Valid(bad.cid); err == nil {
			t.Errorf("accepted %q (%s)", bad.cid, bad.why)
		}
	}
}

// A directory too large to build as one node is refused rather than guessed.
func TestAnOversizedDirectoryIsRefusedRatherThanShardedWrong(t *testing.T) {
	entries := make([]Node, MaxLinks+1)
	for i := range entries {
		f := File([]byte{byte(i)})
		f.Name = string(rune('a'+i%26)) + string(rune('a'+i/26))
		entries[i] = f
	}
	if _, err := Dir(entries); err == nil {
		t.Error("built a directory past the point where real implementations " +
			"shard into a HAMT; the identifier would resolve to nothing")
	}
}

// A path that is both a file and a directory is a mistake, not a merge.
func TestAPathCannotBeBothFileAndDirectory(t *testing.T) {
	_, err := Tree(map[string][]byte{
		"blog":            []byte("a page called blog"),
		"blog/index.html": []byte("a page inside blog"),
	})
	if err == nil {
		t.Error("accepted a name that is simultaneously a file and a directory")
	}
}

func mustDir(t *testing.T) Node {
	t.Helper()
	// Dir with no entries: the empty directory, whose identifier is published.
	n, err := Dir(nil)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
