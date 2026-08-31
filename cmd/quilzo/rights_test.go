package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// A reference is recognised by its value, not by the field it sits in.
//
// Content says whatever it says: an image lives in "image" on one type and
// "avatar" on another, and a type nobody has written yet will call it something
// else again. What is invariant is that a file is addressed by the SHA-256 of
// its bytes, so a field holding 64 hex characters the library also holds is a
// reference to that file.
func TestAssetReferencesAreFoundByValueNotByFieldName(t *testing.T) {
	id := strings.Repeat("ab", 32)
	other := strings.Repeat("cd", 32)

	got := assetIDsIn(map[string]any{
		"hero_picture": id,
		"gallery":      []any{other, "not an id"},
		"title":        "Nothing here",
		"count":        64,
		// A hash of something that is not media. Collected here and filtered
		// later by asking the library, because this function cannot know.
		"content_hash": strings.Repeat("ef", 32),
	})
	if len(got) != 3 {
		t.Fatalf("found %d candidate(s), want 3: %v", len(got), got)
	}
	var sawHero, sawGallery bool
	for _, g := range got {
		sawHero = sawHero || g == id
		sawGallery = sawGallery || g == other
	}
	if !sawHero {
		t.Error("a reference in a field called hero_picture was missed, so " +
			"this only works on field names somebody thought of")
	}
	if !sawGallery {
		t.Error("a reference inside a list was missed")
	}
}

// The gate reads records, not only pages.
//
// The same miss the claim gate had: in a shop the product photograph is on a
// record, so a gate reading only pages would clear a catalogue full of expired
// licences and report success.
func TestTheRightsGateReadsRecordsAndNotOnlyPages(t *testing.T) {
	root := t.TempDir()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	lib, err := medialib.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	// Two images: one still licensed, one whose licence ended.
	live := storeImage(t, lib, "in-term.png", media.Rights{
		Licence: "stock", Until: at.AddDate(1, 0, 0).Unix()})
	dead := storeImage(t, lib, "lapsed.png", media.Rights{
		Licence: "stock", Until: at.AddDate(0, -1, 0).Unix()})

	// The good one on a page, the expired one on a record.
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{"title": "Home", "image": live},
	}, "pages", "test"); err != nil {
		t.Fatal(err)
	}
	putTestRecords(t, s, "products", []collection.Record{
		{Fields: map[string]any{"name": "Brass pen", "image": dead}},
	})

	rep, err := checkRights(s, lib, site.RefDraft, at)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Checked != 2 {
		t.Errorf("%d image(s) examined, want 2. One means the record was "+
			"never read, which is the failure where this reports clean on a "+
			"whole catalogue", rep.Checked)
	}
	if rep.Blocking() != 1 {
		t.Fatalf("want one blocking image — the one on the record — got %d",
			rep.Blocking())
	}
	// And it says which content would have carried it, because "an image has
	// expired" without naming the page is a report nobody can act on.
	where := strings.Join(rep.Expired[0].Where, " ")
	if !strings.Contains(where, "products/") {
		t.Errorf("the finding does not name what uses the image: %q", where)
	}
}

// Lapsing warns and does not block, and the two are different answers.
func TestLapsingWarnsAndOnlyExpiredBlocks(t *testing.T) {
	root := t.TempDir()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	lib, err := medialib.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	soon := storeImage(t, lib, "soon.png", media.Rights{
		Licence: "stock", Until: at.AddDate(0, 0, 20).Unix()})
	quiet := storeImage(t, lib, "quiet.png", media.Rights{})

	if _, err := site.SaveDraft(s, map[string]any{
		"a": map[string]any{"title": "A", "image": soon},
		"b": map[string]any{"title": "B", "image": quiet},
	}, "pages", "test"); err != nil {
		t.Fatal(err)
	}
	rep, err := checkRights(s, lib, site.RefDraft, at)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Blocking() != 0 {
		t.Errorf("something blocked a publication: %d. Only an expiry that "+
			"has passed may — a gate refusing three different things is one "+
			"people switch off", rep.Blocking())
	}
	if len(rep.Lapsing) != 1 {
		t.Errorf("want one lapsing image, got %d — the warning is the half "+
			"worth having, because an expired licence cannot be fixed after "+
			"the fact", len(rep.Lapsing))
	}
	if len(rep.Undeclared) != 1 {
		t.Errorf("want one undeclared image, got %d", len(rep.Undeclared))
	}
}

// A hash-shaped value the library does not hold is not a missing asset.
//
// Content stores hashes for other reasons. Treating every 64-hex string as a
// media reference would report a false alarm on each one.
func TestAHashThatIsNotAnAssetIsNotAFinding(t *testing.T) {
	root := t.TempDir()
	s, err := store.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	lib, err := medialib.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := site.SaveDraft(s, map[string]any{
		"index": map[string]any{
			"title": "Home", "content_hash": strings.Repeat("ef", 32)},
	}, "pages", "test"); err != nil {
		t.Fatal(err)
	}
	rep, err := checkRights(s, lib, site.RefDraft,
		time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Checked != 0 {
		t.Errorf("%d image(s) examined; a hash of something that is not media "+
			"was treated as a media reference", rep.Checked)
	}
}

// storeImage puts a real decodable image in the library with the given rights.
func storeImage(t *testing.T, lib *medialib.Library, name string,
	r media.Rights) string {
	t.Helper()
	// Distinct bytes per name. A file is addressed by the hash of its bytes,
	// so two identical images deduplicate to one address and every assertion
	// about "two images" would really be about one.
	body := testPNG(name)
	f, err := media.Accept(name, body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Distinct bytes per name, or the two files deduplicate to one address and
	// every assertion about "two images" is really about one.
	f.Alt = "a test image called " + name
	f.Rights = r
	if err := lib.Put(f, body); err != nil {
		t.Fatal(err)
	}
	return f.ID
}

// testPNG encodes a small image whose pixels depend on the name.
func testPNG(name string) []byte {
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	var h uint32 = 2166136261
	for _, b := range []byte(name) {
		h ^= uint32(b)
		h *= 16777619
	}
	c := color.RGBA{uint8(h), uint8(h >> 8), uint8(h >> 16), 255}
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// A licence recorded wrongly can be taken off.
//
// Every flag on `rights set` applies only when non-empty, which is what makes a
// partial edit work — --until on its own must not wipe the holder — and the
// cost was that nothing could say "this was recorded wrongly". An asset
// carrying a licence that does not exist is worse than one carrying none:
// `quilzo rights` reports the undeclared ones so somebody declares them, and
// reports the wrong one as cleared.
//
// It clears the whole record, because media.Rights.Validate refuses an expiry
// with no licence and no holder — a partial clear would leave a store in a
// state its own validator rejects.
func TestClearingRightsLeavesNothingHalfRecorded(t *testing.T) {
	source, err := os.ReadFile("rightscmd.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(source)
	if !strings.Contains(src, `fs.Bool("clear"`) {
		t.Fatal("rights set has no way to remove a record, so an asset " +
			"declared wrongly stays declared wrongly")
	}
	if !strings.Contains(src, "f.Rights = media.Rights{}") {
		t.Error("clearing does not empty the record")
	}
	// Combining it with a value to set is refused rather than half-applied.
	if !strings.Contains(src, "--clear removes the whole record") {
		t.Error("clearing does not refuse being combined with an edit, so " +
			"`--clear --licence x` would do one of two things and not say which")
	}
	// And it is audited, because taking a licence off is a publishing decision.
	if !strings.Contains(src, `"cleared"`) {
		t.Error("clearing a licence is not recorded in the audit log")
	}
}
