package medialib_test

import (
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/medialib"
)

// An id is a path component, and anything that is not sixty-four hex
// characters must not reach the filesystem.
//
// The guard was there and was in Stat, which Get happened to call first. That
// is safe and is not obviously safe: somebody skipping Stat to avoid reading
// the record twice would remove a path-traversal check while appearing to
// make the function faster. This fails if that happens.
func TestAnIDCannotWalkOutOfTheLibrary(t *testing.T) {
	lib, err := medialib.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{
		"../../../../etc/passwd",
		"..%2f..%2fetc%2fpasswd",
		strings.Repeat("a", 63), // one short
		strings.Repeat("a", 65), // one long
		strings.Repeat("A", 64), // uppercase is not what Accept produces
		"../" + strings.Repeat("a", 61),
		"",
		"/etc/passwd",
	} {
		if _, _, err := lib.Get(id); err == nil {
			t.Errorf("Get(%q) did not refuse", id)
		}
		if _, err := lib.Stat(id); err == nil {
			t.Errorf("Stat(%q) did not refuse", id)
		}
	}
}
