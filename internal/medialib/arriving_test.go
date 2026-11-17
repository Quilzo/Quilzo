// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package medialib

import (
	"os"
	"testing"
)

// A record whose bytes are gone is not a file the library holds. Arriving
// read the record alone, so an upload of a picture whose bytes had been lost
// (a folder copied without them, a file removed by hand) was "already in the
// library" and nothing was stored: the upload that used to put the picture
// back left every page that showed it broken, and said it was kept as it was.
func TestAnUploadIsNotAlreadyHereWhenItsBytesAreGone(t *testing.T) {
	lib := library(t)
	f := onePNG(t, lib)
	upload := f
	upload.Alt = "somebody else's words"

	arriving, was, here := lib.Arriving(upload, false)
	if !here || arriving.Alt != "a single pixel" || was.Alt != "a single pixel" {
		t.Fatalf("a file the library holds arrives as %+v, here %v", arriving, here)
	}

	if err := os.Remove(lib.path(f.ID)); err != nil {
		t.Fatal(err)
	}
	arriving, _, here = lib.Arriving(upload, false)
	if here {
		t.Fatal("a record with no bytes beside it is taken for a file that is here")
	}
	if arriving.Alt != upload.Alt {
		t.Errorf("what arrives is %q, not the upload", arriving.Alt)
	}
}
