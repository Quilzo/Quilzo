// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package medialib

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/media"
)

// onePNG is the smallest thing this library will accept.
func onePNG(t *testing.T, lib *Library) media.File {
	t.Helper()
	body := []byte{
		0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
		0, 0, 0, 0x0d, 'I', 'H', 'D', 'R',
		0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0,
		0x3a, 0x7e, 0x9b, 0x55,
		0, 0, 0, 0x0a, 'I', 'D', 'A', 'T',
		0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01,
		0x0d, 0x0a, 0x2d, 0xb4,
		0, 0, 0, 0, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82,
	}
	f, err := media.Accept("pixel.png", body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.Alt = "a single pixel"
	if err := lib.Put(f, body); err != nil {
		t.Fatal(err)
	}
	return f
}

func library(t *testing.T) *Library {
	t.Helper()
	lib, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return lib
}

func remembers(l *Library) int {
	l.statMu.Lock()
	defer l.statMu.Unlock()
	return len(l.stats)
}

func TestASecondStatComesFromTheMemo(t *testing.T) {
	lib := library(t)
	f := onePNG(t, lib)

	first, err := lib.Stat(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if remembers(lib) == 0 {
		t.Fatal("nothing was remembered")
	}

	again, err := lib.Stat(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.Alt != first.Alt || again.ID != first.ID {
		t.Errorf("the memo answered differently: %+v vs %+v", again, first)
	}
}

// The failure this design exists to avoid. The id is the hash of the image,
// not of the record beside it, and the record holds the alt text, the rights,
// the focal point and the caption tracks — all of which are edited.
//
// This writes the sidecar directly, the way another process does.
func TestAnEditFromAnotherProcessIsNoticed(t *testing.T) {
	lib := library(t)
	f := onePNG(t, lib)

	if _, err := lib.Stat(f.ID); err != nil {
		t.Fatal(err)
	}

	f.Alt = "a single pixel, described again"
	f.Rights = media.Rights{Licence: "CC-BY-4.0", Holder: "somebody"}
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := lib.path(f.ID) + ".json"
	// A distinct modification time, because the point of the test is the
	// check and not the resolution of the clock.
	if err := os.WriteFile(p, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(p, later, later); err != nil {
		t.Fatal(err)
	}

	got, err := lib.Stat(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Alt != "a single pixel, described again" {
		t.Errorf("the memo served the old description: %q", got.Alt)
	}
	if got.Rights.Licence != "CC-BY-4.0" {
		t.Errorf("the memo served the old rights: %+v — a licence that has "+
			"expired is a publication that should have been stopped",
			got.Rights)
	}
}

// A write through this library drops the entry outright, so an edit in this
// process is never served from the memo even for the instant before a stat
// would have caught it.
func TestAWriteThroughTheLibraryIsNoticedImmediately(t *testing.T) {
	lib := library(t)
	f := onePNG(t, lib)
	if _, err := lib.Stat(f.ID); err != nil {
		t.Fatal(err)
	}

	_, body, err := lib.Get(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.Alt = "described once more"
	if err := lib.Put(f, body); err != nil {
		t.Fatal(err)
	}

	got, err := lib.Stat(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Alt != "described once more" {
		t.Errorf("after a Put the memo still says %q", got.Alt)
	}
}

// A removed file is gone, not remembered. Otherwise a page keeps being told
// about an image that is not there, which is worse than the 404 Remove's own
// comment says a reader should get.
func TestARemovedFileIsNotStillRemembered(t *testing.T) {
	lib := library(t)
	f := onePNG(t, lib)
	if _, err := lib.Stat(f.ID); err != nil {
		t.Fatal(err)
	}
	if err := lib.Remove(f.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := lib.Stat(f.ID); err == nil {
		t.Fatal("a removed file was still described")
	} else if !strings.Contains(err.Error(), "no file") {
		t.Errorf("the error is %v", err)
	}
	if remembers(lib) != 0 {
		t.Errorf("%d entries survived the removal", remembers(lib))
	}
}

func TestAMissingFileIsNotRemembered(t *testing.T) {
	lib := library(t)
	if _, err := lib.Stat(strings.Repeat("a", 64)); err == nil {
		t.Fatal("a file that is not there was described")
	}
	if remembers(lib) != 0 {
		t.Errorf("%d entries for a file that does not exist", remembers(lib))
	}
}

func TestAnInvalidIDIsStillRefused(t *testing.T) {
	lib := library(t)
	for _, id := range []string{"", "../../etc/passwd", "ZZZZ", strings.Repeat("a", 63)} {
		if _, err := lib.Stat(id); err == nil {
			t.Errorf("%q was accepted as an id", id)
		}
	}
}

func TestTheMemoIsBounded(t *testing.T) {
	lib := library(t)
	f := onePNG(t, lib)
	for i := 0; i < maxStats+10; i++ {
		info, err := os.Stat(lib.path(f.ID) + ".json")
		if err != nil {
			t.Fatal(err)
		}
		// Distinct keys, which is what a large library gives it.
		lib.remember(idFor(i), f, info)
		if got := remembers(lib); got > maxStats {
			t.Fatalf("after %d the memo holds %d", i, got)
		}
	}
}

func idFor(i int) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 64)
	for j := range out {
		out[j] = hex[(i+j)%16]
	}
	return string(out)
}

// The memo is read and written from every request, so it has to be safe. Run
// with -race, which is where this earns its keep.
func TestConcurrentStatsAreSafe(t *testing.T) {
	lib := library(t)
	f := onePNG(t, lib)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				got, err := lib.Stat(f.ID)
				if err != nil {
					t.Error(err)
					return
				}
				if got.ID != f.ID {
					t.Errorf("got %s", got.ID)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func BenchmarkStat(b *testing.B) {
	lib, err := Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	f := onePNG(&testing.T{}, lib)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := lib.Stat(f.ID); err != nil {
			b.Fatal(err)
		}
	}
}
