// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package vector

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A vector is kept by its model and its text's hash, never the text, and
// read back as it was kept, to float32's precision; another model's vector
// for the same text is another vector.
func TestAVectorIsKeptByItsTextsHash(t *testing.T) {
	st := Store{Dir: t.TempDir()}
	if _, ok := st.Get("m", "returns within 30 days"); ok {
		t.Fatal("a vector nobody kept")
	}
	if !st.Stamp("m").IsZero() {
		t.Fatal("a stamp nobody made")
	}
	want := []float64{0.25, -0.5, 1.0 / 3}
	if err := st.Put("m", "returns within 30 days", want); err != nil {
		t.Fatal(err)
	}
	got, ok := st.Get("m", "returns within 30 days")
	if !ok || len(got) != 3 || got[0] != 0.25 || got[1] != -0.5 || math.Abs(got[2]-1.0/3) > 1e-6 {
		t.Fatalf("%v %v", got, ok)
	}
	if _, ok := st.Get("other", "returns within 30 days"); ok {
		t.Fatal("another model's vector was this one's")
	}
	_ = filepath.WalkDir(st.Dir, func(p string, d os.DirEntry, err error) error {
		if b, _ := os.ReadFile(p); strings.Contains(string(b), "returns") || strings.Contains(p, "returns") {
			t.Errorf("the text is kept at %s", p)
		}
		return nil
	})
	for _, bad := range [][]float64{nil, {math.NaN()}, {math.Inf(1)}, make([]float64, MaxDims+1)} {
		if st.Put("m", "x", bad) == nil {
			t.Errorf("kept %v", len(bad))
		}
	}
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	if err := st.Touch("m", now); err != nil || !st.Stamp("m").Equal(now) {
		t.Fatalf("%v %v", st.Stamp("m"), err)
	}
}
