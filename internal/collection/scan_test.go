package collection

import (
	"fmt"
	"testing"
	"time"

	"github.com/lithoform/lithoform/internal/store"
)

func seed(tb testing.TB, n int) (*store.Store, string) {
	tb.Helper()
	s, err := store.Open(tb.TempDir())
	if err != nil {
		tb.Fatal(err)
	}
	recs := make([]Record, n)
	for i := range recs {
		recs[i] = Record{Fields: map[string]any{
			"status": []string{"met", "partial", "unmet"}[i%3],
			"owner":  fmt.Sprintf("person%d", i%20),
			"title":  fmt.Sprintf("control number %d", i),
		}}
	}
	tree, _, err := PutMany(s, "", "controls", recs, time.Now())
	if err != nil {
		tb.Fatal(err)
	}
	return s, tree
}

// The cost this file exists to remove.
func BenchmarkListScan(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s, tree := seed(b, n)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, _, err := List(s, tree, "controls",
					Query{Equals: map[string]any{"status": "unmet"}, Limit: 10}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// The same question, through the index.
func BenchmarkIndexedQuery(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s, tree := seed(b, n)
			c := NewCache()
			if _, err := c.For(s, tree, "controls"); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				idx, err := c.For(s, tree, "controls")
				if err != nil {
					b.Fatal(err)
				}
				idx.Query(Query{Equals: map[string]any{"status": "unmet"}, Limit: 10})
			}
		})
	}
}

// What a write costs the next reader.
//
// The interesting number: after editing one record in ten thousand, how much
// of the index has to be rebuilt. If reuse works it is one read; if it does
// not, this looks like a cold build and the whole file is pointless.
func BenchmarkRebuildAfterOneEdit(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			s, tree := seed(b, n)
			warm, err := Build(s, tree, "controls", nil)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				next, _, err := Put(s, tree, "controls",
					Record{Fields: map[string]any{"status": "met",
						"title": fmt.Sprintf("edit %d", i)}}, time.Now())
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if _, err := Build(s, next, "controls", warm); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
