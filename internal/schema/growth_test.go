package schema

import (
	"strings"
	"testing"
)

// Growth check: the CVE's signature is time doubling per added character. If
// validation is linear, ten times the input is about ten times the work.
func TestValidationGrowsLinearly(t *testing.T) {
	typ := article()
	measure := func(n int) int64 {
		s := strings.Repeat("a", n) + "!"
		content := map[string]any{"title": s, "body": s, "slug": s, "contact": s, "canonical": s}
		start := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				Validate(typ, content)
			}
		})
		return start.NsPerOp()
	}
	small, large := measure(1000), measure(10000)
	ratio := float64(large) / float64(small)
	t.Logf("1k chars: %dns   10k chars: %dns   ratio %.1fx (linear would be ~10x)", small, large, ratio)
	if ratio > 40 {
		t.Errorf("10x the input cost %.1fx the time; that is not linear", ratio)
	}
}
