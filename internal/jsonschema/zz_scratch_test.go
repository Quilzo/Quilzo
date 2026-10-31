package jsonschema

import (
	"encoding/json"
	"testing"
	"time"
)

func TestZZScratch(t *testing.T) {
	for _, d := range []int{8, 9, 10} {
		var nested any = []any{}
		for i := 0; i < d; i++ {
			nested = []any{nested}
		}
		for _, sch := range []string{
			`{"type":"array","items":{"allOf":[{"$ref":"#"},{"$ref":"#"},{"$ref":"#"}]}}`,
		} {
			var s any
			_ = json.Unmarshal([]byte(sch), &s)
			b, _ := json.Marshal(nested)
			var v any
			_ = json.Unmarshal(b, &v)
			c := &checker{root: s, formats: true, patterns: map[string]compiled{}}
			start := time.Now()
			err := c.check(s, v, "answer", 0)
			t.Logf("d=%d steps=%d took=%v err=%v", d, c.steps, time.Since(start), err)
		}
	}
}
