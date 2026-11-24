// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"strings"
	"testing"
)

// JSON is walked before it is decoded, and refused where a hostile file
// would use the decoder against its reader: a key given twice, nesting no
// export has, something after the end, and a document that is not one.
func TestHostileJSONRefused(t *testing.T) {
	for what, doc := range map[string]string{
		"a key given twice":    `{"status":"pass","status":"fail"}`,
		"a nested key twice":   `{"a":[{"b":1,"c":{"d":1,"d":2}}]}`,
		"nesting past the max": strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1),
		"something after":      `{"a":1} {"b":2}`,
		"not JSON":             `{"a":`,
		"nothing at all":       ``,
	} {
		if err := checkJSON([]byte(doc), false); err == nil {
			t.Errorf("%s is read", what)
		}
	}
	for what, doc := range map[string]string{
		"keys repeated in two objects": `[{"a":1},{"a":2}]`,
		"nesting at the max":           strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth),
		"an empty object":              `{}`,
	} {
		if err := checkJSON([]byte(doc), false); err != nil {
			t.Errorf("%s is refused: %v", what, err)
		}
	}
	if err := checkJSON([]byte("{\"a\":1}\n{\"a\":2}\n"), true); err != nil {
		t.Errorf("JSON lines are refused: %v", err)
	}
}

// Whatever bytes arrive, the walk answers or refuses, and never panics.
func FuzzCheckJSON(f *testing.F) {
	f.Add([]byte(`{"a":[1,2,{"b":null}]}`))
	f.Add([]byte(`[[[[`))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = checkJSON(b, false)
		_ = checkJSON(b, true)
		_, _ = jsonDocs(b)
	})
}
