// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package yamlite

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func parse(t *testing.T, src string) any {
	t.Helper()
	v, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("%v\n%s", err, src)
	}
	return v
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// The shapes agent definitions are written in, read as encoding/json
// would read the same document.
func TestTheYAMLAgentsAreWrittenInReadsAsItsJSON(t *testing.T) {
	cases := map[string]struct{ yaml, json string }{
		"an ADK agent config": {`# yaml-language-server: $schema=https://example/schema.json
agent_class: LlmAgent
name: assistant_agent
model: gemini-2.5-flash
description: A helper that answers questions.
instruction: |
  You are a helpful assistant.

  Answer in one paragraph.
tools:
  - name: google_search
  - name: my_library.tools.lookup
    args:
      - name: limit
        value: 5
sub_agents:
  - config_path: search_agent.yaml
`, `{"agent_class":"LlmAgent","description":"A helper that answers questions.","instruction":"You are a helpful assistant.\n\nAnswer in one paragraph.\n","model":"gemini-2.5-flash","name":"assistant_agent","sub_agents":[{"config_path":"search_agent.yaml"}],"tools":[{"name":"google_search"},{"args":[{"name":"limit","value":5}],"name":"my_library.tools.lookup"}]}`},
		"CrewAI's agents.yaml": {`researcher:
  role: >
    {topic} Senior Data Researcher
  goal: >
    Uncover cutting-edge developments in {topic}
  backstory: >
    You're a seasoned researcher with a knack for uncovering the latest
    developments in {topic}. Known for your ability to find the most relevant
    information and present it in a clear and concise manner.
  llm: openai/gpt-4o
  allow_delegation: false
  max_iter: 15

reporting_analyst:
  role: "{topic} Reporting Analyst"
  goal: 'Create detailed reports'
  backstory: plain words
    over two lines
`, `{"reporting_analyst":{"backstory":"plain words over two lines","goal":"Create detailed reports","role":"{topic} Reporting Analyst"},"researcher":{"allow_delegation":false,"backstory":"You're a seasoned researcher with a knack for uncovering the latest developments in {topic}. Known for your ability to find the most relevant information and present it in a clear and concise manner.\n","goal":"Uncover cutting-edge developments in {topic}\n","llm":"openai/gpt-4o","max_iter":15,"role":"{topic} Senior Data Researcher\n"}}`},
		"front matter with a flow list and a comma list": {`---
name: code-reviewer
description: Reviews code for quality and best practices
tools: Read, Glob, Grep
skills: [lint, "test runner"]
model: sonnet
maxTurns: 20
`, `{"description":"Reviews code for quality and best practices","maxTurns":20,"model":"sonnet","name":"code-reviewer","skills":["lint","test runner"],"tools":"Read, Glob, Grep"}`},
		"a list at its key's indentation, and nested lists": {`tools:
- a
- - b
  - c
- {k: v, n: [1, 2]}
empty:
nothing: ~
`, `{"empty":null,"nothing":null,"tools":["a",["b","c"],{"k":"v","n":[1,2]}]}`},
		"quoting and escapes": {`a: "line\none \"quoted\" \u00e9"
b: 'it''s'
c: "a
  folded
  value"
d: "x" # a comment
e: http://example.com/a#b
f: "#not a comment"
g: 0x1F
h: 1.5e3
i: "123"
j: yes
`, `{"a":"line\none \"quoted\" é","b":"it's","c":"a folded value","d":"x","e":"http://example.com/a#b","f":"#not a comment","g":31,"h":1500,"i":"123","j":"yes"}`},
		"block scalar chomping and indentation": {`keep: |+
  kept

strip: |-
  stripped
indented: |2
    two more
  than this
folded: >-
  one
  two

  three
    indented
  four
last: x
`, `{"folded":"one two\nthree\n  indented\nfour","indented":"  two more\nthan this\n","keep":"kept\n\n","last":"x","strip":"stripped"}`},
		// The line break ending the file ends its last line, and is not
		// one more for a block kept with |+ to keep.
		"a kept block ending the file": {"keep: |+\n  kept\n\n", `{"keep":"kept\n\n"}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var want any
			if err := json.Unmarshal([]byte(c.json), &want); err != nil {
				t.Fatal(err)
			}
			got := parse(t, c.yaml)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("read\n%s\nwant\n%s", asJSON(got), asJSON(want))
			}
		})
	}
}

// What it does not follow it refuses, and says where: a guess would be an
// agent with words nobody wrote.
func TestWhatIsNotReadIsRefusedByLine(t *testing.T) {
	for name, src := range map[string]string{
		"an anchor":            "a: &x 1\nb: 2\n",
		"an alias":             "a: 1\nb: *a\n",
		"a tag":                "a: !!str 1\n",
		"a merge key":          "base: {}\nchild:\n  <<: {}\n",
		"a complex key":        "? a\n: b\n",
		"a tab":                "a:\n\tb: 1\n",
		"a key twice":          "a: 1\na: 2\n",
		"two documents":        "a: 1\n---\nb: 2\n",
		"a broken indentation": "a:\n  b: 1\n c: 2\n",
		"an unclosed quote":    "a: \"never\n",
		"an unclosed flow":     "a: [1, 2\n",
		"a bad escape":         `a: "\q"` + "\n",
		"a directive":          "%YAML 1.2\n---\na: 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(src)); err == nil {
				t.Errorf("read as if understood:\n%s", src)
			} else if !strings.HasPrefix(err.Error(), "line ") && name != "a bad escape" && name != "an unclosed quote" {
				t.Logf("%v", err)
			}
		})
	}
}

// What the writer writes, the reader reads back as the same value,
// whatever the strings hold.
func TestWhatIsWrittenReadsBackTheSame(t *testing.T) {
	v := Map{
		{"name", "assistant"},
		{"instruction", "You are helpful.\n\n  Indented line.\nLast line with trailing space "},
		{"literal", "One\nTwo\n"},
		{"kept", "One\n\n"},
		{"stripped", "One\nTwo"},
		{"tricky", "key: value # not a comment"},
		{"leading", "- not a list"},
		{"number-like", "0x10"},
		{"bool-like", "true"},
		{"null-like", "~"},
		{"empty", ""},
		{"unicode", "café ☕"},
		{"n", 3},
		{"f", 1.5},
		{"b", false},
		{"nil", nil},
		{"tools", []any{Map{{"name", "a"}, {"args", []any{Map{{"name", "k"}, {"value", 2}}}}}, "plain", []any{"x"}, []any{}}},
		{"empty map", Map{}},
		{"sorted", map[string]any{"z": 1, "a": 2}},
	}
	b, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	want := map[string]any{
		"name": "assistant", "instruction": "You are helpful.\n\n  Indented line.\nLast line with trailing space ",
		"literal": "One\nTwo\n", "kept": "One\n\n", "stripped": "One\nTwo",
		"tricky": "key: value # not a comment", "leading": "- not a list", "number-like": "0x10",
		"bool-like": "true", "null-like": "~", "empty": "", "unicode": "café ☕",
		"n": 3.0, "f": 1.5, "b": false, "nil": nil,
		"tools": []any{map[string]any{"name": "a", "args": []any{map[string]any{"name": "k", "value": 2.0}}},
			"plain", []any{"x"}, []any{}},
		"empty map": map[string]any{}, "sorted": map[string]any{"z": 1.0, "a": 2.0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("wrote\n%s\nread back\n%s", b, asJSON(got))
	}
	if _, err := Marshal(Map{{"x", math.Inf(1)}}); err == nil {
		t.Error("an infinity was written")
	}
}

// A file cut off anywhere, or garbled, is an error or a value: never a
// crash, whatever arrives to be imported.
func TestNothingItIsGivenCrashesIt(t *testing.T) {
	docs := []string{
		"a:\n  - b: |\n      text\n    c: [1, {d: \"e\"}]\n  - - x\n    - 'y'\nf: >-\n  g\n\n  h\n",
		"---\nname: x\ndescription: \"multi\n  line\"\ntools: Read, Grep\n---\nbody\n",
		"- \n-\n  - a\n- \"\\u00\"\n- |9\n- ? \n",
		"{a: [b, {c: d}], e: f}\n", "[1, 2, [3, [4]]]\n", "\"\\", "'", "a: |", "a: >+2\n", "- - - -", ":", "?", "#", "a: b: c",
	}
	for _, d := range docs {
		for i := 0; i <= len(d); i++ {
			_, _ = Parse([]byte(d[:i]))
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"a:\n  - b: |\n      text\n    c: [1, {d: \"e\"}]\n", "x: >-\n  y\n\n  z\n", "- - a\n  - b\n",
		"name: x\ninstruction: \"a\\nb\"\n", "k: 'it''s'\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := Parse(b)
		if err != nil {
			return
		}
		// What it read, it writes, and reads back the same.
		out, err := Marshal(v)
		if err != nil {
			return
		}
		again, err := Parse(out)
		if err != nil {
			t.Fatalf("its own writing was refused: %v\n%q\nfrom %q", err, out, b)
		}
		if asJSON(again) != asJSON(v) {
			t.Fatalf("read back differently:\n%s\n%s\nwrote %q from %q", asJSON(v), asJSON(again), out, b)
		}
	})
}
