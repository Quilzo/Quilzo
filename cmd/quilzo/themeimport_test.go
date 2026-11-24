// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/theme"
)

func TestASetPairBeatsTheMappingFile(t *testing.T) {
	// The file is what somebody wrote down last week; --set is what they
	// typed just now to try something. A flag a file silently overrode would
	// be a flag nobody could use to try anything.
	dir := t.TempDir()
	path := filepath.Join(dir, "map.json")
	if err := os.WriteFile(path,
		[]byte(`{"primary":"from.the.file"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := buildMapping(path, stringList{"primary=from.the.flag"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if got["primary"] != "from.the.flag" {
		t.Fatalf("primary came out %q", got["primary"])
	}
}

func TestASchemeFlagSuffixesOnlyTheColours(t *testing.T) {
	// A colour has a value per scheme and a radius does not, so suffixing a
	// radius would produce "radius.dark", which is refused downstream with a
	// message about a flag the operator did not think they were setting.
	got, err := buildMapping("", stringList{
		"primary=a.b", "radius=c.d", "surface.light=e.f",
	}, "dark")
	if err != nil {
		t.Fatal(err)
	}
	if got["primary.dark"] != "a.b" {
		t.Fatalf("a colour was not moved into the scheme: %v", got)
	}
	if got["radius"] != "c.d" {
		t.Fatalf("a length was suffixed with a scheme: %v", got)
	}
	// A key that already names a scheme is left alone: somebody who said
	// which one meant it, and overwriting that would make --scheme unable to
	// coexist with a mapping that mixes the two.
	if got["surface.light"] != "e.f" {
		t.Fatalf("an explicit scheme was overridden: %v", got)
	}
}

func TestOnlyTheTwoSchemesAreAccepted(t *testing.T) {
	if _, err := buildMapping("", stringList{"primary=a.b"}, "dim"); err == nil {
		t.Fatal("a third scheme was accepted; there are two")
	}
}

func TestAMappingLineThatIsNotAPairIsRefused(t *testing.T) {
	if _, err := buildMapping("", stringList{"primary"}, ""); err == nil {
		t.Fatal("a --set with no path was accepted")
	}
}

func TestTheSkeletonHasEveryKeyAndRefusesToClobber(t *testing.T) {
	// The skeleton exists because typing sixty names correctly before
	// anything happens is the actual friction here. Overwriting one somebody
	// has already filled in would be the worst possible moment to lose it.
	if w == nil {
		w = out.New(false)
		t.Cleanup(func() { w = nil })
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "pairs.json")
	if err := writeSkeleton(path); err != nil {
		t.Fatal(err)
	}
	got, err := buildMapping(path, nil, "")
	if err != nil {
		t.Fatalf("this program cannot read the skeleton it wrote: %v", err)
	}
	// Every line is empty, and an empty line is skipped rather than refused,
	// so a skeleton straight off the disk is a mapping that asks for nothing
	// rather than one that fails sixty times.
	if len(got) != 0 {
		t.Fatalf("the empty skeleton asked for %d thing(s)", len(got))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var pairs map[string]string
	if err := json.Unmarshal(raw, &pairs); err != nil {
		t.Fatalf("the skeleton is not valid JSON: %v", err)
	}
	for _, tok := range theme.Tokens() {
		if tok.Kind == theme.Choice {
			// A style is not something a token file carries.
			if _, ok := pairs[tok.Name]; ok {
				t.Fatalf("%s is in the skeleton, and no token file has it", tok.Name)
			}
			continue
		}
		if _, ok := pairs[tok.Name]; !ok {
			t.Fatalf("%s is not in the skeleton", tok.Name)
		}
		if tok.Kind == theme.Colour {
			if _, ok := pairs[tok.Name+".dark"]; !ok {
				t.Fatalf("%s has two schemes and the skeleton offers one",
					tok.Name)
			}
		}
	}
	if err := writeSkeleton(path); err == nil {
		t.Fatal("the skeleton overwrote a mapping that was already there")
	}
}

func TestAFileTooLargeToBeAnExportIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge.json")
	if err := os.WriteFile(path, make([]byte, MaxTokenFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(path); err == nil {
		t.Fatal("a file far past any published export was read into memory")
	}
}

// An export says what it wrote. It said "96 token(s) written ... as Design
// Tokens Format Module" over a file holding 86, the style, motion, icons,
// corner and scheme being choices rather than tokens and left out without a
// word, and it said the same over a Tailwind stylesheet. The count is what
// the file holds, the format is the one written, and the choices that are
// not in it are named, with the command that sets them on another site.
func TestAThemeExportSaysWhatItWrote(t *testing.T) {
	root, tpl := designStore(t)
	if err := cmdTheme(root, []string{"set", "style", "neon", "scheme", "dark", "--dir", tpl}); err != nil {
		t.Fatal(err)
	}
	old := w
	t.Cleanup(func() { w = old })
	export := func(args ...string) (said, file string) {
		t.Helper()
		var buf bytes.Buffer
		w = out.New(false)
		w.Out = &buf
		path := filepath.Join(t.TempDir(), "export")
		if err := cmdTheme(root, append([]string{"export", "--dir", tpl, "--out", path}, args...)); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return buf.String(), string(b)
	}
	counted := regexp.MustCompile(`(\d+) token\(s\) written`)

	said, file := export()
	m := counted.FindStringSubmatch(said)
	if want := strings.Count(file, `"$value"`); m == nil || m[1] != fmt.Sprint(want) {
		t.Errorf("the export says %v of a file holding %d tokens", m, want)
	}
	if !strings.Contains(said, "Design Tokens Format Module") {
		t.Errorf("the export does not name its format: %s", said)
	}
	for _, want := range []string{"style neon", "scheme dark", "quilzo theme set style neon"} {
		if !strings.Contains(said, want) {
			t.Errorf("the export does not say %q: %s", want, said)
		}
	}

	said, file = export("--tailwind")
	m = counted.FindStringSubmatch(said)
	if want := len(regexp.MustCompile(`(?m)^\s*--[a-z0-9-]+:`).FindAllString(file, -1)); m == nil || m[1] != fmt.Sprint(want) {
		t.Errorf("the Tailwind export says %v of a file holding %d properties", m, want)
	}
	if strings.Contains(said, "Design Tokens Format Module") || !strings.Contains(said, "Tailwind CSS v4 @theme stylesheet") {
		t.Errorf("the Tailwind export names the wrong format: %s", said)
	}
}
