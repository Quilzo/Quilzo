// Package webfont loads the typefaces a site serves from its own origin.
//
// # Why self-hosted and nothing else
//
// A page that links a font from another host has handed that host a request on
// every visit — a record of every reader, and the ability to stall the first
// paint or change what the page looks like. The Content-Security-Policy cannot
// help, because the page asked for it. So there is no way to name a remote font
// here: a site serves the faces in its own templates/fonts directory or it uses
// the built-in stacks, which are already on the reader's device.
//
// # Why a font is validated rather than trusted
//
// These bytes are served from the site's own origin, which is the origin the
// page trusts. That makes the directory a place where chosen bytes reach a URL
// inside the trust boundary — the same argument that makes the admin's logo one
// character rather than an uploaded image.
//
// A font is not markup and a browser does not execute it, but font parsers are
// a historically rich source of memory-safety bugs and the honest position is
// that this program cannot audit one. What it can do is refuse anything that is
// not what it claims: the WOFF2 signature is checked, the length field has to
// agree with the file, the size is bounded, and the name has to be a name. An
// operator putting a font here is making a decision about their own readers;
// this makes sure they are making it about a font.
//
// # Why the filename is the contract
//
// There is no manifest to write. The filename carries the family, the weight and
// the style, because a manifest is a second place for the truth to live and the
// first thing to go stale when somebody adds a file. Satoshi.woff2 is the family
// Satoshi across the full variable range; Satoshi-600.woff2 is one weight;
// Satoshi-400-700.woff2 is a range; Satoshi-italic.woff2 is the italic.
package webfont

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/theme"
)

// MaxBytes bounds one face.
//
// A latin subset of a variable face is 40 to 60 kilobytes. Half a megabyte is
// already an unsubsetted family with every script in it, which is a page-weight
// problem rather than an attack, and saying so at the boundary is cheaper than
// discovering it in somebody's field report.
const MaxBytes = 512 << 10

// signature is the WOFF2 magic: "wOF2".
var signature = []byte{0x77, 0x4F, 0x46, 0x32}

// A family name has to be a name. It lands in a CSS font-family value and in a
// URL path, so it is matched rather than escaped: letters, digits, and single
// separators between them.
var reFamily = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:[ _][A-Za-z0-9]+)*$`)

// Face is one loaded file.
type Face struct {
	// File is the name as served: Satoshi-600.woff2.
	File string
	// Family is the CSS family this face belongs to.
	Family string
	// Weight is a single weight or a variable range, as CSS wants it.
	Weight string
	// Style is "normal" or "italic".
	Style string
	// Bytes is the file, held in memory. Fonts are small and read once, and a
	// per-request read would be a filesystem call on the hot path for a file
	// that never changes while the process is running.
	Bytes []byte
}

// Set is every face a site serves.
type Set struct {
	faces []Face
	// Warnings names files that were refused, so a font that is not being served
	// says why rather than silently not working. A silent skip is how somebody
	// spends an afternoon on a cache they do not have.
	Warnings []string
}

// Load reads every .woff2 in a directory.
//
// A missing directory is not an error: most sites have no fonts of their own and
// the built-in stacks are a complete answer. An unreadable one is, because that
// is a site whose design is about to be quietly different from the one its
// operator configured.
func Load(dir string) (*Set, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return &Set{}, nil
		}
		return nil, err
	}
	set := &Set{}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, name := range names {
		if !strings.HasSuffix(strings.ToLower(name), ".woff2") {
			set.Warnings = append(set.Warnings, fmt.Sprintf(
				"%s is not a .woff2 and was not served. WOFF2 only: it is the "+
					"one format every browser in use reads, so shipping a "+
					"second is bytes nobody downloads", name))
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			set.Warnings = append(set.Warnings, name+" could not be read: "+rerr.Error())
			continue
		}
		face, verr := parse(name, b)
		if verr != nil {
			set.Warnings = append(set.Warnings, name+" was refused: "+verr.Error())
			continue
		}
		set.faces = append(set.faces, face)
	}
	return set, nil
}

// parse validates one file and reads its contract off the filename.
func parse(name string, b []byte) (Face, error) {
	if len(b) > MaxBytes {
		return Face{}, fmt.Errorf("%d bytes, and the limit is %d. Subset it to "+
			"the scripts the site actually uses", len(b), MaxBytes)
	}
	if len(b) < 48 || string(b[:4]) != string(signature) {
		return Face{}, fmt.Errorf(
			"this is not a WOFF2 file — the signature is missing. A .ttf or " +
				"an .otf renamed does not become one; convert it")
	}
	// Bytes 8..12 are the total length the file declares. A file that disagrees
	// with itself is either truncated or is not what it says, and both are
	// reasons to refuse rather than hand it to a parser.
	declared := binary.BigEndian.Uint32(b[8:12])
	if int(declared) != len(b) {
		return Face{}, fmt.Errorf(
			"the file declares %d bytes and is %d. It is truncated or it is "+
				"not the file it claims to be", declared, len(b))
	}

	stem := strings.TrimSuffix(strings.TrimSuffix(name, ".woff2"), ".WOFF2")
	parts := strings.Split(stem, "-")
	family := strings.TrimSpace(parts[0])
	if !reFamily.MatchString(family) {
		return Face{}, fmt.Errorf(
			"%q is not a usable family name. Letters and digits, with single "+
				"spaces or underscores between them — it becomes both a CSS "+
				"family and part of a URL", family)
	}

	face := Face{File: name, Family: family, Weight: "100 900", Style: "normal", Bytes: b}
	for _, part := range parts[1:] {
		p := strings.ToLower(strings.TrimSpace(part))
		switch {
		case p == "italic" || p == "oblique":
			face.Style = "italic"
		case p == "" || p == "regular" || p == "normal" || p == "variable" || p == "vf":
			// Nothing to say: the defaults already cover these.
		default:
			if w, ok := weight(p); ok {
				face.Weight = w
				continue
			}
			return Face{}, fmt.Errorf(
				"%q in the filename is neither a weight, a weight range nor "+
					"a style. Name it Family-600.woff2, "+
					"Family-400-700.woff2 or Family-italic.woff2", part)
		}
	}
	return face, nil
}

// weight reads a single weight or a range.
func weight(s string) (string, bool) {
	if lo, hi, isRange := strings.Cut(s, ".."); isRange {
		a, aok := number(lo)
		b, bok := number(hi)
		if aok && bok && a <= b {
			return a + " " + b, true
		}
		return "", false
	}
	if n, ok := number(s); ok {
		return n, true
	}
	// Named weights, because "Satoshi-bold.woff2" is what somebody will write.
	named := map[string]string{
		"thin": "100", "extralight": "200", "light": "300", "book": "400",
		"medium": "500", "semibold": "600", "bold": "700", "extrabold": "800",
		"black": "900",
	}
	if n, ok := named[s]; ok {
		return n, true
	}
	return "", false
}

func number(s string) (string, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 1000 {
		return "", false
	}
	return strconv.Itoa(n), true
}

// Faces returns every loaded face.
func (s *Set) Faces() []Face {
	if s == nil {
		return nil
	}
	out := make([]Face, len(s.faces))
	copy(out, s.faces)
	return out
}

// Families is what the theme needs: the declarations to emit as @font-face.
func (s *Set) Families() []theme.Family {
	if s == nil {
		return nil
	}
	out := make([]theme.Family, 0, len(s.faces))
	for _, f := range s.faces {
		out = append(out, theme.Family{
			Name:   f.Family,
			Href:   "/fonts/" + f.File,
			Weight: f.Weight,
			Style:  f.Style,
		})
	}
	return out
}

// Names lists the distinct family names, so a message can say what is available.
func (s *Set) Names() []string {
	if s == nil {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, f := range s.faces {
		if seen[f.Family] {
			continue
		}
		seen[f.Family] = true
		out = append(out, f.Family)
	}
	sort.Strings(out)
	return out
}

// File returns one face's bytes by the name it is served under.
//
// Looked up in the loaded set rather than read from the directory, so a path
// that walked out of it has nowhere to arrive: the only names that resolve are
// names this package already validated.
func (s *Set) File(name string) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	for _, f := range s.faces {
		if f.File == name {
			return f.Bytes, true
		}
	}
	return nil, false
}

// Len is how many faces are loaded.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.faces)
}
