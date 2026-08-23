package webfont

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A licence beside a font is not a mistake.
//
// The Open Font Licence requires its text to be distributed with the files, so
// an operator who does it correctly puts OFL.txt in templates/fonts — and this
// used to answer with three warnings saying the licence was not a font. The
// files that are genuinely somebody's mistake, a .ttf or a .woff expecting to
// be served, still say so.
func TestALicenceBesideAFontIsNotAWarning(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, body []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("OFL.txt", []byte("Copyright ... SIL Open Font Licence 1.1"))
	write("LICENSE-Inter.txt", []byte("Copyright ..."))
	write("README.md", []byte("# the faces this site serves"))
	write("Aster.ttf", []byte("\x00\x01\x00\x00 a real TrueType file"))

	set, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, warning := range set.Warnings {
		for _, quiet := range []string{"OFL.txt", "LICENSE-Inter.txt", "README.md"} {
			if strings.Contains(warning, quiet) {
				t.Errorf("complying with the font's licence produced a "+
					"warning:\n\t%s", warning)
			}
		}
	}
	var sawTTF bool
	for _, warning := range set.Warnings {
		if strings.Contains(warning, "Aster.ttf") {
			sawTTF = true
		}
	}
	if !sawTTF {
		t.Error("a .ttf in the fonts directory is somebody expecting it to be " +
			"served, and it will not be; that still has to be said")
	}
}
