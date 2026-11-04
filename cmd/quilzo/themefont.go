// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/webfont"
)

// A typeface from the file somebody has.
//
// The fonts directory took WOFF2 and nothing else, and nothing here could
// make a WOFF2: its tables are Brotli, and this program has the standard
// library and no Brotli. So the customer whose foundry sent a .ttf or an .otf
// — which is most of them — had no way in, and the help's answer was "convert
// it", with nothing to convert it with.
//
// This makes a WOFF 1.0 out of either, with zlib, and checks it the way every
// face in the directory is checked before it is written there
// (internal/webfont). A .woff or a .woff2 is checked as it is. The command
// line and the Design screen both come through addFont, so they cannot
// accept different fonts.

// fontAdded is what addFont wrote, and what it was made from.
type fontAdded struct {
	admin.FontAdded
	// Source and Served are the sizes before and after, so somebody can see
	// what converting cost or saved.
	Source int `json:"source_bytes"`
	Served int `json:"served_bytes"`
	// Path is where it was written.
	Path string `json:"path"`
}

// fontSourceExts are the extensions a name given for a face may carry; they
// are dropped, because the served name's extension is the format it is
// served in, which is decided here.
var fontSourceExts = []string{".woff2", ".woff", ".ttf", ".otf"}

// addFont writes a face into DIR/fonts/ from an uploaded or named file.
//
// filename is what the file was called, used for the served name when name is
// empty. replace allows a face already served under the same name to be
// overwritten; without it, that is refused, because a face is cached for a
// year under its name (internal/public/fonts.go) and replacing one silently
// is a change some readers see and others do not.
func addFont(dir, filename string, body []byte, name string, replace bool) (fontAdded, error) {
	if len(body) > webfont.MaxSourceBytes {
		return fontAdded{}, fmt.Errorf("%d bytes, and the most this takes is %d. "+
			"Subset it to the scripts the site uses first", len(body), webfont.MaxSourceBytes)
	}
	kind := webfont.Sniff(body)
	served, format := body, kind
	switch kind {
	case "truetype", "opentype":
		out, err := webfont.Convert(body)
		if err != nil {
			return fontAdded{}, err
		}
		served, format = out, "woff"
	case "woff", "woff2":
	case "collection":
		_, err := webfont.Convert(body) // says what to do about a collection
		return fontAdded{}, err
	default:
		return fontAdded{}, fmt.Errorf("%s is not a TrueType, OpenType, WOFF or WOFF2 face", filepath.Base(filename))
	}

	stem := strings.TrimSpace(name)
	if stem == "" {
		stem = filepath.Base(strings.ReplaceAll(filename, "\\", "/"))
	}
	for _, ext := range fontSourceExts {
		if cut, ok := cutSuffixFold(stem, ext); ok {
			stem = cut
			break
		}
	}
	// A name, not a path: it is joined to the fonts directory, so anything
	// that could walk out of it is refused before the join rather than
	// cleaned after it.
	if stem == "" || strings.ContainsAny(stem, `/\`) || strings.HasPrefix(stem, ".") {
		return fontAdded{}, fmt.Errorf("%q is not a name a face can be served under", stem)
	}
	file := stem + "." + format
	face, err := webfont.Check(file, served)
	if err != nil {
		if name == "" {
			return fontAdded{}, fmt.Errorf("%s: %v. Give it the name to serve it "+
				"under: the family, then the weight or range and the style, as in "+
				"Satoshi-400-700", file, err)
		}
		return fontAdded{}, fmt.Errorf("%s: %w", file, err)
	}

	fontsDir := filepath.Join(dir, "fonts")
	path := filepath.Join(fontsDir, file)
	// One face, one file. Satoshi-600.woff2 and Satoshi-600.woff side by
	// side are two faces with the same family, weight and style, and the
	// browser would choose between them by an order nobody chose.
	for _, other := range []string{"woff", "woff2"} {
		if other == format {
			continue
		}
		if fileExists(filepath.Join(fontsDir, stem+"."+other)) {
			return fontAdded{}, fmt.Errorf("%s.%s is already served for this face, "+
				"and two files for one face leave the browser to choose. Remove "+
				"it first, or serve this one under another name", stem, other)
		}
	}
	if fileExists(path) && !replace {
		return fontAdded{}, fmt.Errorf("%s is already served. Replacing it changes "+
			"the face for readers whose browsers fetch it again and not for those "+
			"holding the old one for a year; say so to replace it anyway", file)
	}
	if err := os.MkdirAll(fontsDir, 0o700); err != nil {
		return fontAdded{}, err
	}
	// Whole or not at all: the site reads this directory when it reloads, and
	// a face half written is a face refused.
	if err := atomicfile.Write(path, served, 0o600); err != nil {
		return fontAdded{}, err
	}
	return fontAdded{
		FontAdded: admin.FontAdded{File: face.File, Family: face.Family,
			Weight: face.Weight, Style: face.Style, From: kind},
		Source: len(body), Served: len(served), Path: path,
	}, nil
}

// cutSuffixFold is strings.CutSuffix without regard to case.
func cutSuffixFold(s, suffix string) (string, bool) {
	if len(s) >= len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix) {
		return s[:len(s)-len(suffix)], true
	}
	return s, false
}

// themeFont is `quilzo theme font add FILE`.
func themeFont(root string, args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return fmt.Errorf("usage: quilzo theme font add FILE [--name Family-400-700] " +
			"[--dir templates] [--force]")
	}
	return themeFontAdd(root, args[1:])
}

func themeFontAdd(root string, args []string) error {
	pos, flags := splitThemeArgs(args)
	fs, dir := dirFlag("font add", flags)
	name := fs.String("name", "",
		"the name to serve it under: the family, then the weight or range and the style (Satoshi-400-700)")
	force := fs.Bool("force", false, "replace a face already served under that name")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	pos = append(pos, fs.Args()...)
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo theme font add FILE [--name Family-400-700] " +
			"[--dir templates] [--force]")
	}
	f, err := os.Open(pos[0])
	if err != nil {
		return err
	}
	body, err := io.ReadAll(io.LimitReader(f, webfont.MaxSourceBytes+1))
	_ = f.Close()
	if err != nil {
		return err
	}
	added, err := addFont(*dir, pos[0], body, *name, *force)
	if err != nil {
		return err
	}
	record(root, resolveCaller(root, "").auditRecord("theme.font.add", "/",
		audit.Success, map[string]string{
			"file": added.File, "family": added.Family, "from": added.From,
		}))

	if w.JSON(added) {
		return nil
	}
	w.Human("%s%s%s is served from this origin at /fonts/%s\n", bold, added.File, reset, added.File)
	w.Human("  %sfamily %s · weight %s · %s%s\n", dim, added.Family, added.Weight, added.Style, reset)
	if added.From == "truetype" || added.From == "opentype" {
		w.Human("  %smade from a %s face: %d KiB became %d KiB of WOFF%s\n", dim,
			map[string]string{"truetype": "TrueType", "opentype": "OpenType"}[added.From],
			(added.Source+1023)/1024, (added.Served+1023)/1024, reset)
	}
	w.Human("\n  %suse it:   quilzo theme set font-body %s%s\n", dim, added.Family, reset)
	w.Human("  %sits licence goes with it: put the licence text beside it in %s%s\n",
		dim, filepath.Join(*dir, "fonts"), reset)
	w.Human("  %sthe admin's preview has it now; the site serves it from its next publish%s\n",
		dim, reset)
	return nil
}
