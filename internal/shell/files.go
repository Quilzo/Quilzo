// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package shell

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// The rest of a workspace's file actions: reading part of a file, editing
// one in place, moving, deleting and searching. Each goes through the
// workspace's os.Root as List, Read and Write do, so no name leads out of
// it, and none touches git's own folder by hand.
//
// # Why a deletion goes to a bin
//
// A deleted file is moved into the workspace's bin and kept there a week,
// so deleting is something a run can do without a person and something a
// person can take back. Removing what is already in the bin is the one
// deletion nothing brings back, and that waits for a person, as rm does.

// Bin is the workspace's folder for what file_delete removed, and BinKeep
// how long it is kept there.
const (
	Bin     = ".quilzo-bin"
	BinKeep = 7 * 24 * time.Hour
)

// Bounds on the file actions added here.
const (
	// MaxEdited is the largest file edited in place.
	MaxEdited = MaxWrite
	// MaxLinesRead is the largest file read part of, line by line.
	MaxLinesRead = 64 << 20
	// MaxFound is how many matching lines a search answers with, and
	// MaxSearched how many files it opens.
	MaxFound    = 200
	MaxSearched = 20_000
	// MaxSearchedFile is the largest file a search reads.
	MaxSearchedFile = 1 << 20
)

// inBin reports whether a cleaned name is in the bin.
func inBin(c string) bool { return c == Bin || strings.HasPrefix(c, Bin+"/") }

// gitOwn reports whether a cleaned name is in git's own folder.
func gitOwn(c string) bool {
	for _, part := range strings.Split(c, "/") {
		if strings.EqualFold(part, ".git") {
			return true
		}
	}
	return false
}

// throughLink says which folder on the way to a cleaned name is a link,
// if any: what a person approved is the name they saw, not wherever a
// link a command left points.
func (w *Workspace) throughLink(c string) string {
	for d := path.Dir(c); d != "."; d = path.Dir(d) {
		if fi, err := w.root.Lstat(d); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
			return d
		}
	}
	return ""
}

// ReadLines is part of a file: count lines from line from (the first is
// 1), at most MaxRead bytes of them, and how many lines the file has. A
// file too large to read whole is read this way.
func (w *Workspace) ReadLines(name string, from, count int) (text string, total int, err error) {
	c, err := clean(name)
	if err != nil {
		return "", 0, err
	}
	if from < 1 {
		from = 1
	}
	if count < 1 {
		count = 2000
	}
	f, err := w.root.OpenFile(c, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", 0, notThere(name, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", 0, err
	}
	switch {
	case fi.IsDir():
		return "", 0, fmt.Errorf("%s is a folder; file_list shows what it holds", name)
	case !fi.Mode().IsRegular():
		return "", 0, fmt.Errorf("%s is not a plain file", name)
	case fi.Size() > MaxLinesRead:
		return "", 0, fmt.Errorf("%s is %d bytes, more than the %d read line by line; search it, or read it with a command", name, fi.Size(), MaxLinesRead)
	}
	sc := bufio.NewScanner(io.LimitReader(f, MaxLinesRead))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var b strings.Builder
	n, full := 0, false
	for sc.Scan() {
		n++
		if n < from || n >= from+count || full {
			continue
		}
		line := sc.Bytes()
		if !utf8.Valid(line) || bytes.IndexByte(line, 0) >= 0 {
			return "", 0, fmt.Errorf("%s is not text (line %d)", name, n)
		}
		if b.Len()+len(line)+1 > MaxRead {
			full = true
			continue
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return "", 0, fmt.Errorf("%s: %w", name, err)
	}
	if from > n && n > 0 {
		return "", n, fmt.Errorf("%s has %d lines; there is no line %d", name, n, from)
	}
	return b.String(), n, nil
}

// Edit replaces text in a file: old must be there once, or every time
// when all is set, and new takes its place. The file is written whole,
// through Write, so a reader never sees half of it.
func (w *Workspace) Edit(name, old, new string, all bool) (int, error) {
	if old == "" {
		return 0, errors.New(`say what to replace in "old"; to add lines, give "line" and "insert"`)
	}
	if old == new {
		return 0, errors.New(`"old" and "new" are the same; nothing would change`)
	}
	text, err := w.readForEdit(name)
	if err != nil {
		return 0, err
	}
	n := strings.Count(text, old)
	switch {
	case n == 0:
		return 0, fmt.Errorf("%s does not contain the text given in \"old\"; read it again, since it may have changed, "+
			"and give the text exactly, spaces and all", name)
	case n > 1 && !all:
		return 0, fmt.Errorf("the text given in \"old\" is in %s %d times; give more of what surrounds it so it "+
			"is there once, or say \"all\": true to replace every one", name, n)
	}
	if !all {
		n = 1
	}
	return n, w.Write(name, strings.Replace(text, old, new, n))
}

// Insert puts text into a file after line after (0 is before the first).
func (w *Workspace) Insert(name string, after int, text string) error {
	if text == "" {
		return errors.New(`say what to insert in "insert"`)
	}
	cur, err := w.readForEdit(name)
	if err != nil {
		return err
	}
	lines := strings.SplitAfter(cur, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if after < 0 || after > len(lines) {
		return fmt.Errorf("%s has %d lines; insert after one of 0 to %d", name, len(lines), len(lines))
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	head := strings.Join(lines[:after], "")
	if head != "" && !strings.HasSuffix(head, "\n") {
		head += "\n"
	}
	return w.Write(name, head+text+strings.Join(lines[after:], ""))
}

// readForEdit is a file's text, for editing: whole, text, and no larger
// than a write.
func (w *Workspace) readForEdit(name string) (string, error) {
	c, err := clean(name)
	if err != nil {
		return "", err
	}
	if c == "." {
		return "", errors.New("name a file to edit")
	}
	f, err := w.root.OpenFile(c, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", notThere(name, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a plain file", name)
	}
	if fi.Size() > MaxEdited {
		return "", fmt.Errorf("%s is %d bytes; files up to %d are edited in place", name, fi.Size(), MaxEdited)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxEdited+1))
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return "", fmt.Errorf("%s is not text, and only text is edited", name)
	}
	return string(b), nil
}

// Move gives a file or folder a new name in the workspace. A file already
// at the new name goes to the bin first, and the answer says so.
func (w *Workspace) Move(from, to string, now time.Time) (string, error) {
	cf, err := clean(from)
	if err != nil {
		return "", err
	}
	ct, err := clean(to)
	if err != nil {
		return "", err
	}
	switch {
	case cf == "." || ct == ".":
		return "", errors.New("name what to move and its new name, both inside the workspace")
	case cf == ct:
		return "", errors.New("the new name is the name it has")
	case gitOwn(cf) || gitOwn(ct):
		return "", errors.New("git's own folder is not moved into or out of by hand")
	case ct == Bin || inBin(ct):
		return "", errors.New("file_delete is how something goes into the bin")
	case strings.HasPrefix(ct, cf+"/"):
		return "", fmt.Errorf("%s cannot be moved inside itself", from)
	}
	if l := w.throughLink(ct); l != "" {
		return "", fmt.Errorf("%s is reached through a link (%s); name where it is", to, l)
	}
	if _, err := w.root.Lstat(cf); err != nil {
		return "", notThere(from, err)
	}
	var said string
	if fi, err := w.root.Lstat(ct); err == nil {
		if fi.IsDir() {
			return "", fmt.Errorf("%s is a folder; give the whole new name, such as %s/%s", to, to, path.Base(cf))
		}
		kept, err := w.toBin(ct, now)
		if err != nil {
			return "", err
		}
		said = fmt.Sprintf("; what was at %s is in the bin as %s", to, kept)
	}
	if dir := path.Dir(ct); dir != "." {
		if err := w.root.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	if err := w.root.Rename(cf, ct); err != nil {
		return "", notThere(from, err)
	}
	return fmt.Sprintf("moved %s to %s%s", from, to, said), nil
}

// Delete removes a file or folder from the workspace: into the bin, from
// where file_move brings it back, or for good when it is already there.
// It answers with where it went, or "" when it is gone for good.
func (w *Workspace) Delete(name string, now time.Time) (string, error) {
	c, err := clean(name)
	if err != nil {
		return "", err
	}
	switch {
	case c == ".":
		return "", errors.New("the workspace itself is not deleted; name what is in it")
	case gitOwn(c):
		return "", errors.New("git's own folder is not deleted by hand")
	}
	if _, err := w.root.Lstat(c); err != nil {
		return "", notThere(name, err)
	}
	if inBin(c) {
		if err := w.root.RemoveAll(c); err != nil {
			return "", err
		}
		return "", nil
	}
	w.emptyBin(now)
	return w.toBin(c, now)
}

// IsInBin reports whether a name is in the bin, where deleting it is for
// good.
func IsInBin(name string) bool {
	c, err := clean(name)
	return err == nil && inBin(c)
}

// toBin moves a cleaned name into the bin, under the moment and its own
// path, and says where it went.
func (w *Workspace) toBin(c string, now time.Time) (string, error) {
	var r [3]byte
	_, _ = rand.Read(r[:])
	dest := path.Join(Bin, now.UTC().Format("20060102T150405Z")+"-"+hex.EncodeToString(r[:]), c)
	if err := w.root.MkdirAll(path.Dir(dest), 0o700); err != nil {
		return "", err
	}
	if err := w.root.Rename(c, dest); err != nil {
		return "", err
	}
	return dest, nil
}

// emptyBin removes what has been in the bin longer than BinKeep. What it
// cannot read the time of is left alone.
func (w *Workspace) emptyBin(now time.Time) {
	f, err := w.root.OpenFile(Bin, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	ents, _ := f.ReadDir(10_000)
	f.Close()
	for _, e := range ents {
		stamp, _, ok := strings.Cut(e.Name(), "-")
		if !ok {
			continue
		}
		at, err := time.Parse("20060102T150405Z", stamp)
		if err == nil && now.Sub(at) > BinKeep {
			_ = w.root.RemoveAll(path.Join(Bin, e.Name()))
		}
	}
}

// Found is one line a search matched.
type Found struct {
	File string
	Line int
	Text string
}

// Search looks through the workspace's text files under a folder: for
// files whose name matches a pattern such as *.go, for lines holding some
// text, or both. text is a regular expression when regex is set (RE2,
// which takes time in proportion to what it reads, whatever the pattern).
// It answers with the files or lines found, at most MaxFound, and whether
// it stopped before looking everywhere. Git's own folder and the bin are
// not searched.
func (w *Workspace) Search(under, name, text string, regex, ignoreCase bool) ([]Found, bool, error) {
	c, err := clean(under)
	if err != nil {
		return nil, false, err
	}
	if name == "" && text == "" {
		return nil, false, errors.New(`say what to look for: a file name pattern in "name", text in "text", or both`)
	}
	if name != "" {
		if _, err := path.Match(name, ""); err != nil {
			return nil, false, fmt.Errorf("%q is not a file name pattern (such as *.go or report-??.md)", name)
		}
	}
	var match func(string) bool
	if text != "" {
		if !regex {
			text = regexp.QuoteMeta(text)
		}
		if ignoreCase {
			text = "(?i)" + text
		}
		re, err := regexp.Compile(text)
		if err != nil {
			return nil, false, fmt.Errorf("%q is not a regular expression: %v", text, err)
		}
		match = re.MatchString
	}
	var found []Found
	opened, cut := 0, false
	err = fs.WalkDir(w.root.FS(), c, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == c {
				return err
			}
			cut = true
			return nil
		}
		if d.IsDir() {
			if p != c && (strings.EqualFold(d.Name(), ".git") || p == Bin) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if name != "" {
			if ok, _ := path.Match(name, d.Name()); !ok {
				return nil
			}
		}
		if len(found) >= MaxFound || opened >= MaxSearched {
			cut = true
			return fs.SkipAll
		}
		if match == nil {
			found = append(found, Found{File: p})
			return nil
		}
		opened++
		w.searchFile(p, match, &found, &cut)
		return nil
	})
	if err != nil {
		return nil, false, notThere(under, err)
	}
	return found, cut, nil
}

// searchFile adds a file's matching lines to found.
func (w *Workspace) searchFile(p string, match func(string) bool, found *[]Found, cut *bool) {
	f, err := w.root.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() || fi.Size() > MaxSearchedFile {
		return
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxSearchedFile+1))
	if err != nil || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return
	}
	for i, line := range strings.Split(string(b), "\n") {
		if !match(line) {
			continue
		}
		if len(*found) >= MaxFound {
			*cut = true
			return
		}
		if len(line) > 300 {
			line = strings.ToValidUTF8(line[:300], "") + "…"
		}
		*found = append(*found, Found{File: p, Line: i + 1, Text: line})
	}
}
