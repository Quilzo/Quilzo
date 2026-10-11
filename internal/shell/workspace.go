// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package shell

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// A workspace: the agent's folder, kept between runs. Quilzo reads and
// writes it through os.Root, which refuses a name that leads out of it,
// whether by "..", an absolute path or a link to somewhere else.

// Bounds on what the file actions take and give.
const (
	MaxRead    = 256 << 10
	MaxWrite   = 1 << 20
	MaxListed  = 500
	MaxScanned = 200_000
)

// Workspace is an agent's folder.
type Workspace struct {
	Dir  string
	root *os.Root
}

// OpenWorkspace opens a workspace, making its folder if it is not there.
func OpenWorkspace(dir string) (*Workspace, error) {
	if !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("%q is not an absolute path to a workspace", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &Workspace{Dir: dir, root: r}, nil
}

// Close lets go of the workspace.
func (w *Workspace) Close() error { return w.root.Close() }

// clean is a name in the workspace as os.Root takes it: relative, slashed,
// with no way up. "" and "." are the workspace itself.
func clean(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == "/" {
		return ".", nil
	}
	if strings.ContainsRune(name, 0) {
		return "", errors.New("a name with a NUL in it")
	}
	if path.IsAbs(name) || filepath.IsAbs(name) {
		return "", fmt.Errorf("%q is a path outside the workspace; give one inside it", name)
	}
	c := path.Clean(filepath.ToSlash(name))
	if c == ".." || strings.HasPrefix(c, "../") {
		return "", fmt.Errorf("%q leads out of the workspace", name)
	}
	return c, nil
}

// Item is one thing in a folder.
type Item struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // file, folder, link
	Size int64  `json:"size,omitempty"`
}

// List is what a folder holds, at most MaxListed things, and whether there
// were more.
func (w *Workspace) List(name string) ([]Item, bool, error) {
	c, err := clean(name)
	if err != nil {
		return nil, false, err
	}
	f, err := w.root.Open(c)
	if err != nil {
		return nil, false, notThere(name, err)
	}
	defer f.Close()
	ents, err := f.ReadDir(MaxListed + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	more := len(ents) > MaxListed
	if more {
		ents = ents[:MaxListed]
	}
	items := make([]Item, 0, len(ents))
	for _, e := range ents {
		it := Item{Name: e.Name(), Kind: "file"}
		switch {
		case e.Type()&fs.ModeSymlink != 0:
			it.Kind = "link"
		case e.IsDir():
			it.Kind = "folder"
		default:
			if fi, err := e.Info(); err == nil {
				it.Size = fi.Size()
			}
		}
		items = append(items, it)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items, more, nil
}

// Read is a file's text. A file larger than MaxRead, or one that is not
// text, is described rather than given.
func (w *Workspace) Read(name string) (string, error) {
	c, err := clean(name)
	if err != nil {
		return "", err
	}
	// Opened without waiting: a named pipe a command made would otherwise
	// hold the read, and the run, until somebody wrote to it.
	f, err := w.root.OpenFile(c, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", notThere(name, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if fi.IsDir() {
		return "", fmt.Errorf("%s is a folder; file_list shows what it holds", name)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a plain file", name)
	}
	if fi.Size() > MaxRead {
		return "", fmt.Errorf("%s is %d bytes, more than the %d a read gives; read part of it with a command", name, fi.Size(), MaxRead)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxRead+1))
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return "", fmt.Errorf("%s is not text (%d bytes)", name, len(b))
	}
	return string(b), nil
}

// Write puts text into a file, making the folders it is in.
func (w *Workspace) Write(name, text string) error {
	c, err := clean(name)
	if err != nil {
		return err
	}
	if c == "." {
		return errors.New("name a file to write")
	}
	if len(text) > MaxWrite {
		return fmt.Errorf("at most %d bytes are written at once", MaxWrite)
	}
	if dir := path.Dir(c); dir != "." {
		if err := w.root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// Into a new file beside it, then over it, so a reader never sees half.
	tmp := c + ".quilzo-writing"
	if err := w.root.WriteFile(tmp, []byte(text), 0o644); err != nil {
		return err
	}
	if err := w.root.Rename(tmp, c); err != nil {
		_ = w.root.Remove(tmp)
		return err
	}
	return nil
}

func notThere(name string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s is not in the workspace", name)
	}
	var pe *fs.PathError
	if errors.As(err, &pe) && strings.Contains(pe.Err.Error(), "escapes") {
		return fmt.Errorf("%s leads out of the workspace", name)
	}
	return err
}

// Index is what was in the workspace at a moment: each file's size and
// when it last changed, enough to see what a command changed.
type Index struct {
	Files map[string]stamp
	Size  int64
	// Cut says the scan stopped at MaxScanned files.
	Cut bool
}

type stamp struct {
	Size int64
	Mod  time.Time
}

// Scan is the workspace's index now. Git's own folder is counted in the
// size and left out of what changed: a commit changes it, and the files
// the commit was about are what a person reads.
func (w *Workspace) Scan() Index {
	ix := Index{Files: map[string]stamp{}}
	_ = fs.WalkDir(w.root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		ix.Size += fi.Size()
		if p == ".git" || strings.HasPrefix(p, ".git/") {
			return nil
		}
		if len(ix.Files) >= MaxScanned {
			ix.Cut = true
			return fs.SkipAll
		}
		ix.Files[p] = stamp{Size: fi.Size(), Mod: fi.ModTime()}
		return nil
	})
	return ix
}

// Changes are the files a step added, changed and removed.
type Changes struct {
	Added   []string `json:"added,omitempty"`
	Changed []string `json:"changed,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

// None reports that nothing changed.
func (c Changes) None() bool { return len(c.Added)+len(c.Changed)+len(c.Removed) == 0 }

// String is the changes in a line, naming at most a few of each.
func (c Changes) String() string {
	if c.None() {
		return "no files changed"
	}
	part := func(verb string, names []string) string {
		if len(names) == 0 {
			return ""
		}
		shown := names
		if len(shown) > 8 {
			shown = shown[:8]
		}
		s := verb + " " + strings.Join(shown, ", ")
		if more := len(names) - len(shown); more > 0 {
			s += fmt.Sprintf(" and %d more", more)
		}
		return s
	}
	var parts []string
	for _, p := range []string{part("added", c.Added), part("changed", c.Changed), part("removed", c.Removed)} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, "; ")
}

// Since is what changed between two indexes.
func (now Index) Since(before Index) Changes {
	var c Changes
	for p, s := range now.Files {
		if b, ok := before.Files[p]; !ok {
			c.Added = append(c.Added, p)
		} else if b != s {
			c.Changed = append(c.Changed, p)
		}
	}
	for p := range before.Files {
		if _, ok := now.Files[p]; !ok {
			c.Removed = append(c.Removed, p)
		}
	}
	sort.Strings(c.Added)
	sort.Strings(c.Changed)
	sort.Strings(c.Removed)
	return c
}

// Claim is one run's hold on a workspace: a workspace is worked on by one
// run at a time.
type Claim struct {
	path string
	run  string
}

type claimNote struct {
	Run  string    `json:"run"`
	Beat time.Time `json:"beat"`
}

// ClaimStale is how long a claim stands without its run renewing it.
const ClaimStale = 5 * time.Minute

// ClaimWorkspace takes the workspace for a run, or says which run has it.
// The claim lives at path; Renew keeps it fresh and Release lets it go.
func ClaimWorkspace(path, run string) (*Claim, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			b, _ := json.Marshal(claimNote{Run: run, Beat: time.Now().UTC()})
			_, werr := f.Write(b)
			if cerr := f.Close(); werr == nil {
				werr = cerr
			}
			if werr != nil {
				_ = os.Remove(path)
				return nil, werr
			}
			return &Claim{path: path, run: run}, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		var n claimNote
		if b, rerr := os.ReadFile(path); rerr == nil && json.Unmarshal(b, &n) == nil {
			if age := time.Since(n.Beat); age < ClaimStale && age > -time.Minute && n.Run != run {
				return nil, fmt.Errorf("the workspace is in use by run %s; one run works on it at a time", n.Run)
			}
		}
		// Left by a run that is gone, or this run's own: taken over.
		_ = os.Remove(path)
	}
	return nil, errors.New("the workspace could not be claimed")
}

// Renew keeps the claim fresh.
func (c *Claim) Renew() {
	b, _ := json.Marshal(claimNote{Run: c.run, Beat: time.Now().UTC()})
	_ = os.WriteFile(c.path, b, 0o600)
}

// Release lets the workspace go, if this run still holds it.
func (c *Claim) Release() {
	var n claimNote
	if b, err := os.ReadFile(c.path); err == nil && json.Unmarshal(b, &n) == nil && n.Run == c.run {
		_ = os.Remove(c.path)
	}
}
