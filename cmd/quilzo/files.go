// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Reading and writing the store's own small files, shared by the commands.

func agentsDir(root string) string { return filepath.Join(root, "agents") }

// maxLine is the longest line a JSON Lines file may have: one record, of
// whatever a person or a program wrote, never the whole file on one line.
const maxLine = 1 << 20

// loadJSONL reads a file of one object per line. Blank lines and lines
// starting with # are skipped; a missing file is empty.
func loadJSONL(path string, each func([]byte) error) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if err := each([]byte(text)); err != nil {
			return fmt.Errorf("%s line %d: %w", path, line, err)
		}
	}
	return sc.Err()
}

// jsonNamesIn lists the .json files in a directory, without a suffix.
func jsonNamesIn(dir, exclude string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") ||
			strings.HasSuffix(name, exclude) {
			continue
		}
		out = append(out, strings.TrimSuffix(name, ".json"))
	}
	sort.Strings(out)
	return out, nil
}

// stdio is "-", which a command line takes for standard input where a file
// is read and standard output where one is written. It was a file name like
// any other: `quilzo add about=-` was "open -: no such file", and `records
// export -o -` wrote a file called "-", which is awkward to remove and never
// what was meant, while a script piping the export into gzip got nothing.
const stdio = "-"

// readInput reads a file a person named, or standard input for "-",
// refusing more than limit bytes.
func readInput(path string, limit int64) ([]byte, error) {
	if path != stdio {
		return readBounded(path, limit)
	}
	b, err := io.ReadAll(io.LimitReader(os.Stdin, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("standard input is larger than %d bytes", limit)
	}
	return b, nil
}

// toStdout reports whether a command's output goes to standard output: no
// file was named, or "-" was. A command says where it wrote only when that
// was a file, so the stream piped on carries the output and nothing else.
func toStdout(path string) bool { return path == "" || path == stdio }

// notStdio refuses "-" where a directory is written: `export json --to -`
// made a directory of that name.
func notStdio(path, flag string) error {
	if path == stdio {
		return errMisused{fmt.Errorf("%s is a directory to write into, and - is standard output; name a directory", flag)}
	}
	return nil
}

// readBounded reads a file, refusing one larger than limit.
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return b, nil
}

// readFileMaybe reads a file, returning nil rather than an error when it is
// not there.
func readFileMaybe(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return b, err
}

// safeName is a name usable as one file in one directory.
func safeName(s string) string {
	if strings.TrimSpace(s) == "" {
		return "default"
	}
	return strings.NewReplacer("/", "_", "\\", "_", ":", "_", "..", "_").
		Replace(s)
}

// writeJSON writes an indented object, creating the directory.
func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}

// multiFlag is a flag that may be given more than once.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
