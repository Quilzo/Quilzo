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
