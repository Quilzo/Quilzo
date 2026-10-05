// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package selfvuln

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Is this binary the one it says it is?
//
// Three questions, from cheapest to strongest. Has the file on disk changed
// since this process started (a replacement waiting for a restart, or
// somebody else's)? Is it the binary this store last saw with this version
// (one rebuilt or patched in place keeps its version and changes its
// bytes)? And, when the operator has kept the release's SHA256SUMS beside
// the store, is it one the release published?

// Hash is the SHA-256 of a file, read as a stream.
func Hash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, bufio.NewReaderSize(f, 1<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Seen is a binary this store has run.
type Seen struct {
	Version string    `json:"version"`
	SHA256  string    `json:"sha256"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
}

// Verdict is what is known about the running binary.
type Verdict struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	// Changed says the file differs from the one this process started as.
	Changed bool `json:"changed,omitempty"`
	// Rebuilt says a binary with the same version but other bytes ran
	// here before.
	Rebuilt bool `json:"rebuilt,omitempty"`
	// Released is "matches", "differs" or "" when no SHA256SUMS is kept.
	Released string `json:"released,omitempty"`
	Says     string `json:"says"`
}

// SeenPath is where the binaries a store has run are kept.
func SeenPath(root string) string { return filepath.Join(root, "self", "binaries.json") }

// SumsPath is where an operator keeps the release's SHA256SUMS.
func SumsPath(root string) string { return filepath.Join(root, "self", "SHA256SUMS") }

// Verify answers the three questions for the binary at path, started as
// startedAs (its hash when this process began; empty to skip the first),
// and records it as seen.
func Verify(root, path, version, startedAs string, now time.Time) (Verdict, error) {
	sum, err := Hash(path)
	if err != nil {
		return Verdict{}, err
	}
	v := Verdict{Path: path, Version: version, SHA256: sum}
	v.Changed = startedAs != "" && startedAs != sum
	var seen []Seen
	if b, err := os.ReadFile(SeenPath(root)); err == nil {
		_ = json.Unmarshal(b, &seen)
	}
	found := false
	for i := range seen {
		if seen[i].Version != version {
			continue
		}
		if seen[i].SHA256 == sum {
			seen[i].Last, found = now, true
		} else {
			v.Rebuilt = true
		}
	}
	if !found {
		seen = append(seen, Seen{Version: version, SHA256: sum, First: now, Last: now})
	}
	sort.Slice(seen, func(i, j int) bool { return seen[i].Last.After(seen[j].Last) })
	if len(seen) > 50 {
		seen = seen[:50]
	}
	if err := os.MkdirAll(filepath.Dir(SeenPath(root)), 0o700); err == nil {
		b, _ := json.MarshalIndent(seen, "", " ")
		_ = atomicfile.Write(SeenPath(root), b, 0o600)
	}
	if sums, err := os.ReadFile(SumsPath(root)); err == nil {
		v.Released = "differs"
		for _, line := range strings.Split(string(sums), "\n") {
			if f := strings.Fields(line); len(f) >= 1 && strings.EqualFold(f[0], sum) {
				v.Released = "matches"
			}
		}
	}
	switch {
	case v.Changed:
		v.Says = "the binary on disk is not the one running: a replacement waiting for a restart, or somebody else's"
	case v.Released == "differs":
		v.Says = "the running binary is not one of the release's published checksums"
	case v.Rebuilt:
		v.Says = "a binary with the same version but other bytes ran here before: rebuilt, or patched in place"
	case v.Released == "matches":
		v.Says = "the running binary is one the release published"
	default:
		v.Says = "the running binary is the one this store has seen with this version; keep the release's SHA256SUMS in " + SumsPath(root) + " to check it against the release"
	}
	return v, nil
}

// Suspicious reports a verdict a person should hear about.
func (v Verdict) Suspicious() bool { return v.Changed || v.Rebuilt || v.Released == "differs" }

// FromZip reads the Go vulnerability database's zip (as vuln.go.dev
// publishes it) into a snapshot of its standard-library records, gzipped,
// as Path keeps one.
func FromZip(path string) ([]byte, Snapshot, error) {
	z, err := zip.OpenReader(path)
	if err != nil {
		return nil, Snapshot{}, err
	}
	defer z.Close()
	var out struct {
		Modified time.Time         `json:"modified"`
		Records  []json.RawMessage `json:"records"`
	}
	for _, f := range z.File {
		if f.Name == "index/db.json" {
			var idx struct {
				Modified time.Time `json:"modified"`
			}
			if err := readZipJSON(f, &idx); err != nil {
				return nil, Snapshot{}, err
			}
			out.Modified = idx.Modified
			continue
		}
		if filepath.Dir(f.Name) != "ID" {
			continue
		}
		var rec map[string]any
		if err := readZipJSON(f, &rec); err != nil {
			return nil, Snapshot{}, err
		}
		if !aboutStdlib(rec) {
			continue
		}
		delete(rec, "details")
		delete(rec, "credits")
		raw, _ := json.Marshal(rec)
		out.Records = append(out.Records, raw)
	}
	if out.Modified.IsZero() || len(out.Records) == 0 {
		return nil, Snapshot{}, errors.New("that is not the Go vulnerability database's zip: no index or no standard-library records")
	}
	sort.Slice(out.Records, func(i, j int) bool { return string(out.Records[i]) < string(out.Records[j]) })
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err := json.NewEncoder(gz).Encode(out); err != nil {
		return nil, Snapshot{}, err
	}
	if err := gz.Close(); err != nil {
		return nil, Snapshot{}, err
	}
	snap, err := read(buf.Bytes())
	if err != nil {
		return nil, Snapshot{}, fmt.Errorf("reading it back: %w", err)
	}
	return buf.Bytes(), snap, nil
}

func readZipJSON(f *zip.File, v any) error {
	r, err := f.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, 4<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func aboutStdlib(rec map[string]any) bool {
	aff, _ := rec["affected"].([]any)
	for _, a := range aff {
		m, _ := a.(map[string]any)
		p, _ := m["package"].(map[string]any)
		if n, _ := p["name"].(string); n == "stdlib" || n == "toolchain" {
			return true
		}
	}
	return false
}
