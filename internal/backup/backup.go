// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

// Package backup writes a whole store to one encrypted file, checks one
// without restoring it, and restores one into an empty directory.
//
// # What is in it
//
// Every file the store keeps: the history, its settings, its sealed
// credentials (still sealed: a backup does not unseal them), the media
// library, records, logs, and the layouts beside it. Not its locks, nor
// its temporary files, nor what is not a regular file.
//
// # How it is kept
//
// A tar stream, encrypted in chunks of 64 KiB with AES-256-GCM: each
// chunk's nonce is its number and whether it is the last, and the file's
// header is bound into every chunk, so a chunk moved, dropped, changed or
// cut off at the end is refused. The key is derived for each backup from
// the backup key (HKDF-SHA256) and a salt of its own. The backup key is
// not the vault's: whoever holds the backups need not hold the keyring,
// and a credential in a backup is sealed under both.
//
// The last entry is a manifest: every file's path, size and SHA-256. A
// check reads the whole backup, decrypts every chunk and compares every
// file with the manifest, so a backup that checks is one that restores.
//
// Standard library only: archive/tar, crypto/aes, crypto/cipher,
// crypto/hkdf, crypto/sha256.
package backup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Magic begins every backup, so a file that is not one is said to be not
// one rather than to be a broken one.
const Magic = "QUILZO-BACKUP 1\n"

const (
	saltSize  = 32
	chunkSize = 64 << 10
	overhead  = 16
	// ManifestName is the manifest's entry.
	ManifestName = "MANIFEST.json"
	// MaxFiles bounds what one backup lists, and what a restore will
	// write.
	MaxFiles = 2_000_000
)

// KeySize is a backup key's length.
const KeySize = 32

// NewKey is a fresh backup key.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	_, err := rand.Read(k)
	return k, err
}

// EncodeKey writes a key as it is given to an operator.
func EncodeKey(k []byte) string { return base64.StdEncoding.EncodeToString(k) }

// DecodeKey reads one.
func DecodeKey(s string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(k) != KeySize {
		return nil, errors.New("a backup key is 32 bytes, base64")
	}
	return k, nil
}

// File is one file a backup holds.
type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest is what a backup says it holds.
type Manifest struct {
	Version int       `json:"version"`
	Created time.Time `json:"created"`
	// Note is the operator's, or the program's: which store, which build.
	Note  string `json:"note,omitempty"`
	Files []File `json:"files"`
	Bytes int64  `json:"bytes"`
}

// Source is one file to back up: where it goes in the backup, and how to
// read it.
type Source struct {
	Path string
	Open func() (io.ReadCloser, error)
}

func streamKey(key, salt []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, errors.New("a backup key is 32 bytes")
	}
	return hkdf.Key(sha256.New, key, salt, "quilzo backup stream v1", 32)
}

func nonce(n uint64, last bool) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint64(b[3:11], n)
	if last {
		b[11] = 1
	}
	return b
}

// sealer writes the encrypted stream: each chunk once it is full, and the
// last when it is closed.
type sealer struct {
	w    io.Writer
	aead cipher.AEAD
	aad  []byte
	buf  []byte
	n    uint64
}

func (s *sealer) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		room := chunkSize - len(s.buf)
		if room == 0 {
			// A full chunk is written only once more follows, so the last
			// chunk is always the one Close writes, flagged as last.
			if err := s.flush(false); err != nil {
				return 0, err
			}
			room = chunkSize
		}
		take := min(room, len(p))
		s.buf = append(s.buf, p[:take]...)
		p = p[take:]
	}
	return total, nil
}

func (s *sealer) flush(last bool) error {
	ct := s.aead.Seal(nil, nonce(s.n, last), s.buf, s.aad)
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(ct)))
	if _, err := s.w.Write(size[:]); err != nil {
		return err
	}
	if _, err := s.w.Write(ct); err != nil {
		return err
	}
	s.n++
	s.buf = s.buf[:0]
	return nil
}

func (s *sealer) Close() error { return s.flush(true) }

// Write writes a backup of sources to w, and returns its manifest.
func Write(w io.Writer, key []byte, sources []Source, note string, now time.Time) (Manifest, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return Manifest{}, err
	}
	sk, err := streamKey(key, salt)
	if err != nil {
		return Manifest{}, err
	}
	block, err := aes.NewCipher(sk)
	if err != nil {
		return Manifest{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Manifest{}, err
	}
	header := append([]byte(Magic), salt...)
	if _, err := w.Write(header); err != nil {
		return Manifest{}, err
	}
	s := &sealer{w: w, aead: aead, aad: header, buf: make([]byte, 0, chunkSize)}
	tw := tar.NewWriter(s)
	m := Manifest{Version: 1, Created: now.UTC(), Note: note}
	seen := map[string]bool{}
	for _, src := range sources {
		if err := checkPath(src.Path); err != nil {
			return m, err
		}
		if seen[src.Path] {
			return m, fmt.Errorf("%s is in the backup twice", src.Path)
		}
		seen[src.Path] = true
		f, err := add(tw, src, now)
		if err != nil {
			return m, fmt.Errorf("%s: %w", src.Path, err)
		}
		m.Files = append(m.Files, f)
		m.Bytes += f.Size
	}
	if len(m.Files) > MaxFiles {
		return m, fmt.Errorf("more than %d files", MaxFiles)
	}
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return m, err
	}
	if err := tw.WriteHeader(&tar.Header{Name: ManifestName, Mode: 0o600, Size: int64(len(b)), ModTime: now.UTC(),
		Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
		return m, err
	}
	if _, err := tw.Write(b); err != nil {
		return m, err
	}
	if err := tw.Close(); err != nil {
		return m, err
	}
	return m, s.Close()
}

// add writes one file, its size and digest taken from what was read: a
// file that grew while it was read is backed up as it was when its size
// was taken.
func add(tw *tar.Writer, src Source, now time.Time) (File, error) {
	rc, err := src.Open()
	if err != nil {
		return File{}, err
	}
	defer rc.Close()
	// Read whole first, because a tar header says the size before the
	// bytes: a file written to as it is read cannot be streamed honestly.
	var body bytes.Buffer
	if _, err := io.Copy(&body, rc); err != nil {
		return File{}, err
	}
	sum := sha256.Sum256(body.Bytes())
	if err := tw.WriteHeader(&tar.Header{Name: src.Path, Mode: 0o600, Size: int64(body.Len()), ModTime: now.UTC(),
		Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
		return File{}, err
	}
	if _, err := tw.Write(body.Bytes()); err != nil {
		return File{}, err
	}
	return File{Path: src.Path, Size: int64(body.Len()), SHA256: hex.EncodeToString(sum[:])}, nil
}

// checkPath refuses a path a restore could not write where it belongs.
func checkPath(p string) error {
	if p == "" || p == ManifestName || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") ||
		path.Clean(p) != p || p == "." || strings.HasPrefix(p, "../") || strings.Contains(p, "/../") || len(p) > 1024 {
		return fmt.Errorf("%q is not a path a backup holds", p)
	}
	return nil
}

// opener reads the encrypted stream.
type opener struct {
	r    *bufio.Reader
	aead cipher.AEAD
	aad  []byte
	n    uint64
	buf  []byte
	done bool
}

func (o *opener) Read(p []byte) (int, error) {
	for len(o.buf) == 0 {
		if o.done {
			return 0, io.EOF
		}
		var size [4]byte
		if _, err := io.ReadFull(o.r, size[:]); err != nil {
			return 0, errors.New("the backup is cut short: its last part is missing")
		}
		n := binary.BigEndian.Uint32(size[:])
		if n < overhead || n > chunkSize+overhead {
			return 0, errors.New("the backup is damaged: a part is the wrong size")
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(o.r, ct); err != nil {
			return 0, errors.New("the backup is cut short")
		}
		_, perr := o.r.Peek(1)
		last := perr == io.EOF
		pt, err := o.aead.Open(nil, nonce(o.n, last), ct, o.aad)
		if err != nil {
			if last {
				return 0, errors.New("the backup is damaged, cut short, or not for this key")
			}
			return 0, errors.New("the backup is damaged, or not for this key")
		}
		o.n++
		o.buf = pt
		o.done = last
	}
	n := copy(p, o.buf)
	o.buf = o.buf[n:]
	return n, nil
}

// open reads a backup's header and returns its contents as a tar stream.
func open(r io.Reader, key []byte) (*tar.Reader, error) {
	br := bufio.NewReaderSize(r, chunkSize+overhead+4)
	header := make([]byte, len(Magic)+saltSize)
	if _, err := io.ReadFull(br, header); err != nil || string(header[:len(Magic)]) != Magic {
		return nil, errors.New("this is not a Quilzo backup")
	}
	sk, err := streamKey(key, header[len(Magic):])
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sk)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return tar.NewReader(&opener{r: br, aead: aead, aad: header}), nil
}

// walk reads every entry, hashing each and handing it to put, and checks
// the whole against the manifest at the end.
func walk(r io.Reader, key []byte, put func(File, io.Reader) error) (Manifest, error) {
	tr, err := open(r, key)
	if err != nil {
		return Manifest{}, err
	}
	var got []File
	var m *Manifest
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Manifest{}, fmt.Errorf("reading the backup: %w", err)
		}
		if m != nil {
			return Manifest{}, errors.New("the backup has entries after its manifest")
		}
		if h.Typeflag != tar.TypeReg {
			return Manifest{}, fmt.Errorf("%q is not a file, and a backup holds only files", h.Name)
		}
		if h.Name == ManifestName {
			var mm Manifest
			if err := json.NewDecoder(io.LimitReader(tr, 512<<20)).Decode(&mm); err != nil {
				return Manifest{}, fmt.Errorf("the manifest is unreadable: %w", err)
			}
			m = &mm
			continue
		}
		if err := checkPath(h.Name); err != nil {
			return Manifest{}, err
		}
		if len(got) >= MaxFiles {
			return Manifest{}, fmt.Errorf("more than %d files", MaxFiles)
		}
		hash := sha256.New()
		counted := &countingReader{r: io.TeeReader(tr, hash)}
		if put != nil {
			if err := put(File{Path: h.Name, Size: h.Size}, counted); err != nil {
				return Manifest{}, err
			}
		}
		if _, err := io.Copy(io.Discard, counted); err != nil {
			return Manifest{}, err
		}
		got = append(got, File{Path: h.Name, Size: counted.n, SHA256: hex.EncodeToString(hash.Sum(nil))})
	}
	if m == nil {
		return Manifest{}, errors.New("the backup has no manifest")
	}
	if len(m.Files) != len(got) {
		return *m, fmt.Errorf("the manifest lists %d files and the backup holds %d", len(m.Files), len(got))
	}
	for i := range got {
		if got[i] != m.Files[i] {
			return *m, fmt.Errorf("%s is not as the manifest says", got[i].Path)
		}
	}
	return *m, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// Verify reads a whole backup: every part decrypted, every file compared
// with the manifest. Nothing is written.
func Verify(r io.Reader, key []byte) (Manifest, error) { return walk(r, key, nil) }

// Restore writes a backup's files into dir, which must not exist or be
// empty, and checks them against the manifest. On an error what was
// written stays, and is said to be incomplete.
func Restore(r io.Reader, key []byte, dir string) (Manifest, error) {
	if ents, err := os.ReadDir(dir); err == nil && len(ents) > 0 {
		return Manifest{}, fmt.Errorf("%s is not empty: a backup is restored into a directory of its own", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Manifest{}, err
	}
	m, err := walk(r, key, func(f File, body io.Reader) error {
		to := filepath.Join(dir, filepath.FromSlash(f.Path))
		if rel, err := filepath.Rel(dir, to); err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("%s would be written outside %s", f.Path, dir)
		}
		if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
			return err
		}
		out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, body); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
	if err != nil {
		return m, fmt.Errorf("%w; what was written to %s is incomplete, delete it", err, dir)
	}
	return m, nil
}

// Collect lists the files under dir to back up, as paths under prefix:
// every regular file but locks and what skip excludes, the ones under the
// directories in last after all the others.
func Collect(dir, prefix string, skip func(rel string) bool, last ...string) ([]Source, error) {
	var first, later []Source
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel != "." && skip != nil && skip(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() || strings.HasSuffix(rel, ".lock") {
			return nil
		}
		full := p
		src := Source{Path: path.Join(prefix, rel), Open: func() (io.ReadCloser, error) { return os.Open(full) }}
		for _, l := range last {
			if rel == l || strings.HasPrefix(rel, l+"/") {
				later = append(later, src)
				return nil
			}
		}
		first = append(first, src)
		return nil
	})
	sort.Slice(first, func(i, j int) bool { return first[i].Path < first[j].Path })
	sort.Slice(later, func(i, j int) bool { return later[i].Path < later[j].Path })
	return append(first, later...), err
}
