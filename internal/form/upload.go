// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package form

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/media"
)

// Files a form takes: a CV, a photograph of the damage, a signed letter.
//
// Checked the way the media library checks what an editor uploads
// (media.Accept): by what the bytes are, never by the name or the type the
// browser claimed, with that format's own limits and checks — a PDF must
// be one, an image must decode. A field takes only the kinds it declares,
// images and documents unless it says otherwise. The file is kept beside
// the submission, with it: deleted when it expires, when it is erased and
// when the form is purged. Nobody but staff ever gets it back, and they get
// it as a download, never shown in the admin's own pages.

// File is a field that takes a file.
const File Kind = "file"

// Bounds on what is uploaded.
const (
	// MaxFileBytes is the most one file may be, whatever its format allows.
	MaxFileBytes = 10 << 20
	// MaxUploadBytes is the most one submission's files may be together.
	MaxUploadBytes = 20 << 20
	// MaxKeptFileBytes is the most the files kept with every form's
	// submissions may come to together, unless the store says less
	// (Store.FileCeiling). Nothing bounded them: one address sending
	// pictures as fast as the throttle allows kept 338 MB an hour, for the
	// whole retention period, on the disk the content store and the site's
	// temporary directory are on, and a few hundred addresses would fill
	// it and stop publishing with it. A gigabyte is thousands of CVs or
	// hundreds of photographs inside a retention period.
	MaxKeptFileBytes = 1 << 30
)

// ErrFilesFull is a submission refused because the files it carries would
// take what is kept past the store's ceiling. Said to the sender as it is.
var ErrFilesFull = errors.New("this form cannot take any more files just now. Please try again later")

// UploadKinds are what a file field may take.
var UploadKinds = []string{string(media.Image), string(media.Document), string(media.Text),
	string(media.Audio), string(media.Video)}

// defaultUploadKinds are what a file field takes when it does not say.
var defaultUploadKinds = []string{string(media.Image), string(media.Document)}

// FileRef is a file a submission carries.
type FileRef struct {
	Field string `json:"field"`
	// Name is the sender's name for it, for display only: never a path.
	Name   string `json:"name"`
	Format string `json:"format"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Upload is a file as it arrived.
type Upload struct {
	Name string
	Data []byte
}

// accepts are the kinds a file field takes.
func (fl Field) accepts() []string {
	if len(fl.Accept) == 0 {
		return defaultUploadKinds
	}
	return fl.Accept
}

// HasFiles reports whether a form takes a file, so is sent as
// multipart/form-data.
func (f *Form) HasFiles() bool {
	for _, fl := range f.Fields {
		if fl.Kind == File {
			return true
		}
	}
	return false
}

// AcceptTypes is a file field's accept attribute: a hint to the browser's
// file picker, never what is checked.
func (fl Field) AcceptTypes() string {
	var out []string
	for _, k := range fl.accepts() {
		switch k {
		case string(media.Image):
			out = append(out, "image/*")
		case string(media.Document):
			out = append(out, ".pdf")
		case string(media.Text):
			out = append(out, ".txt", ".md", ".csv")
		case string(media.Audio):
			out = append(out, "audio/*")
		case string(media.Video):
			out = append(out, "video/*")
		}
	}
	return strings.Join(out, ",")
}

// checkUpload is a file checked as its field takes it.
func checkUpload(fl Field, u Upload, now time.Time) (FileRef, error) {
	if len(u.Data) > MaxFileBytes {
		return FileRef{}, fmt.Errorf("is over %d MB", MaxFileBytes>>20)
	}
	m, err := media.Accept(u.Name, u.Data, now)
	if err != nil {
		return FileRef{}, fmt.Errorf("could not be taken: %w", err)
	}
	if !slices.Contains(fl.accepts(), string(m.Kind)) {
		return FileRef{}, fmt.Errorf("takes %s, and this is %s", strings.Join(fl.accepts(), " or "), m.Kind)
	}
	sum := sha256.Sum256(u.Data)
	return FileRef{Field: fl.Name, Name: m.Name, Format: m.Format, Size: m.Size,
		SHA256: hex.EncodeToString(sum[:])}, nil
}

// AcceptWithFiles is Accept for a form that takes files: files are what
// arrived for its file fields, by field name.
func AcceptWithFiles(f *Form, values map[string]string, files map[string]Upload, source string,
	now time.Time) (Submission, error) {
	return acceptAll(f, values, files, source, now, true)
}

// filesDir is where a submission's files are kept.
func (st *Store) filesDir(form, id string) (string, error) {
	p, err := st.path(form, id)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(p, ".json") + ".files", nil
}

// fileCeiling is the most the files kept here may come to.
func (st *Store) fileCeiling() int64 {
	if st.FileCeiling > 0 {
		return st.FileCeiling
	}
	return MaxKeptFileBytes
}

// roomFor refuses a submission's files when they would take the files
// kept past the ceiling. Counted from the files on disk rather than kept
// as a total, because the admin deletes and expires submissions in
// another process, and a total here would never see it.
func (st *Store) roomFor(s Submission) error {
	var adding int64
	for _, d := range s.data {
		adding += int64(len(d))
	}
	kept, err := st.keptFileBytes()
	if err != nil {
		return err
	}
	if kept+adding > st.fileCeiling() {
		return ErrFilesFull
	}
	return nil
}

// keptFileBytes is what the files kept with every submission come to.
func (st *Store) keptFileBytes() (int64, error) {
	forms, err := os.ReadDir(st.dir)
	if err != nil {
		return 0, err
	}
	var n int64
	for _, f := range forms {
		if !f.IsDir() {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(st.dir, f.Name()))
		if err != nil {
			// Purged while this was counting: nothing of it is kept.
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || !strings.HasSuffix(e.Name(), ".files") {
				continue
			}
			files, err := os.ReadDir(filepath.Join(st.dir, f.Name(), e.Name()))
			if err != nil {
				continue
			}
			for _, fl := range files {
				if info, err := fl.Info(); err == nil && info.Mode().IsRegular() {
					n += info.Size()
				}
			}
		}
	}
	return n, nil
}

// putFiles writes a submission's files, before the submission itself, so a
// submission never names a file that is not there.
func (st *Store) putFiles(s Submission) error {
	if len(s.data) == 0 {
		return nil
	}
	dir, err := st.filesDir(s.Form, s.ID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, ref := range s.Files {
		data, ok := s.data[ref.Field]
		if !ok || !reName.MatchString(ref.Field) {
			return fmt.Errorf("no file for %s", ref.Field)
		}
		if err := os.WriteFile(filepath.Join(dir, ref.Field), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// File is one file a submission carries, checked against the digest it was
// kept with.
func (st *Store) File(form, id, field string) (FileRef, []byte, error) {
	p, err := st.path(form, id)
	if err != nil {
		return FileRef{}, nil, err
	}
	body, err := os.ReadFile(p)
	if err != nil {
		return FileRef{}, nil, errNoSubmission
	}
	var s Submission
	if err := json.Unmarshal(body, &s); err != nil {
		return FileRef{}, nil, err
	}
	for _, ref := range s.Files {
		if ref.Field != field {
			continue
		}
		dir, _ := st.filesDir(form, id)
		data, err := os.ReadFile(filepath.Join(dir, ref.Field))
		if err != nil {
			return FileRef{}, nil, err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != ref.SHA256 {
			return FileRef{}, nil, errors.New("the file is not the one that was sent")
		}
		return ref, data, nil
	}
	return FileRef{}, nil, fmt.Errorf("that submission has no file for %s", field)
}

// MIME is what a kept file is served as, from its format.
func (ref FileRef) MIME() string {
	return media.File{Format: ref.Format}.MIME()
}

// DownloadName is a safe name to save a kept file as: rebuilt, not the
// sender's.
func (ref FileRef) DownloadName(id string) string {
	ext := media.File{Format: ref.Format}.Extension()
	if ext != "" && !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return id[:min(12, len(id))] + "-" + ref.Field + ext
}
