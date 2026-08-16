// Package medialib stores accepted uploads, which nothing did.
//
// `scrivet media add photo.jpg --alt "..."` printed "accepted", wrote an audit
// record, and threw the bytes away. There was no library, nothing served the
// file, and no page could refer to it. The validation was real and thorough —
// magic bytes, a full decode, format-specific size caps, metadata stripping —
// and then the result went nowhere. A validator with an upload's name on it.
//
// That was findable only by trying to use the feature rather than by reading
// its tests, all of which passed: internal/media was correct about everything
// it claimed to do, and storing files was not one of those things.
//
// # Where files go
//
//	<dir>/<aa>/<bb>/<id>        the bytes, exactly as accepted
//	<dir>/<aa>/<bb>/<id>.json   what they are
//
// Two levels of shard from the id's own first four characters, the same shape
// the record store uses and for the same reason: the id is the SHA-256 of the
// bytes, so it is uniform, the shards fill evenly, and a directory listing
// never has to hold the whole library.
//
// There is no index file. The library is what is on disk, derived by walking
// it, because an index is a second thing to keep true and the first time it
// disagrees with the directory nobody knows which one is lying — the same
// argument that keeps the collection list out of a registry.
//
// # Deduplication is free
//
// The id is the hash of the content, so the same photograph uploaded twice is
// stored once and the second upload is a no-op that returns the first one's
// id. Nothing has to detect that; it is what content addressing is.
package medialib

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/lithoform/lithoform/internal/media"
)

// Library is a directory of accepted uploads.
type Library struct{ dir string }

// reID matches what media.Accept produces: a SHA-256 in lowercase hex.
//
// Checked before an id becomes a path, every time, because an id that reaches
// the filesystem unvalidated is a traversal. The id is server-generated, so
// this can only fail on input somebody supplied — which is exactly when it
// matters.
var reID = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidID reports whether a string can address a file.
func ValidID(id string) error {
	if !reID.MatchString(id) {
		return fmt.Errorf("%q is not a media id: 64 hexadecimal characters", id)
	}
	return nil
}

// Open prepares a library, creating the directory if it is not there.
func Open(dir string) (*Library, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Library{dir: dir}, nil
}

// Dir is where the library lives.
func (l *Library) Dir() string { return l.dir }

func (l *Library) path(id string) string {
	return filepath.Join(l.dir, id[0:2], id[2:4], id)
}

// Put stores a file that has already been accepted.
//
// It takes a media.File rather than raw bytes and a name, so it cannot be
// called on anything that has not been through validation. Storing first and
// validating later is the ordering that puts a polyglot on disk.
func (l *Library) Put(f media.File, body []byte) error {
	if err := ValidID(f.ID); err != nil {
		return err
	}
	// The id has to be the hash of what is being written, or every integrity
	// check downstream verifies a claim about a file that is not there. Accept
	// computes it; this catches a caller who edited the bytes afterwards.
	if got, err := media.Accept(f.Name, body, timeOf(f)); err != nil {
		return fmt.Errorf("refusing to store bytes that no longer validate: %w", err)
	} else if got.ID != f.ID {
		return fmt.Errorf(
			"the record says %s and the bytes hash to %s; storing them under "+
				"the record's id would file the content under a name that is "+
				"not its address", f.ID[:12], got.ID[:12])
	}

	p := l.path(f.ID)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	// Written to a temporary name and renamed, so a reader never sees a
	// half-written image. The bytes are immutable once placed, which is what
	// makes that safe.
	if err := writeAtomic(p, body, 0o600); err != nil {
		return err
	}
	meta, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(p+".json", append(meta, '\n'), 0o600)
}

// Get returns a file and its bytes.
func (l *Library) Get(id string) (media.File, []byte, error) {
	f, err := l.Stat(id)
	if err != nil {
		return media.File{}, nil, err
	}
	body, err := os.ReadFile(l.path(id))
	if err != nil {
		return media.File{}, nil, err
	}
	return f, body, nil
}

// Stat returns what a file is, without reading it.
func (l *Library) Stat(id string) (media.File, error) {
	if err := ValidID(id); err != nil {
		return media.File{}, err
	}
	body, err := os.ReadFile(l.path(id) + ".json")
	if os.IsNotExist(err) {
		return media.File{}, fmt.Errorf("there is no file %s here", id[:12])
	}
	if err != nil {
		return media.File{}, err
	}
	var f media.File
	if err := json.Unmarshal(body, &f); err != nil {
		return media.File{}, fmt.Errorf("%s: %w", id[:12], err)
	}
	return f, nil
}

// List returns everything in the library, newest first.
//
// A walk, and said plainly: there is no index, so this reads one small JSON
// file per stored asset. That is fine for the libraries a single node holds
// and it is the honest cost of not keeping a second copy of the truth.
func (l *Library) List() ([]media.File, error) {
	var out []media.File
	err := filepath.WalkDir(l.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		body, err := os.ReadFile(p)
		if err != nil {
			// One unreadable record must not make the library unreadable. A
			// listing that fails entirely tells somebody their files are gone
			// when one row is damaged.
			return nil
		}
		var f media.File
		if json.Unmarshal(body, &f) != nil {
			return nil
		}
		out = append(out, f)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UploadedAt != out[j].UploadedAt {
			return out[i].UploadedAt > out[j].UploadedAt
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// Remove deletes a file.
//
// The bytes go. This is not the content store — there is no history here to
// preserve and no ref pointing at it, and keeping every image anybody ever
// uploaded forever is how a media library becomes the reason a disk fills up.
// A page still referring to the id gets a 404, which is visible, rather than
// an image that silently changed.
func (l *Library) Remove(id string) error {
	if err := ValidID(id); err != nil {
		return err
	}
	p := l.path(id)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		return fmt.Errorf("there is no file %s here", id[:12])
	}
	if err := os.Remove(p); err != nil {
		return err
	}
	return os.Remove(p + ".json")
}

// Total reports how much the library holds.
func (l *Library) Total() (files int, bytes int64, err error) {
	all, err := l.List()
	if err != nil {
		return 0, 0, err
	}
	for _, f := range all {
		bytes += f.Size
	}
	return len(all), bytes, nil
}

// timeOf is the moment the record was stamped with, used when re-accepting to
// check the hash. Any instant would do — the id is the hash of the bytes and
// nothing else — but reusing the record's own makes the check deterministic
// rather than dependent on when it happened to run.
func timeOf(f media.File) time.Time { return time.Unix(f.UploadedAt, 0) }

func writeAtomic(path string, body []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
