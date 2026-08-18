// Package atomicfile replaces a file's contents in one step.
//
// # Why this is not a nicety
//
// Two processes share a store: `quilzo serve` is the admin and `quilzo site`
// is the website, and running them separately is the deployment this project
// recommends because it keeps credentials out of the internet-facing half.
//
// Both read the same state files. os.WriteFile truncates and then writes, so
// there is a window in which the file on disk is empty or half a document, and
// a reader landing in that window does not get old data — it gets a parse
// error. That happened: starting the two processes together produced
//
//	the token store could not be read: unexpected end of JSON input
//
// and the site refused to start, because a store with access control
// configured and an unreadable token file is correctly treated as one nobody
// may write to. A restart fixed it, which is the worst kind of bug: it looks
// like a flake, it is a race, and under load it stops being rare.
//
// Rename within a directory is atomic on every filesystem this runs on. A
// reader sees the whole previous file or the whole next one.
//
// # Why fsync, and why on the directory too
//
// Without fsync on the file, rename can be durable while the contents are not,
// and a crash leaves a correctly-named empty file — which is worse than the
// truncation this exists to prevent, because it survives the restart. Without
// fsync on the directory, the rename itself may not be durable.
//
// The cost is a few milliseconds on writes that happen when somebody presses a
// button, which is the right place to spend it.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write replaces path with data, atomically.
//
// The temporary file is created in the same directory as the target, because
// rename is only atomic within a filesystem and /tmp is frequently a different
// one. It is removed on every failure path, so a failed write does not leave
// litter next to the file it failed to replace.
func Write(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("preparing to write %s: %w", path, err)
	}
	tmp := f.Name()
	// From here every failure removes the temporary file. Closing twice is
	// harmless and closing before rename is required on Windows.
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}()

	// The mode is set explicitly rather than left to CreateTemp, which makes
	// files 0600 — right for the token store and wrong for anything a second
	// account has to read.
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("setting permissions on %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("flushing %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replacing %s: %w", path, err)
	}

	// The rename is now visible and not necessarily durable. A crash here
	// leaves the previous file, which is the correct outcome and the reason
	// this is worth doing even though it is invisible when nothing crashes.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
