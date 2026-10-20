// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package atomicfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// A read, a change and a write, as one step.
//
// Most of this program's state is a JSON file that a writer loads, changes
// and writes back whole. Two writers doing that at once lose one change,
// and which one is decided by timing: a publish that read the webhooks
// before an endpoint was removed wrote the endpoint back after it, a
// provisioning request that read the policy before a revocation restored
// the role, a run that read an agent's memory before it was forgotten
// remembered it again. Each was a security decision undone by a write
// that never knew about it.
//
// Update holds the file's lock for the whole step, so the change is made to
// what is stored now and nothing written in between is overwritten. The
// lock is the same kind Lock takes, held by an open descriptor and released
// by the kernel when the holder exits, so it cannot be left behind.

// ErrUnchanged, returned by a change, leaves the file as it was.
var ErrUnchanged = errors.New("nothing to change")

// Update reads the document at path into a fresh value, lets change alter
// it, and writes it back with mode 0600, all under the lock beside it
// (path + ".lock"). An absent file is the zero value. The change sees what
// is stored at that moment, so whatever it decides is decided on the
// current state; when it returns an error nothing is written, and
// ErrUnchanged is not reported as one.
func Update[T any](path string, change func(*T) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	unlock, err := Lock(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	var v T
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &v); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	case !os.IsNotExist(err):
		return err
	}
	if err := change(&v); err != nil {
		if errors.Is(err, ErrUnchanged) {
			return nil
		}
		return err
	}
	out, err := json.MarshalIndent(&v, "", "  ")
	if err != nil {
		return err
	}
	return Write(path, append(out, '\n'), 0o600)
}
