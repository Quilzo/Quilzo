// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/backup"
	"github.com/quilzo/quilzo/internal/out"
)

// A command that has left Quilzo is answered with why, as a usage error,
// however it arrives: on its own, with a subcommand, after help, asking for
// its help, or with --json. "There is no such command" and a guess at a
// typo would tell somebody who typed it correctly that they had not.
func TestAMovedOutCommandIsSaidToHaveMoved(t *testing.T) {
	root, token := accessStore(t)
	for cmd := range movedOut {
		for _, line := range [][]string{
			{cmd},
			{cmd, "list"},
			{"help", cmd},
			{"--help", cmd},
			{"-h", cmd, "list"},
			{cmd, "--help"},
			{cmd, "help"},
			{"--json", cmd, "demo"},
		} {
			_, e, code := cliRun(t, root, token, line...)
			said := strings.Join(line, " ")
			if code != out.ExitUsage {
				t.Errorf("`quilzo %s` exited %d, and a command that has left is a usage error (%d)",
					said, code, out.ExitUsage)
			}
			if !strings.Contains(e, "moved out of Quilzo into a separate product") {
				t.Errorf("`quilzo %s` did not say the command has moved out: %s", said, firstLines(e, 3))
			}
			if strings.Contains(e, "there is no") || strings.Contains(e, "Did you mean") {
				t.Errorf("`quilzo %s` was answered as a typo: %s", said, firstLines(e, 3))
			}
		}
	}
}

// The authorisation check, which every command passes through, gives the
// same answer by itself. main answers a name that has left before the check
// is reached, so nothing run from the command line gets this far, and the
// check is asked directly: its answer must not depend on main having been
// there first, or the day the two are reordered a name that has left is
// "there is no such command" again.
func TestTheAuthorisationCheckSaysAMovedOutCommandMoved(t *testing.T) {
	for cmd := range movedOut {
		for _, args := range [][]string{nil, {"list"}, {"demo", "--help"}} {
			err := authoriseCommand(t.TempDir(), cmd, args)
			if err == nil {
				t.Fatalf("`quilzo %s %s` is authorised, and the command has left", cmd, strings.Join(args, " "))
			}
			var misused errMisused
			if !errors.As(err, &misused) {
				t.Errorf("`quilzo %s` is refused as %T, and a command that has left is a usage error", cmd, err)
			}
			if !strings.Contains(err.Error(), "moved out of Quilzo into a separate product") ||
				strings.Contains(err.Error(), "Did you mean") {
				t.Errorf("`quilzo %s` is answered %q", cmd, err)
			}
		}
	}
}

// A name that has left is not a command any more anywhere the command layer
// looks one up, so nothing grants, documents or dispatches it by accident.
func TestAMovedOutCommandIsInNoTable(t *testing.T) {
	for cmd := range movedOut {
		for key := range commandNeeds {
			if first, _, _ := strings.Cut(key, " "); first == cmd {
				t.Errorf("the privilege table still has %q", key)
			}
		}
		if storelessWhole[cmd] {
			t.Errorf("%q is still listed as running without a store", cmd)
		}
		if helpFor(cmd, nil) != "" {
			t.Errorf("the help still describes `quilzo %s`", cmd)
		}
		for key := range answersOwnHelp {
			if first, _, _ := strings.Cut(key, " "); first == cmd {
				t.Errorf("the help list still has %q", key)
			}
		}
	}
}

// A store that rooms wrote into still opens, checks, backs up and restores,
// and what the rooms kept is carried through untouched.
//
// testdata/oldrooms is a store made by the release before rooms left: init,
// a room opened, three messages said (one a reply), a reaction, an edit and
// a removal, and nothing else. Its files are as that binary wrote them, the
// audit log included, less the lock files and the audit key, which a store
// makes again when it needs one. The two directories init makes empty are
// made here, because git does not carry an empty directory.
func TestAStoreTheRoomsWroteStillOpensChecksBacksUpAndRestores(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	fixture := filepath.Join("testdata", "oldrooms")
	kept := map[string][]byte{}
	err := filepath.WalkDir(fixture, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(fixture, path)
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		to := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
			return err
		}
		if strings.HasPrefix(filepath.ToSlash(rel), "rooms/") {
			kept[filepath.ToSlash(rel)] = body
		}
		return os.WriteFile(to, body, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) < 4 {
		t.Fatalf("the fixture holds %d files under rooms/; it is not the store it says it is", len(kept))
	}
	for _, dir := range []string{"objects", "refs"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	key, _ := backup.NewKey()
	t.Setenv(backupKeyEnv, backup.EncodeKey(key))
	file := filepath.Join(t.TempDir(), "store.qzb")
	into := filepath.Join(t.TempDir(), "restored")
	for _, line := range [][]string{
		{"verify"},
		{"auditlog", "verify"},
		{"backup", "create", file},
		{"backup", "verify", file},
		{"backup", "restore", file, "--into", into},
	} {
		o, e, code := cliRun(t, root, "", line...)
		if code != 0 {
			t.Fatalf("`quilzo %s` on a store with rooms in it exited %d: %s",
				strings.Join(line, " "), code, firstLines(o+e, 6))
		}
	}

	// Nothing the rooms kept was changed or removed, here or in what was
	// restored, and the restored store checks as the original did.
	for rel, body := range kept {
		for _, in := range []string{root, filepath.Join(into, "store")} {
			got, err := os.ReadFile(filepath.Join(in, filepath.FromSlash(rel)))
			if err != nil {
				t.Errorf("%s is gone from %s: %v", rel, in, err)
				continue
			}
			if !bytes.Equal(got, body) {
				t.Errorf("%s in %s is not what the rooms wrote", rel, in)
			}
		}
	}
	for _, line := range [][]string{{"verify"}, {"auditlog", "verify"}} {
		o, e, code := cliRun(t, filepath.Join(into, "store"), "", line...)
		if code != 0 {
			t.Errorf("`quilzo %s` on the restored store exited %d: %s",
				strings.Join(line, " "), code, firstLines(o+e, 6))
		}
	}
}
