// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/out"
)

// A container's mount table: its root an overlay, as Docker makes one.
const containerRoot = "652 553 0:62 / / rw,relatime master:301 - overlay overlay rw,lowerdir=/var/lib/docker/l/A,upperdir=/var/lib/docker/d/diff,workdir=/var/lib/docker/d/work\n" +
	"653 652 0:65 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n"

// Finding STACK-F1. `docker run --rm quilzo init` said "created .quilzo"
// and exited 0 into the container's own layer, which --rm then deleted: a
// store made and lost without a word. Where that layer is the store's
// filesystem, init says so.
func TestInitSaysWhenTheStoreWouldGoWithTheContainer(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "store")
	volume := "700 652 8:1 /volumes/quilzo/_data " + escapeMount(dir) + " rw,relatime - ext4 /dev/sda1 rw\n"
	for _, c := range []struct {
		name, table string
		warn        bool
	}{
		{"the container's own layer", containerRoot, true},
		{"a volume mounted on it", containerRoot + volume, false},
		{"a volume beside it, at a path that only starts the same",
			containerRoot + "700 652 8:1 /v " + escapeMount(dir+"-other") + " rw - ext4 /dev/sda1 rw\n", true},
		{"a machine's own disk", "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n", false},
		{"no mount table at all", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			saved, savedW := readMountInfo, w
			t.Cleanup(func() { readMountInfo, w = saved, savedW })
			table := c.table
			readMountInfo = func() ([]byte, error) { return []byte(table), nil }
			var stdout, stderr bytes.Buffer
			w = &out.Writer{Out: &stdout, Err: &stderr}
			if err := cmdInit(root); err != nil {
				t.Fatal(err)
			}
			said := stderr.String()
			if c.warn != strings.Contains(said, "goes when the container does") {
				t.Errorf("warned %v, want %v:\n%s", !c.warn, c.warn, said)
			}
			if c.warn && !strings.Contains(said, "-v quilzo:"+root) {
				t.Errorf("the warning does not say how to keep it:\n%s", said)
			}
		})
	}
}

// escapeMount writes a path as the mount table does: a space, a tab, a
// newline and a backslash as octal escapes.
func escapeMount(p string) string {
	return strings.NewReplacer(" ", `\040`, "\t", `\011`, "\n", `\012`, `\`, `\134`).Replace(p)
}

func TestTheMountTableIsReadWithItsEscapes(t *testing.T) {
	table := containerRoot + "700 652 8:1 / /srv/my\\040store rw - ext4 /dev/sda1 rw\n"
	if onContainerLayer("/srv/my store", []byte(table)) {
		t.Error("a volume mounted at a path with a space in it was not seen")
	}
	if !onContainerLayer("/srv/other", []byte(table)) {
		t.Error("a path beside that volume was taken to be on it")
	}
}

// Also finding STACK-F1. In a container the store's directory is there
// before init runs: the image makes /srv/store so a volume mounted on it is
// seeded with the right owner, and a mount point is a directory. init took
// that for a store already there: it said "reusing /srv/store" of the store
// it was making, and gave the new store an upgraded installation's grace --
// two weeks in which a token alone reached the admin -- instead of two
// factors from its first day.
func TestInitInAnEmptyDirectoryMakesANewStore(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	saved := w
	t.Cleanup(func() { w = saved })
	root := filepath.Join(t.TempDir(), "store")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	w = &out.Writer{Out: &stdout, Err: &bytes.Buffer{}}
	before := time.Now()
	if err := runInit(root, []string{"--admin", "you"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "created "+root) {
		t.Errorf("init in an empty directory did not say it made a store:\n%s", stdout.String())
	}
	from, set := mfaFromIfSet(root)
	if !set || from.After(time.Now()) || from.Before(before.Add(-time.Second)) {
		t.Errorf("two factors are compulsory from %v (set %v); a new store has them from its first day", from, set)
	}
	// And a store that is there is reused, and keeps what it had.
	stdout.Reset()
	if err := runInit(root, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "reusing "+root) {
		t.Errorf("init on a store did not say it reused it:\n%s", stdout.String())
	}
}
