// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// A store in a container's own layer is a store that goes with the container.
//
// `docker run --rm quilzo init` printed "created .quilzo" and exited 0. The
// store was in the container's writable layer, and --rm deleted the layer as
// the command ended: everything init had made was gone before anybody looked,
// and nothing had said so. Only a volume keeps what a container writes, and
// only the person running the container can mount one.
//
// So init looks at where it is writing. On Linux the mount table says which
// filesystem holds a path: the mount whose point is the longest prefix of
// it. When that is the root and the root is an overlay, which is what Docker
// and Podman give a container, nothing has been mounted over the store and it
// lives as long as the container does. That is said, with the command that
// keeps it. Anything else -- a volume, a bind mount, a machine's own disk, a
// system with no /proc -- is left alone.

// readMountInfo is this process's mount table; a variable so a test can be
// a container without running one.
var readMountInfo = func() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") }

// onContainerLayer reports whether path, absolute, is on the overlay that
// is a container's root rather than on anything mounted over it.
func onContainerLayer(path string, mountinfo []byte) bool {
	best, fstype := "", ""
	for _, line := range strings.Split(string(mountinfo), "\n") {
		// id parent major:minor root mount-point options [optional...] - type source super
		f := strings.Fields(line)
		sep := -1
		for i, x := range f {
			if x == "-" {
				sep = i
				break
			}
		}
		if len(f) < 5 || sep < 0 || sep+1 >= len(f) {
			continue
		}
		point := unescapeMount(f[4])
		if !under(path, point) || len(point) < len(best) {
			continue
		}
		// The same point mounted twice is the later mount, which hides the
		// earlier; the table lists them in order.
		best, fstype = point, f[sep+1]
	}
	return best == "/" && fstype == "overlay"
}

func under(path, point string) bool {
	if point == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == point || strings.HasPrefix(path, point+"/")
}

// unescapeMount undoes the mount table's octal escapes: a space is \040.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// warnContainerLayer says so when root would go with the container.
func warnContainerLayer(root string) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return
	}
	table, err := readMountInfo()
	if err != nil || !onContainerLayer(abs, table) {
		return
	}
	// Standard error, so it is said in --json mode too and a script reading
	// the answer does not take it for part of it. Every command opens a
	// store, and a test can open one before anything has made the writer.
	dst := io.Writer(os.Stderr)
	if w != nil && w.Err != nil {
		dst = w.Err
	}
	fmt.Fprintf(dst, "  %sthe store is in this container's own filesystem, which goes when the container does: "+
		"with --rm, as soon as this command ends.\n  Mount a volume on it to keep it: docker run -v quilzo:%s ...%s\n",
		yellow, abs, reset)
}
