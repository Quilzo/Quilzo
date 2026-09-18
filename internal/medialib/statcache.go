// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package medialib

import (
	"os"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/media"
)

// Remembering what a sidecar said, and checking before believing it.
//
// # What this costs to not do
//
// Stat opens a JSON file, reads it and unmarshals it. A profile of one page
// request on this program's own demo put that at 12.3% of the whole request,
// because a page with a listing asks for it once per media reference per row,
// on every request, for files whose bytes cannot change.
//
// # Why the id is not a safe key on its own
//
// Because the id is the hash of the image, not of the record. The bytes at
// that address are immutable — that is the property the whole store rests on —
// but the sidecar beside them holds the alt text, the rights, the focal point
// and the caption tracks, and all four are edited. A cache keyed on the id
// alone would serve yesterday's alt text, and worse, yesterday's rights: a
// licence that has expired is a publication that should have been stopped.
//
// # So it is checked twice, against two different failures
//
// A write through this library drops the entry. That is exact and costs
// nothing, and it covers the admin and the command line, because every
// sidecar in this program is written by Put or removed by Remove.
//
// A read compares the file's size and modification time against what was
// recorded. That is what catches the other process: the public site runs as
// its own program against the same directory, so an operator running
// `quilzo media rights` while a site is being served is not an edge case, it
// is the normal way to do it. One os.Stat is a syscall; what it replaces is
// an open, a read, a close and a JSON unmarshal.
//
// What is left uncovered is a filesystem whose modification times are coarse —
// some are one or two seconds — where an out-of-process edit that happens to
// leave the file exactly the same size, inside the same tick, would not be
// noticed. On Linux the timestamps are nanoseconds and that window does not
// exist; this is written down rather than left for somebody to find.

// statEntry is one remembered sidecar and the fingerprint it was read under.
type statEntry struct {
	file  media.File
	size  int64
	mtime time.Time
}

// maxStats bounds the memo.
//
// Emptied when full rather than evicted one entry at a time. A library larger
// than this is one where the media screen's own listing would keep filling and
// clearing it, which gives no saving and costs nothing beyond what the reads
// cost today; an LRU would help that case and is not worth its complexity
// until somebody has one.
const maxStats = 8192

// remembered returns a sidecar if it was read and the file has not changed.
func (l *Library) remembered(id string, info os.FileInfo) (media.File, bool) {
	l.statMu.Lock()
	defer l.statMu.Unlock()
	e, ok := l.stats[id]
	if !ok {
		return media.File{}, false
	}
	if e.size != info.Size() || !e.mtime.Equal(info.ModTime()) {
		return media.File{}, false
	}
	return e.file, true
}

// remember records a sidecar under the fingerprint it was read at.
func (l *Library) remember(id string, f media.File, info os.FileInfo) {
	l.statMu.Lock()
	defer l.statMu.Unlock()
	if l.stats == nil || len(l.stats) >= maxStats {
		l.stats = make(map[string]statEntry, maxStats)
	}
	l.stats[id] = statEntry{file: f, size: info.Size(), mtime: info.ModTime()}
}

// forget drops what was remembered about one file.
//
// Called by every write, so an edit in this process is never served from the
// memo even for the instant before a stat would have caught it.
func (l *Library) forget(id string) {
	l.statMu.Lock()
	defer l.statMu.Unlock()
	delete(l.stats, id)
}

// statMu and stats are declared here rather than in the Library literal so the
// memo can be read as one piece.
type statMemo struct {
	statMu sync.Mutex
	stats  map[string]statEntry
}
