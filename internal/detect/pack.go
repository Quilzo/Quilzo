// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package detect

import (
	"embed"
	"sort"
)

// A starter pack: rules that ship, to be copied into a rules directory and
// owned from there.
//
// Copied, not loaded. A rule that runs out of the binary is a rule nobody
// reviewed, cannot be tuned, and changes meaning on an upgrade. Installed,
// each is a file in the organisation's own repository: its ring, its
// suppressions and its record are its own, and an upgrade does not touch
// it.
//
// Every rule in it carries an event it must match and one it must not,
// like any other, and a test here runs them.

//go:embed pack/*.json pack/*.yml
var packFS embed.FS

// PackFile is one file of the pack.
type PackFile struct {
	Name string
	Body []byte
}

// Pack is the shipped rules and correlations, by file name.
func Pack() ([]PackFile, error) {
	entries, err := packFS.ReadDir("pack")
	if err != nil {
		return nil, err
	}
	var out []PackFile
	for _, e := range entries {
		b, err := packFS.ReadFile("pack/" + e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, PackFile{Name: e.Name(), Body: b})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}
