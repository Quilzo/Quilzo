// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

// A desktop cell: the fourth tier of the computer-use plan, for apps no
// browser reaches. One cell is one microVM holding an X server, the
// accessibility tree and the apps; an agent works it through the same
// shape as the browser — a tree read as an outline with references, a
// press named by reference, typing where the last press landed.
//
// What a declaration constrains on a cell is less than on a browser,
// honestly: a desktop app has no host to allow and no request to rule,
// because the cell's network is the microVM's and nothing of the host is
// mounted into it. The capabilities themselves are the constraint — which
// kinds of act are held — with pictures behind their own door, and every
// press that commits to something still asks a person first, from the
// tree's own words about what it is.

// CellCapabilities are the desktop's actions, in the browser's shape.
var CellCapabilities = [...]string{
	"desktop_read", "desktop_press", "desktop_type", "desktop_key", "desktop_look",
}

// IsDesktop says whether an operation is one of the cell's.
func IsDesktop(op string) bool {
	for _, c := range CellCapabilities {
		if c == op {
			return true
		}
	}
	return false
}

// Cell is what a desktop cell's declaration holds.
type Cell struct {
	// Pictures allows desktop_look, which carries a picture of whatever
	// the screen shows — the outline is the default, as the browser's is.
	Pictures bool `json:"pictures,omitempty"`
}

// validateCell holds a cell's declaration to what it can mean.
func (m Manifest) validateCell() error {
	var holds []string
	for _, c := range m.Capabilities {
		if IsDesktop(c) {
			holds = append(holds, c)
		}
	}
	if m.Cell == nil {
		if len(holds) > 0 {
			return ErrNoCellDeclared
		}
		return nil
	}
	for _, c := range holds {
		if c == "desktop_look" && !m.Cell.Pictures {
			return ErrLookWithoutPictures
		}
	}
	return nil
}

// Errors named once, for the messages that name them in the manual.
var (
	ErrNoCellDeclared      = errText(`holds a desktop capability and declares no "cell": pictures is the one thing it says`)
	ErrLookWithoutPictures = errText("holds desktop_look and its cell does not allow pictures")
)

type errText string

func (e errText) Error() string { return string(e) }

// narrowCell keeps a delegate's cell no wider than its parent's.
func narrowCell(parent, by *Cell) *Cell {
	if parent == nil || by == nil {
		return nil
	}
	return &Cell{Pictures: parent.Pictures && by.Pictures}
}

// cellHolds is used by the runner's vocabulary helpers.
func cellHolds(caps []string) bool {
	for _, c := range caps {
		if IsDesktop(c) {
			return true
		}
	}
	return false
}
