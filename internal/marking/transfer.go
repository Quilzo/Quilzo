package marking

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Moving content between networks, with a record of who moved it.
//
// # Why a manifest and not just a directory
//
// An export already produces a directory somebody can carry across on
// removable media. That is the mechanism; what it is missing is the
// paperwork, and on an isolated network the paperwork is most of the control.
// The procedures these environments run on ask for the same four things every
// time: what was transferred, when, who approved it, and who carried it.
// Without them a directory arriving on the high side is a set of files with
// no provenance, and the receiving authority's only options are to trust it
// or to refuse it.
//
// # What the digest is for
//
// Every file is hashed and the manifest carries the hashes, so the receiving
// side can verify that what arrived is what left. That is a different
// question from whether it was safe to send -- a Cross Domain Solution
// answers that one and this does not pretend to -- but it is the question
// nobody can answer afterwards without a record made at the time.
//
// The manifest names its own algorithm rather than assuming, because a
// manifest read in five years by a tool that did not exist when it was
// written should not have to guess.

// Transfer is the record that travels with an export.
type Transfer struct {
	// Created is when the manifest was made.
	Created string `json:"created"`
	// Banner is the marking the exported content carries as a whole.
	Banner string `json:"banner,omitempty"`
	// Approved and Carried name the people accountable, which is what turns
	// a directory into a transfer.
	Approved string `json:"approved_by"`
	Carried  string `json:"carried_by"`
	// Reason is why this crossed, because the question asked afterwards is
	// always why rather than what.
	Reason string `json:"reason"`
	// From and To name the networks, in the deployment's own terms.
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`

	// Algorithm names how Files were hashed.
	Algorithm string `json:"algorithm"`
	// Files maps a path relative to the export root to its digest.
	Files map[string]string `json:"files"`
	// Bytes is the total, so a receiving station can check the media before
	// reading any of it.
	Bytes int64 `json:"bytes"`
}

// TransferName is what the manifest is called inside an export.
const TransferName = "transfer.json"

// RecordTransfer walks an export and writes the manifest into it.
//
// Every field about people is required. A manifest with a blank approver is
// the thing it exists to prevent: a transfer that happened and that nobody is
// named on.
func RecordTransfer(dir string, t Transfer, now time.Time) (*Transfer, error) {
	for name, value := range map[string]string{
		"--approved-by": t.Approved,
		"--carried-by":  t.Carried,
		"--reason":      t.Reason,
	} {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf(
				"%s is required. A transfer nobody is named on is a directory "+
					"that appeared on the other side, and the receiving "+
					"authority's only options are to trust it or refuse it",
				name)
		}
	}

	t.Created = now.UTC().Format(time.RFC3339)
	t.Algorithm = "sha256"
	t.Files = map[string]string{}
	t.Bytes = 0

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		// The manifest does not hash itself, which it cannot: writing it
		// changes it.
		if rel == TransferName {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(body)
		t.Files[rel] = hex.EncodeToString(sum[:])
		t.Bytes += int64(len(body))
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(t.Files) == 0 {
		return nil, fmt.Errorf("%s holds no files to transfer", dir)
	}

	body, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, TransferName),
		append(body, '\n'), 0o644); err != nil {
		return nil, err
	}
	return &t, nil
}

// VerifyTransfer checks an arriving export against its manifest.
//
// Both directions are checked, and the second is the one that matters. A file
// whose digest differs is corruption or tampering and is obvious. A file that
// is present and not in the manifest is content that joined the transfer
// somewhere between the two networks, and it is the one nobody looks for.
func VerifyTransfer(dir string) (*Transfer, []string, error) {
	body, err := os.ReadFile(filepath.Join(dir, TransferName))
	if err != nil {
		return nil, nil, fmt.Errorf(
			"%s carries no transfer manifest, so what arrived cannot be "+
				"checked against what left: %w", dir, err)
	}
	var t Transfer
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, nil, fmt.Errorf("the transfer manifest does not parse: %w", err)
	}
	if t.Algorithm != "sha256" {
		return nil, nil, fmt.Errorf(
			"the manifest was written with %q and this checks sha256",
			t.Algorithm)
	}

	var problems []string
	seen := map[string]bool{}

	walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == TransferName {
			return nil
		}
		seen[rel] = true

		want, listed := t.Files[rel]
		if !listed {
			problems = append(problems, fmt.Sprintf(
				"%s is present and not in the manifest — it joined the "+
					"transfer after it was recorded", rel))
			return nil
		}
		content, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(content)
		if got := hex.EncodeToString(sum[:]); got != want {
			problems = append(problems, fmt.Sprintf(
				"%s does not match the manifest (%s, expected %s)",
				rel, got[:12], want[:12]))
		}
		return nil
	})
	if walkErr != nil {
		return nil, nil, walkErr
	}

	for rel := range t.Files {
		if !seen[rel] {
			problems = append(problems, fmt.Sprintf(
				"%s is in the manifest and did not arrive", rel))
		}
	}
	sort.Strings(problems)
	return &t, problems, nil
}
