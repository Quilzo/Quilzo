// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/c2pa"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
)

// Checking a manifest, which nothing could do.
//
// # The gap
//
// internal/c2pa is about fifteen hundred lines of JUMBF, deterministic CBOR
// and COSE, and it verifies four things where most implementations check two.
// In production it was write-only: c2pa.Verify was called from tests and from
// nowhere else. The program signed and never looked.
//
// That is the shape of the whole standard's problem in 2026 — an enormous
// amount of signing infrastructure and almost no verification — and it is a
// bad look for the one product whose argument is that a claim you cannot check
// is not a claim. So: a command.
//
// # Two different questions
//
// A file this site signs and a file that arrived already signed are not the
// same question, and answering them in one word would be the mistake.
//
//	ours      the manifest this site would serve, verified against this site's
//	          own key. Proves the pipeline produces something that checks out,
//	          end to end, rather than something that merely parses.
//
//	theirs    a manifest that came with the upload. It is signed by a key
//	          nobody here holds and there is no trust list to look one up in,
//	          so the signature is not checked and the report says so. What is
//	          checked is everything that needs no key: that the manifest
//	          describes these exact bytes and sits exactly where it says.
//
// The second is reported as what it is rather than rounded up to "verified" or
// down to "unknown". A manifest that binds to the file and is signed by a
// stranger is a real piece of evidence about the file's history, and pretending
// otherwise in either direction would be the easy lie.

// verdict is one asset's answer.
type verdict struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	State string `json:"state"`
	// Detail is the sentence a person reads.
	Detail string `json:"detail"`
	// Claims is what the manifest says, when there is one.
	Claims string `json:"digital_source_type,omitempty"`
	Signer string `json:"signer,omitempty"`
}

const (
	verdictOK          = "ok"      // this site's manifest, verified
	verdictCarried     = "carried" // somebody else's, intact, signer unknown
	verdictBroken      = "broken"  // a manifest that does not check out
	verdictNoContainer = "skipped" // nothing this program can sign or read
)

func cmdMediaVerify(root string, args []string) error {
	lib, err := openMedia(root)
	if err != nil {
		return err
	}
	files, err := lib.List()
	if err != nil {
		return err
	}
	chain, key, err := provenanceSigner(root, siteName(root), time.Now())
	if err != nil {
		return err
	}
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("the provenance key is not an Ed25519 key")
	}

	wanted := map[string]bool{}
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			wanted[a] = true
		}
	}

	sort.Slice(files, func(i, j int) bool { return files[i].ID < files[j].ID })
	out := make([]verdict, 0, len(files))
	for _, f := range files {
		if len(wanted) > 0 && !wanted[f.ID] {
			continue
		}
		// A rendition is a copy of a picture already in this list and carries
		// the same account of itself. Reporting each one would bury the
		// twelve answers somebody wants under forty-eight they do not.
		if f.RenditionOf != "" {
			continue
		}
		out = append(out, verifyOne(lib, f, chain, key, pub))
	}

	if len(wanted) > 0 && len(out) == 0 {
		return fmt.Errorf("no such file in the library")
	}
	if w.JSON(out) {
		return nil
	}
	return reportVerdicts(root, out)
}

// verifyOne answers for a single asset.
func verifyOne(lib *medialib.Library, f media.File, chain [][]byte,
	key ed25519.PrivateKey, pub ed25519.PublicKey) verdict {

	v := verdict{ID: f.ID, Name: f.Name}
	_, body, err := lib.Get(f.ID)
	if err != nil {
		v.State, v.Detail = verdictBroken, "the file could not be read: "+err.Error()
		return v
	}

	// Somebody else's manifest, first: this is the file as it arrived, and if
	// it carries one then that is the account of it that matters.
	if st, rerr := c2pa.Read(body); rerr == nil {
		v.State, v.Claims = verdictCarried, st.DigitalSourceType
		v.Signer = st.SoftwareAgent
		v.Detail = "arrived with its own manifest, intact and bound to these " +
			"bytes; who signed it is not checked"
		if st.GeneratedByModel() {
			v.Detail = "arrived saying a trained model made it, intact and " +
				"bound to these bytes; who signed it is not checked"
		}
		return v
	} else if hasCarriedManifest(f, body) {
		v.State = verdictBroken
		v.Detail = "carries a manifest that does not check out: " + rerr.Error()
		return v
	}

	if !embeddable(f) {
		v.State = verdictNoContainer
		v.Detail = "not a container this signs"
		return v
	}

	// Ours: sign it the way the server would and check the result. Not a
	// rehearsal — it is the same claim, built by the same function, so a
	// pipeline that produces something unverifiable fails here rather than in
	// somebody's C2PA tool.
	signed, serr := c2pa.Embed(body, claimForFile(f, signingAgent, time.Now), chain, key)
	if serr != nil {
		v.State = verdictBroken
		v.Detail = "this site could not sign it: " + serr.Error()
		return v
	}
	st, verr := c2pa.Verify(signed, pub)
	if verr != nil {
		v.State = verdictBroken
		v.Detail = "this site signed it and the result does not verify: " +
			verr.Error()
		return v
	}
	v.State, v.Claims = verdictOK, st.DigitalSourceType
	v.Signer = st.SoftwareAgent
	v.Detail = "signed by this site, and the manifest verifies"
	return v
}

// hasCarriedManifest reports whether the stored bytes look like they hold one.
//
// Asked only to tell two silences apart: a file with no manifest, and a file
// whose manifest could not be read. Structural, because a file that does not
// parse cannot be asked what it is.
func hasCarriedManifest(f media.File, body []byte) bool {
	return media.CarriesProvenance(strings.ToLower(f.Format), body)
}

func reportVerdicts(root string, out []verdict) error {
	if len(out) == 0 {
		w.Human("  %sthere is nothing in the library%s\n", dim, reset)
		return nil
	}
	// One line each, and the explanation once at the end.
	//
	// The first version printed the whole account of what was checked beside
	// every file, which on a shop's twelve photographs was the same three
	// lines twelve times — a list where every entry is a paragraph is a list
	// nobody reads to the end of, and the one broken file in it is the one
	// they were looking for.
	counts := map[string]int{}
	for _, v := range out {
		counts[v.State]++
		colour := green
		switch v.State {
		case verdictBroken:
			colour = red
		case verdictCarried:
			colour = yellow
		case verdictNoContainer:
			colour = dim
		}
		name := v.Name
		if name == "" {
			name = shortID(v.ID)
		}
		says := v.Claims
		if says == "" {
			says = "no origin declared"
		}
		w.Human("  %s%-8s%s %-28s %s%s%s\n", colour, v.State, reset, name,
			dim, says, reset)
		// Only where it is not the ordinary answer. "Verified" needs no
		// sentence beside it; "this does not check out" does.
		if v.State != verdictOK {
			w.Human("           %s%s%s\n", dim, v.Detail, reset)
		}
	}

	w.Human("\n  %s%d of %d verified against this site's key%s\n",
		dim, counts[verdictOK], len(out), reset)
	w.Human("  %sthat is the signature, every assertion's own hash, the "+
		"binding to these\n  bytes, and that the excluded range is where the "+
		"manifest sits%s\n", dim, reset)
	if counts[verdictCarried] > 0 {
		w.Human("\n  %s%d arrived with a manifest of their own. Those are "+
			"bound to their\n  bytes and signed by keys this site does not "+
			"hold; there is no trust\n  list here to look one up in, so who "+
			"signed them is not checked%s\n",
			yellow, counts[verdictCarried], reset)
	}
	if counts[verdictNoContainer] > 0 {
		w.Human("\n  %s%d are formats this program neither signs nor reads — "+
			"PNG and JPEG\n  are the two containers implemented%s\n",
			dim, counts[verdictNoContainer], reset)
	}

	record(root, resolveCaller(root, "").auditRecord("media.verify", "/",
		audit.Success, map[string]string{
			"checked": fmt.Sprint(len(out)),
			"broken":  fmt.Sprint(counts[verdictBroken]),
		}))

	if counts[verdictBroken] > 0 {
		return fmt.Errorf("%d file(s) carry a manifest that does not check out",
			counts[verdictBroken])
	}
	return nil
}
