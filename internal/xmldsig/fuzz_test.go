// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package xmldsig

import (
	"bytes"
	"crypto"
	"os"
	"path/filepath"
	"testing"
)

// Whatever the reader accepts, canonicalisation renders, and the rendering
// reads back to itself.
func FuzzRead(f *testing.F) {
	seeds, _ := filepath.Glob(filepath.Join("testdata", "c14n", "*.xml"))
	more, _ := filepath.Glob(filepath.Join("testdata", "saml", "*.xml"))
	for _, s := range append(seeds, more...) {
		b, _ := os.ReadFile(s)
		f.Add(b)
	}
	f.Add([]byte(`<a xmlns="urn:a"><b xmlns=""/></a>`))
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := Read(b)
		if err != nil {
			return
		}
		for _, incl := range [][]string{nil, {"xs"}} {
			once, err := Canonical(d.Root, incl, nil)
			if err != nil || len(once) == 0 {
				t.Fatalf("accepted but not canonicalisable: %v", err)
			}
			d2, err := Read(once)
			if err != nil {
				t.Fatalf("the canonical form does not read: %v\n%s", err, once)
			}
			twice, err := Canonical(d2.Root, incl, nil)
			if err != nil || !bytes.Equal(once, twice) {
				t.Fatalf("not a fixed point:\n%s\n%s", once, twice)
			}
		}
	})
}

// The property the package exists for. Change a signed document however
// you like: if it still verifies, what comes back is byte for byte what the
// JDK signed. No variant can verify and say something else.
func FuzzVerifiedContentNeverChanges(f *testing.F) {
	keys := []crypto.PublicKey{certKey(f, "rsa"), certKey(f, "ec")}
	originals := map[string][]byte{}
	for _, fx := range fixtures(f) {
		if fx.Key != "rsa" && fx.Key != "ec" {
			continue
		}
		b := fixtureBytes(f, fx.Name)
		d, err := Read(b)
		if err != nil {
			f.Fatal(err)
		}
		for _, which := range fx.Signed {
			e := signedElement(f, d, fx, which)
			v, err := VerifyEnveloped(e, keys)
			if err != nil {
				f.Fatal(err)
			}
			id, _ := e.Attr("ID")
			originals[id] = v.Canonical
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := Read(b)
		if err != nil {
			return
		}
		for id, signed := range originals {
			e := d.ByID(id)
			if e == nil {
				continue
			}
			v, err := VerifyEnveloped(e, keys)
			if err != nil {
				continue
			}
			if !bytes.Equal(v.Canonical, signed) {
				t.Fatalf("%s verified with different content:\n%s\nwas\n%s", id, v.Canonical, signed)
			}
		}
	})
}
