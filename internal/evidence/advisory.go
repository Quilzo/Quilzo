// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/register"
)

// Advisories: CSAF 2.0 documents, the security advisory and the VEX
// profiles alike, and OpenVEX.
//
// What an advisory says is what its publisher says about a vulnerability in
// a product: affected, not affected, fixed, under investigation. Each such
// statement is a fact about the product, vuln.CVE-ID, whose value is the
// publisher's word for it. The product is an asset of the source, by its
// package URL where the advisory gives one, else by its name.
//
// A statement is the publisher's, and graded by how the file came in: a
// vendor's advisory a person downloaded and uploaded is uploaded, and one
// inside a DSSE envelope signed by a key a person pinned is signed.

func init() {
	readers[FormatCSAF] = readCSAF
	readers[FormatOpenVEX] = readOpenVEX
}

// csafStatus is each list of a vulnerability's product status, and the word
// the fact takes for it.
var csafStatus = []struct{ list, word string }{
	{"known_affected", "affected"}, {"first_affected", "affected"}, {"last_affected", "affected"},
	{"known_not_affected", "not_affected"}, {"fixed", "fixed"}, {"first_fixed", "fixed"},
	{"under_investigation", "under_investigation"}, {"recommended", "recommended"},
}

func readCSAF(rd *reader) error {
	var doc any
	if err := decodeJSON(rd.in.Body, &doc); err != nil {
		return err
	}
	d := obj(doc)
	if v := str(at(d, "document", "csaf_version")); v != "2.0" {
		return fmt.Errorf("%w: it is CSAF %q, and this reads CSAF 2.0", ErrUnreadable, label(v))
	}
	products := map[string]map[string]any{}
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if depth > MaxDepth {
			return
		}
		for _, b := range arr(v) {
			bo := obj(b)
			if p := obj(bo["product"]); p != nil {
				products[str(p["product_id"])] = p
			}
			walk(bo["branches"], depth+1)
		}
	}
	tree := obj(at(d, "product_tree"))
	walk(tree["branches"], 0)
	for _, p := range arr(tree["full_product_names"]) {
		po := obj(p)
		products[str(po["product_id"])] = po
	}
	for _, r := range arr(tree["relationships"]) {
		if p := obj(obj(r)["full_product_name"]); p != nil {
			products[str(p["product_id"])] = p
		}
	}
	assets := map[string]register.ID{}
	product := func(pid, place string) (register.ID, error) {
		if id, ok := assets[pid]; ok {
			return id, nil
		}
		p := products[pid]
		if p == nil {
			rd.note("a statement at %s names the product %s, which the advisory's product tree does not have", place, label(pid))
			return "", nil
		}
		name := firstText(str(p["name"]), pid)
		ref := firstText(str(at(p, "product_identification_helper", "purl")), str(at(p, "product_identification_helper", "cpe")), name)
		id, err := rd.asset("application", ref, name, place)
		if err == nil {
			assets[pid] = id
		}
		return id, err
	}
	read := 0
	for i, v := range arr(d["vulnerabilities"]) {
		vo := obj(v)
		place := fmt.Sprintf("/vulnerabilities/%d", i)
		cve := str(vo["cve"])
		if cve == "" {
			if ids := arr(vo["ids"]); len(ids) > 0 {
				cve = str(obj(ids[0])["text"])
			}
		}
		if cve == "" {
			rd.note("the vulnerability at %s names no CVE or other identifier, and was not read", place)
			continue
		}
		for _, s := range csafStatus {
			for j, pid := range arr(at(vo, "product_status", s.list)) {
				id, err := product(str(pid), fmt.Sprintf("%s/product_status/%s/%d", place, s.list, j))
				if err != nil {
					return err
				}
				if id == "" {
					continue
				}
				if err := rd.observe(id, factName("vuln", cve), register.TextValue(s.word),
					fmt.Sprintf("%s/product_status/%s/%d", place, s.list, j), ""); err != nil {
					return err
				}
				read++
			}
		}
	}
	if read == 0 {
		return fmt.Errorf("%w: the advisory says nothing about any product's status", ErrUnreadable)
	}
	return nil
}

func readOpenVEX(rd *reader) error {
	var doc any
	if err := decodeJSON(rd.in.Body, &doc); err != nil {
		return err
	}
	return rd.openvex(obj(doc), "")
}

// openvex reads an OpenVEX document held at a place in a file.
func (rd *reader) openvex(d map[string]any, base string) error {
	if ctx := str(d["@context"]); !strings.HasPrefix(ctx, "https://openvex.dev/ns") {
		return fmt.Errorf("%w: it is not an OpenVEX document (its @context is %q)", ErrUnreadable, label(ctx))
	}
	read := 0
	for i, s := range arr(d["statements"]) {
		so := obj(s)
		place := fmt.Sprintf("%s/statements/%d", base, i)
		vuln := str(so["vulnerability"])
		if vuln == "" {
			vuln = firstText(str(at(so, "vulnerability", "name")), str(at(so, "vulnerability", "@id")))
		}
		status := str(so["status"])
		switch status {
		case "not_affected", "affected", "fixed", "under_investigation":
		default:
			return fmt.Errorf("%w: the statement at %s has the status %q, which OpenVEX does not have", ErrUnreadable, place, label(status))
		}
		if vuln == "" {
			return fmt.Errorf("%w: the statement at %s names no vulnerability", ErrUnreadable, place)
		}
		for j, p := range arr(so["products"]) {
			ref := str(p)
			if ref == "" {
				ref = str(obj(p)["@id"])
			}
			if ref == "" {
				continue
			}
			pp := fmt.Sprintf("%s/products/%d", place, j)
			id, err := rd.asset("application", ref, ref, pp)
			if err != nil {
				return err
			}
			if err := rd.observe(id, factName("vuln", vuln), register.TextValue(status), pp, ""); err != nil {
				return err
			}
			read++
		}
	}
	if read == 0 {
		return fmt.Errorf("%w: the document makes no statement about any product", ErrUnreadable)
	}
	return nil
}
