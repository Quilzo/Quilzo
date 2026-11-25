// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/register"
)

// Software bills of materials: CycloneDX 1.2 to 1.6 and SPDX 2.2 and 2.3,
// in JSON.
//
// The software a bill describes is an asset, and so is each component in
// it, by its package URL where it has one: a package URL is the identifier
// every scanner and advisory names a package by, so it is what later links
// a component to a vulnerability. Each component carries three facts: its
// version, its licence as the bill states it, and which software it is part
// of. The software itself carries how many components the bill lists.
//
// A CycloneDX bill may carry VEX statements, what its maker says about a
// vulnerability in a component: each becomes a fact about the component,
// vuln.CVE-ID, whose value is the statement's state (not_affected,
// exploitable and the rest) as the maker gave it.
//
// SPDX 3.0 is JSON-LD of another shape, and is refused rather than misread.

func init() {
	readers[FormatCycloneDX] = readCycloneDX
	readers[FormatSPDX] = readSPDX
}

// maxComponents bounds how many components one bill may list.
const maxComponents = 100_000

func readCycloneDX(rd *reader) error {
	var doc any
	if err := decodeJSON(rd.in.Body, &doc); err != nil {
		return err
	}
	return rd.cyclonedx(obj(doc), "")
}

// cyclonedx reads a bill held at a place in a file: the file itself, or a
// signed statement's predicate.
func (rd *reader) cyclonedx(bom map[string]any, base string) error {
	if bom == nil || str(bom["bomFormat"]) != "CycloneDX" {
		return fmt.Errorf("%w: it is not a CycloneDX bill of materials (no bomFormat CycloneDX)", ErrUnreadable)
	}
	spec := str(bom["specVersion"])
	switch spec {
	case "1.2", "1.3", "1.4", "1.5", "1.6":
	default:
		return fmt.Errorf("%w: it is CycloneDX %q, and this reads 1.2 to 1.6", ErrUnreadable, label(spec))
	}
	var subject register.ID
	if main := obj(at(bom, "metadata", "component")); main != nil {
		id, err := rd.component(main, base+"/metadata/component", "")
		if err != nil {
			return err
		}
		subject = id
	}
	byRef := map[string]register.ID{}
	count := 0
	var walk func(list []any, place string, depth int) error
	walk = func(list []any, place string, depth int) error {
		for i, c := range list {
			count++
			if count > maxComponents {
				return fmt.Errorf("%w: it lists more than %d components", ErrUnreadable, maxComponents)
			}
			comp := obj(c)
			if comp == nil {
				continue
			}
			here := place + "/" + strconv.Itoa(i)
			id, err := rd.component(comp, here, subject)
			if err != nil {
				return err
			}
			if ref := str(comp["bom-ref"]); ref != "" {
				byRef[ref] = id
			}
			if nested := arr(comp["components"]); nested != nil {
				if err := walk(nested, here+"/components", depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(arr(bom["components"]), base+"/components", 0); err != nil {
		return err
	}
	if subject != "" {
		if err := rd.observe(subject, "sbom.components", register.NumberValue(float64(count)), base+"/components", ""); err != nil {
			return err
		}
	}
	for i, v := range arr(bom["vulnerabilities"]) {
		vuln := obj(v)
		place := fmt.Sprintf("%s/vulnerabilities/%d", base, i)
		id := str(vuln["id"])
		if id == "" {
			continue
		}
		state := firstText(str(at(vuln, "analysis", "state")), "unknown")
		for j, a := range arr(vuln["affects"]) {
			ref := str(obj(a)["ref"])
			comp, ok := byRef[ref]
			if !ok {
				rd.note("a VEX statement at %s/affects/%d names a component the bill does not list", place, j)
				continue
			}
			if err := rd.observe(comp, factName("vuln", id), register.TextValue(strings.ToLower(label(state))), place, ""); err != nil {
				return err
			}
		}
	}
	return nil
}

// component is one component of a bill as an asset, with its facts.
func (rd *reader) component(c map[string]any, place string, partOf register.ID) (register.ID, error) {
	name, version, purl := str(c["name"]), str(c["version"]), str(c["purl"])
	ref := firstText(purl, nameAt(name, version), str(c["bom-ref"]))
	if ref == "" {
		return "", fmt.Errorf("%w: the component at %s has no name", ErrUnreadable, place)
	}
	typ := componentType(str(c["type"]))
	id, err := rd.asset(typ, ref, nameAt(name, version), place)
	if err != nil {
		return "", err
	}
	if version != "" {
		if err := rd.observe(id, "component.version", register.TextValue(label(version)), place+"/version", ""); err != nil {
			return "", err
		}
	}
	if lic := cdxLicence(c); lic != "" {
		if err := rd.observe(id, "component.licence", register.TextValue(lic), place+"/licenses", ""); err != nil {
			return "", err
		}
	}
	if partOf != "" && partOf != id {
		if err := rd.observe(id, "component.part-of", register.TextValue(string(partOf)), place, ""); err != nil {
			return "", err
		}
	}
	return id, nil
}

func nameAt(name, version string) string {
	if name == "" {
		return ""
	}
	if version == "" {
		return name
	}
	return name + "@" + version
}

// componentType is the asset type a component of a bill is: hardware a
// device, data a data store, and software, which is nearly all of them, an
// application.
func componentType(t string) register.AssetType {
	switch t {
	case "device", "firmware", "device-driver":
		return "device"
	case "data":
		return "data-store"
	}
	return "application"
}

// cdxLicence is a component's licence as its bill states it: an SPDX
// expression, or the identifiers or names of its licences joined.
func cdxLicence(c map[string]any) string {
	var parts []string
	for _, l := range arr(c["licenses"]) {
		lo := obj(l)
		if e := str(lo["expression"]); e != "" {
			parts = append(parts, e)
			continue
		}
		if s := firstText(str(at(lo, "license", "id")), str(at(lo, "license", "name"))); s != "" {
			parts = append(parts, s)
		}
	}
	return label(strings.Join(parts, " AND "))
}

func readSPDX(rd *reader) error {
	var doc any
	if err := decodeJSON(rd.in.Body, &doc); err != nil {
		return err
	}
	return rd.spdx(obj(doc), "")
}

// spdx reads an SPDX 2.2 or 2.3 document held at a place in a file.
func (rd *reader) spdx(d map[string]any, base string) error {
	if d == nil {
		return fmt.Errorf("%w: it is not an SPDX document", ErrUnreadable)
	}
	if _, ld := d["@context"]; ld {
		return fmt.Errorf("%w: it is SPDX 3, JSON-LD, which this does not read; SPDX 2.2 and 2.3 are read", ErrUnreadable)
	}
	switch v := str(d["spdxVersion"]); v {
	case "SPDX-2.2", "SPDX-2.3":
	default:
		return fmt.Errorf("%w: it is %q, and this reads SPDX-2.2 and SPDX-2.3", ErrUnreadable, label(v))
	}
	described := map[string]bool{}
	for _, id := range arr(d["documentDescribes"]) {
		described[str(id)] = true
	}
	for _, r := range arr(d["relationships"]) {
		ro := obj(r)
		if str(ro["relationshipType"]) == "DESCRIBES" && str(ro["spdxElementId"]) == "SPDXRef-DOCUMENT" {
			described[str(ro["relatedSpdxElement"])] = true
		}
	}
	packages := arr(d["packages"])
	if len(packages) > maxComponents {
		return fmt.Errorf("%w: it lists more than %d packages", ErrUnreadable, maxComponents)
	}
	// The software the document describes first, so every other package
	// can say it is part of it.
	var subject register.ID
	for i, p := range packages {
		po := obj(p)
		if described[str(po["SPDXID"])] {
			id, err := rd.spdxPackage(po, fmt.Sprintf("%s/packages/%d", base, i), "")
			if err != nil {
				return err
			}
			if subject == "" {
				subject = id
			}
		}
	}
	count := 0
	for i, p := range packages {
		po := obj(p)
		if po == nil || described[str(po["SPDXID"])] {
			continue
		}
		count++
		if _, err := rd.spdxPackage(po, fmt.Sprintf("%s/packages/%d", base, i), subject); err != nil {
			return err
		}
	}
	if subject != "" {
		return rd.observe(subject, "sbom.components", register.NumberValue(float64(count)), base+"/packages", "")
	}
	return nil
}

func (rd *reader) spdxPackage(p map[string]any, place string, partOf register.ID) (register.ID, error) {
	purl := ""
	for _, r := range arr(p["externalRefs"]) {
		ro := obj(r)
		if str(ro["referenceType"]) == "purl" {
			purl = str(ro["referenceLocator"])
		}
	}
	name, version := str(p["name"]), str(p["versionInfo"])
	// What was concluded about the licence, else what the package declares;
	// SPDX's "no assertion" and "none" are neither.
	lic := ""
	for _, l := range []string{str(p["licenseConcluded"]), str(p["licenseDeclared"])} {
		if l = strings.TrimSpace(l); l != "" && l != "NOASSERTION" && l != "NONE" {
			lic = l
			break
		}
	}
	c := map[string]any{"name": name, "version": version, "purl": purl, "bom-ref": str(p["SPDXID"])}
	if lic != "" {
		c["licenses"] = []any{map[string]any{"expression": lic}}
	}
	return rd.component(c, place, partOf)
}
