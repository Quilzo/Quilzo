// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package compliance

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

// The Cyber Resilience Act requires a machine-readable software bill of
// materials covering at least the top-level dependencies of a product with
// digital elements, kept current, and produced to a market surveillance
// authority on request. Reporting obligations under it begin on 11 September
// 2026; the SBOM requirement follows in December 2027, but it is needed before
// then because a vulnerability report has to say what is affected.
//
// This one is derived from the build rather than maintained, which matters more
// here than usual: an SBOM that is out of date is worse than none, because it
// is consulted during an incident and believed.
//
// The unusual part of this particular SBOM is how short it is. This program has
// no third-party dependencies, so there is no transitive tree and nothing that
// can reach end of life without anybody noticing. What is left to reconcile
// against an advisory feed is the Go standard library it was built with,
// named the way the Go vulnerability database names it (pkg:golang/stdlib),
// which is what internal/selfvuln does with this binary's own linked
// functions. That is a deliberate property rather than an accident of scope,
// and it is the single largest reason the CRA obligations here are cheap.

// Component is one thing the product is made of, in CycloneDX 1.6's
// shapes: a licence is an object or an SPDX expression, a supplier is an
// organisation, and anything else is a property.
type Component struct {
	BOMRef  string `json:"bom-ref,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	// PURL is the package URL, which is what a vulnerability feed matches on.
	PURL       string     `json:"purl,omitempty"`
	Licenses   []License  `json:"licenses,omitempty"`
	Hashes     []Hash     `json:"hashes,omitempty"`
	Supplier   *Entity    `json:"supplier,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

// License is one licence by its SPDX id, or an SPDX expression.
type License struct {
	License    *LicenseID `json:"license,omitempty"`
	Expression string     `json:"expression,omitempty"`
}

// LicenseID is an SPDX licence identifier.
type LicenseID struct {
	ID string `json:"id"`
}

// Entity is an organisation.
type Entity struct {
	Name string `json:"name"`
}

// Property is a name and a value CycloneDX has no field for.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// LicenseNames are the component's licences as text, for a screen.
func (c Component) LicenseNames() []string {
	var out []string
	for _, l := range c.Licenses {
		switch {
		case l.Expression != "":
			out = append(out, l.Expression)
		case l.License != nil:
			out = append(out, l.License.ID)
		}
	}
	return out
}

// Licence is the SPDX expression this program is published under.
const Licence = "AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial"

// Hash identifies a component's bytes.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// SBOM is the bill of materials.
type SBOM struct {
	Format       string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber,omitempty"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

// Metadata says what this describes and when it was produced.
type Metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     *Tools    `json:"tools,omitempty"`
	Component Component `json:"component"`
}

// Tools are what produced the document, as 1.6 lists them.
type Tools struct {
	Components []Component `json:"components"`
}

// Dependency says what one component depends on: here, the program on the
// standard library and nothing else.
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// Version is the program's own version, set by main from its build flags;
// empty uses the commit the build records.
var Version string

// Generate builds the SBOM from the running binary.
//
// From debug.ReadBuildInfo rather than from go.mod, because the build info is
// what actually went into this binary. A go.mod on disk describes what would be
// built now, and during an incident the question is what is deployed.
func Generate(now time.Time) (*SBOM, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, fmt.Errorf(
			"this binary carries no build information, so an accurate bill of " +
				"materials cannot be produced from it. A guessed one is worse " +
				"than none: it is consulted during an incident and believed")
	}

	version := "development"
	var revision, modified string
	var props []Property
	for _, st := range info.Settings {
		switch st.Key {
		case "vcs.revision":
			revision = st.Value
		case "vcs.modified":
			modified = st.Value
		case "GOOS", "GOARCH", "CGO_ENABLED", "GOEXPERIMENT", "-tags", "-trimpath":
			// What decides whether an advisory applies to this build: an
			// operating system, an architecture, cgo, an experiment.
			props = append(props, Property{Name: "golang:build:" + strings.TrimPrefix(st.Key, "-"), Value: st.Value})
		}
	}
	switch {
	case Version != "" && Version != "dev":
		version = Version
	case revision != "":
		version = revision
		if modified == "true" {
			// Said out loud. A bill of materials for a binary built from
			// uncommitted changes describes source nobody else can obtain.
			version += "+modified"
		}
	}

	goVersion := strings.TrimPrefix(runtime.Version(), "go")
	if i := strings.IndexAny(goVersion, " -+"); i >= 0 {
		goVersion = goVersion[:i]
	}
	stdlibRef := "pkg:golang/stdlib@" + goVersion
	self := Component{
		BOMRef: "pkg:golang/" + info.Main.Path + "@" + version,
		Type:   "application", Name: info.Main.Path, Version: version,
		PURL:       "pkg:golang/" + info.Main.Path + "@" + version,
		Licenses:   []License{{Expression: Licence}},
		Properties: props,
	}
	if sum, err := selfHash(); err == nil {
		self.Hashes = []Hash{{Alg: "SHA-256", Content: sum}}
	}

	components := []Component{{
		// The standard library is a component, named as the Go
		// vulnerability database names it, so a feed matches it. It is the
		// largest thing in this product by volume and the one an advisory
		// is most likely to concern; an SBOM that omits it describes a
		// program with no runtime.
		BOMRef: stdlibRef, Type: "library", Name: "stdlib", Version: goVersion,
		PURL:     stdlibRef,
		Licenses: []License{{License: &LicenseID{ID: "BSD-3-Clause"}}},
		Supplier: &Entity{Name: "The Go Authors"},
	}}
	deps := []Dependency{{Ref: self.BOMRef, DependsOn: []string{stdlibRef}}}

	for _, dep := range info.Deps {
		if dep == nil {
			continue
		}
		c := Component{
			BOMRef: "pkg:golang/" + dep.Path + "@" + dep.Version,
			Type:   "library", Name: dep.Path, Version: dep.Version,
			PURL: "pkg:golang/" + dep.Path + "@" + dep.Version,
		}
		if dep.Sum != "" {
			// The module's go.sum hash: a hash of the module's file list,
			// not of any one file, so a property rather than a hash.
			c.Properties = []Property{{Name: "golang:go.sum", Value: dep.Sum}}
		}
		components = append(components, c)
		deps[0].DependsOn = append(deps[0].DependsOn, c.BOMRef)
	}
	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	return &SBOM{
		Format: "CycloneDX", SpecVersion: "1.6", Version: 1,
		SerialNumber: serial(self.BOMRef, now),
		Metadata: Metadata{
			Timestamp: now.UTC().Format(time.RFC3339),
			Component: self,
			Tools: &Tools{Components: []Component{{
				Type: "application", Name: "quilzo", Version: version,
			}}},
		},
		Components:   components,
		Dependencies: deps,
	}, nil
}

// serial is a URN UUID for one document, as CycloneDX asks: random, so two
// documents for the same build are two documents.
func serial(string, time.Time) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return "urn:uuid:" + h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// selfHash is the SHA-256 of the running binary, so an SBOM can be tied to the
// artefact it describes rather than to a name and a version string. Read as a
// stream, once per process: the binary is tens of megabytes and a screen that
// shows the bill should not read all of it on every visit.
func selfHash() (string, error) {
	hashOnce.Do(func() {
		path, err := os.Executable()
		if err != nil {
			hashErr = err
			return
		}
		f, err := os.Open(path)
		if err != nil {
			hashErr = err
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			hashErr = err
			return
		}
		hashSum = hex.EncodeToString(h.Sum(nil))
	})
	return hashSum, hashErr
}

var (
	hashOnce sync.Once
	hashSum  string
	hashErr  error
)

// Render writes the SBOM as CycloneDX JSON.
func Render(s *SBOM) ([]byte, error) {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// ThirdParty returns the components that are not this program or its toolchain.
//
// The number an auditor actually wants, and the one that decides how much of
// the Cyber Resilience Act's vulnerability handling is work.
func ThirdParty(s *SBOM) []Component {
	var out []Component
	for _, c := range s.Components {
		if c.Name == "stdlib" || c.Name == s.Metadata.Component.Name {
			continue
		}
		out = append(out, c)
	}
	return out
}
