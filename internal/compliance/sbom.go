package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
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
// no third-party dependencies, so there is no transitive tree, nothing that can
// reach end of life without anybody noticing, and nothing to reconcile against
// an advisory feed. That is a deliberate property rather than an accident of
// scope, and it is the single largest reason the CRA obligations here are
// cheap.

// Component is one thing the product is made of.
type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	// PURL is the package URL, which is what a vulnerability feed matches on.
	PURL     string   `json:"purl,omitempty"`
	Licenses []string `json:"licenses,omitempty"`
	Hashes   []Hash   `json:"hashes,omitempty"`
	Direct   bool     `json:"direct"`
	Supplier string   `json:"supplier,omitempty"`
}

// Hash identifies a component's bytes.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// SBOM is the bill of materials.
type SBOM struct {
	Format      string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    Metadata    `json:"metadata"`
	Components  []Component `json:"components"`
}

// Metadata says what this describes and when it was produced.
type Metadata struct {
	Timestamp string      `json:"timestamp"`
	Tools     []Component `json:"tools,omitempty"`
	Component Component   `json:"component"`
}

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
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	if revision != "" {
		version = revision
		if modified == "true" {
			// Said out loud. A bill of materials for a binary built from
			// uncommitted changes describes source nobody else can obtain.
			version += "+modified"
		}
	}

	self := Component{
		Type: "application", Name: info.Main.Path, Version: version,
		PURL:     "pkg:golang/" + info.Main.Path + "@" + version,
		Licenses: []string{"proprietary"}, Direct: true,
	}
	if sum, err := selfHash(); err == nil {
		self.Hashes = []Hash{{Alg: "SHA-256", Content: sum}}
	}

	components := []Component{{
		// The toolchain is a component. It is the largest thing in this
		// product by volume and the one an advisory is most likely to concern,
		// and an SBOM that omits it describes a program with no runtime.
		Type: "framework", Name: "go", Version: runtime.Version(),
		PURL:     "pkg:generic/go@" + strings.TrimPrefix(runtime.Version(), "go"),
		Licenses: []string{"BSD-3-Clause"}, Direct: true,
		Supplier: "Google",
	}}

	for _, dep := range info.Deps {
		if dep == nil {
			continue
		}
		c := Component{
			Type: "library", Name: dep.Path, Version: dep.Version,
			PURL:   "pkg:golang/" + dep.Path + "@" + dep.Version,
			Direct: true,
		}
		if dep.Sum != "" {
			c.Hashes = []Hash{{Alg: "SHA-256", Content: dep.Sum}}
		}
		components = append(components, c)
	}
	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	return &SBOM{
		Format: "CycloneDX", SpecVersion: "1.6", Version: 1,
		Metadata: Metadata{
			Timestamp: now.UTC().Format(time.RFC3339),
			Component: self,
			Tools: []Component{{
				Type: "application", Name: "quilzo", Version: version,
			}},
		},
		Components: components,
	}, nil
}

// selfHash is the SHA-256 of the running binary, so an SBOM can be tied to the
// artefact it describes rather than to a name and a version string.
func selfHash() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

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
		if c.Name == "go" || c.Name == s.Metadata.Component.Name {
			continue
		}
		out = append(out, c)
	}
	return out
}
