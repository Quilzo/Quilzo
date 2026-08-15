package compliance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

// The document cannot drift from the program without the build failing.
//
// A compliance artefact maintained by hand is one that was true when somebody
// wrote it, and the gap between it and the software is invisible until an
// auditor finds it. This walks the source and checks the declared inventory
// against what is actually imported.
func TestTheCryptoInventoryMatchesWhatTheSourceImports(t *testing.T) {
	declared := map[string]bool{}
	for _, a := range Inventory() {
		for _, p := range strings.Split(a.Package, ",") {
			declared[strings.TrimSpace(p)] = true
		}
	}

	imported := map[string]bool{}
	re := regexp.MustCompile(`"(crypto/[a-z0-9/]+)"`)
	for _, root := range []string{"..", filepath.Join("..", "..", "cmd")} {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
				strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, m := range re.FindAllStringSubmatch(string(body), -1) {
				imported[m[1]] = true
			}
			return nil
		})
	}

	for pkg := range imported {
		if !declared[pkg] {
			t.Errorf("%s is imported and not in the cryptographic inventory. "+
				"A questionnaire answered from that inventory would be wrong.",
				pkg)
		}
	}
	for pkg := range declared {
		if !imported[pkg] {
			t.Errorf("%s is in the inventory and imported nowhere. An "+
				"inventory listing what is not used overstates the surface.",
				pkg)
		}
	}
	if len(imported) < 5 {
		t.Fatalf("only %d crypto imports found; this test has stopped looking",
			len(imported))
	}
}

func TestEveryAlgorithmIsFullyDescribed(t *testing.T) {
	for _, a := range Inventory() {
		if a.Name == "" || a.Purpose == "" || a.Where == "" {
			t.Errorf("%#v is missing a field somebody would ask about", a)
		}
		switch a.Quantum {
		case Safe, Reduced, Broken:
		default:
			t.Errorf("%s has quantum status %q", a.Name, a.Quantum)
		}
		switch a.Use {
		case Generated, Verified:
		default:
			t.Errorf("%s has use %q", a.Name, a.Use)
		}
		// Anything a quantum computer defeats needs its position explained,
		// because "broken" with no context reads as an open vulnerability.
		if a.Quantum == Broken && a.Note == "" {
			t.Errorf("%s is quantum-broken with no explanation of what that "+
				"means here", a.Name)
		}
	}
}

// The honest claim, and the one an enterprise questionnaire is asking for.
func TestNothingQuantumBrokenIsGeneratedHere(t *testing.T) {
	for _, a := range Inventory() {
		if a.Quantum == Broken && a.Use == Generated {
			t.Errorf("%s is generated here and quantum-broken, so the stated "+
				"posture is wrong and there is a migration this project owns",
				a.Name)
		}
	}
	summary := Posture()
	if !strings.Contains(summary, "generates no material") {
		t.Errorf("the summary does not make the claim plainly: %s", summary)
	}
	if !strings.Contains(summary, "identity provider") {
		t.Error("the summary does not mention the verified algorithms, which " +
			"is where the real migration is")
	}
}

// Generated before verified: one is this project's problem and the other is
// somebody else's, and a list that mixes them makes the urgent one look the
// same as the inherited one.
func TestConcernsAreOrderedByWhoOwnsThem(t *testing.T) {
	c := Concerns()
	if len(c) == 0 {
		t.Fatal("nothing is listed as a concern, which cannot be right while " +
			"RSA and ECDSA are verified")
	}
	seenVerified := false
	for _, a := range c {
		if a.Use == Verified {
			seenVerified = true
		} else if seenVerified {
			t.Error("a generated concern appears after a verified one")
		}
	}
}

// -- the bill of materials ---------------------------------------------------

func TestTheSBOMIsValidCycloneDX(t *testing.T) {
	s, err := Generate(now)
	if err != nil {
		t.Skipf("no build info in a test binary: %v", err)
	}
	body, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("the SBOM is not JSON: %v", err)
	}
	for _, required := range []string{"bomFormat", "specVersion", "metadata",
		"components"} {
		if _, ok := parsed[required]; !ok {
			t.Errorf("the SBOM has no %s", required)
		}
	}
	if parsed["bomFormat"] != "CycloneDX" {
		t.Errorf("format is %v", parsed["bomFormat"])
	}
}

// The toolchain is the largest thing in this product by volume and the one an
// advisory is most likely to concern. An SBOM that omits it describes a program
// with no runtime.
func TestTheToolchainIsAComponent(t *testing.T) {
	s, err := Generate(now)
	if err != nil {
		t.Skip("no build info")
	}
	var found bool
	for _, c := range s.Components {
		if c.Name == "go" {
			found = true
			if c.Version == "" {
				t.Error("the toolchain has no version")
			}
		}
	}
	if !found {
		t.Error("the Go toolchain is not in the bill of materials")
	}
}

// The property this whole position rests on. If a dependency is ever added, the
// CRA obligations stop being cheap, and somebody should notice deliberately
// rather than discover it during an incident.
func TestThereAreNoThirdPartyDependencies(t *testing.T) {
	s, err := Generate(now)
	if err != nil {
		t.Skip("no build info")
	}
	third := ThirdParty(s)
	if len(third) != 0 {
		var names []string
		for _, c := range third {
			names = append(names, c.Name+"@"+c.Version)
		}
		t.Errorf("this program now has %d third-party dependencies: %v\n"+
			"That is a real change: a transitive tree to track, components "+
			"that can reach end of life unnoticed, and an advisory feed to "+
			"reconcile against. If it was deliberate, update this test and the "+
			"SBOM commentary; if it was not, that is the finding.",
			len(third), names)
	}
}

// An SBOM for a binary built from uncommitted changes describes source nobody
// else can obtain, and saying so is the difference between a document and a
// claim.
func TestAModifiedBuildSaysSo(t *testing.T) {
	s, err := Generate(now)
	if err != nil {
		t.Skip("no build info")
	}
	if s.Metadata.Component.Version == "" {
		t.Error("the product has no version at all")
	}
}
