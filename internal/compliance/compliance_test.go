// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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
		case Generated, Verified, Demonstration:
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

// The summary has to say where this program actually stands.
//
// # Why this no longer asserts a particular posture
//
// It used to require that nothing quantum-broken was generated here, and that
// the summary contained the words "generates no material". Both were true when
// they were written, and both were read out of the same field the document
// prints — so the test asserted that the inventory said what the inventory used
// to say.
//
// When federation landed, `quilzo fediverse` began generating a 2048-bit RSA
// key and every delivery began carrying an RSA signature. The fact changed; the
// inventory entry did not; this test went on passing, because it was pinned to
// the old answer rather than checking the answer against the program. For as
// long as nobody looked, a compliance document said there was no migration for
// this project to own, to a reader answering a questionnaire under a regime with
// a fifteen-million euro ceiling.
//
// So the property is consistency, not a posture: whatever the program generates,
// the summary names it and says whose migration it is. What keeps the inventory
// itself honest is the source walk further down —
// TestAnAlgorithmThisProgramSignsWithIsNotListedAsOnlyVerified — which reads the
// calls rather than the claim.
func TestThePostureNamesWhatIsActuallyGenerated(t *testing.T) {
	summary := Posture()
	for _, a := range Inventory() {
		if a.Quantum != Broken {
			continue
		}
		if !strings.Contains(summary, a.Name) {
			t.Errorf("%s is quantum-broken and the summary does not mention "+
				"it at all:\n%s", a.Name, summary)
			continue
		}
		if a.Use == Generated && !strings.Contains(summary,
			"migration this project owns") {
			t.Errorf("%s is generated here and quantum-broken, and the summary "+
				"does not say the migration is this project's:\n%s",
				a.Name, summary)
		}
	}
	if !strings.Contains(summary, "harvest-now") {
		t.Error("the summary does not address harvest-now, decrypt-later, " +
			"which is the question every questionnaire asks")
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
	// CycloneDX 1.6's shapes: a licence is an object or an expression, a
	// supplier an organisation, tools an object, and no field it does not
	// define.
	meta := parsed["metadata"].(map[string]any)
	if _, ok := meta["tools"].(map[string]any); !ok {
		t.Error("tools is not an object")
	}
	self := meta["component"].(map[string]any)
	lic := self["licenses"].([]any)[0].(map[string]any)
	if lic["expression"] != Licence {
		t.Errorf("the program's licence is %v", lic)
	}
	for _, c := range parsed["components"].([]any) {
		m := c.(map[string]any)
		if _, bad := m["direct"]; bad {
			t.Error("a field CycloneDX does not define")
		}
		for _, l := range m["licenses"].([]any) {
			if _, ok := l.(map[string]any); !ok {
				t.Errorf("a licence that is not an object: %v", l)
			}
		}
		if sup, ok := m["supplier"]; ok {
			if _, ok := sup.(map[string]any); !ok {
				t.Errorf("a supplier that is not an organisation: %v", sup)
			}
		}
	}
	if !strings.HasPrefix(parsed["serialNumber"].(string), "urn:uuid:") {
		t.Error("no serial number")
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
		if c.Name == "stdlib" {
			found = true
			// Named as the Go vulnerability database names it, or no feed
			// ever matches it and a self-scan is silently clean.
			if c.Version == "" || !strings.HasPrefix(c.PURL, "pkg:golang/stdlib@1.") || strings.Contains(c.PURL, "@go") {
				t.Errorf("the standard library is %s %s", c.PURL, c.Version)
			}
		}
	}
	if !found {
		t.Error("the Go standard library is not in the bill of materials")
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

// An algorithm this program signs with cannot be listed as one it only checks.
//
// The test above walks the source for crypto imports and matches them against
// the inventory's package list. That is the wrong half. When federation landed,
// `quilzo fediverse` began generating a 2048-bit RSA key and every delivery to a
// follower's inbox began carrying an RSA signature — and crypto/rsa was already
// declared for verifying ID tokens, so the import check stayed green while the
// entry went on saying "this program never generates an RSA signature".
//
// The posture summary is derived from that field, so it said the program
// generates no material with an algorithm a quantum computer defeats, and that
// there is no migration for this project to own. A compliance document is read
// by somebody answering a questionnaire under a regime with a fifteen-million
// euro ceiling, and it was wrong for as long as nobody looked.
//
// So this checks the claim rather than the import: if the source signs with an
// algorithm, its entry says Generated.
func TestAnAlgorithmThisProgramSignsWithIsNotListedAsOnlyVerified(t *testing.T) {
	// The calls that produce a signature or a key, and the inventory entry each
	// one implicates. Named rather than pattern-matched, because "anything with
	// Sign in it" would also catch a verifier called SignatureOf.
	signing := map[string]string{
		"rsa.SignPKCS1v15":       "crypto/rsa",
		"rsa.SignPSS":            "crypto/rsa",
		"rsa.GenerateKey":        "crypto/rsa",
		"ecdsa.SignASN1":         "crypto/ecdsa",
		"ecdsa.Sign":             "crypto/ecdsa",
		"ed25519.Sign":           "crypto/ed25519",
		"ed25519.GenerateKey":    "crypto/ed25519",
		"ed25519.NewKeyFromSeed": "crypto/ed25519",
	}

	// Where each package's use is declared.
	use := map[string]Use{}
	name := map[string]string{}
	for _, a := range Inventory() {
		for _, p := range strings.Split(a.Package, ",") {
			pkg := strings.TrimSpace(p)
			use[pkg] = a.Use
			name[pkg] = a.Name
		}
	}

	found := map[string]string{} // package -> the call that proves it
	for _, root := range []string{"..", filepath.Join("..", "..", "cmd")} {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
				strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// internal/compliance itself is the document, and internal/demo is
			// a fixture generator rather than the product's own cryptography.
			if strings.Contains(path, "/compliance/") {
				return nil
			}
			body, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			for call, pkg := range signing {
				if strings.Contains(string(body), call+"(") {
					found[pkg] = call + " in " + filepath.ToSlash(path)
				}
			}
			return nil
		})
	}

	for pkg, where := range found {
		switch use[pkg] {
		case Generated:
			// Correct: the document says this program produces material here.
		case "":
			t.Errorf("%s is used to sign or generate keys (%s) and is in no "+
				"inventory entry", pkg, where)
		default:
			t.Errorf("%s is listed as %q and the source signs with it: %s.\n"+
				"  The posture summary is derived from that field, so it "+
				"currently tells a reader this program produces nothing with "+
				"%s — which is what the document is for.",
				pkg, use[pkg], where, name[pkg])
		}
	}
	if len(found) == 0 {
		t.Error("no signing call was found anywhere, which means this test " +
			"scanned nothing and would pass whatever the inventory said")
	}
}

// demonstrations are the commands that run a call, its keys and its media
// against identities made for the run, and the packages only they reach.
// Nothing a deployment does on its own calls any of them.
var (
	demoCommands = map[string]bool{"callcmd.go": true, "huddlecmd.go": true, "scribecmd.go": true,
		"sframecmd.go": true, "screencmd.go": true, "errandcmd.go": true, "annotatecmd.go": true}
	demoPackages = map[string]bool{"groupkey": true, "sframe": true, "huddle": true, "scribe": true,
		"errand": true, "screen": true, "annotate": true}
)

// The inventory claimed product use of call cryptography that only the
// terminal demonstrations reach. ML-KEM with X25519 was "generated" for "the
// per-epoch secret of a call", HKDF for "per-sender media keys", and
// Ed25519 and ML-DSA named groupkey where they are used, while no call, key
// agreement or media encryption runs anywhere but `quilzo call`, `huddle`,
// `scribe` and their kind. An agency hands this to a client as what the
// product does. So a package only demonstrations reach is not named where
// an algorithm is used, and an algorithm only they reach says so in its use.
func TestCallCryptographyIsMarkedAsDemonstrationOnly(t *testing.T) {
	importRe := regexp.MustCompile(`"(crypto/[a-z0-9/]+|github\.com/quilzo/quilzo/internal/[a-z0-9]+)"`)
	// crypto package -> where it is imported, split by what reaches it.
	demo, product := map[string]map[string]bool{}, map[string]map[string]bool{}
	for _, root := range []string{"..", filepath.Join("..", "..", "cmd")} {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
				strings.HasSuffix(path, "_test.go") || strings.Contains(path, "/compliance/") {
				return nil
			}
			body, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			dir := filepath.Base(filepath.Dir(path))
			isDemo := demoPackages[dir] || demoCommands[filepath.Base(path)]
			for _, m := range importRe.FindAllStringSubmatch(string(body), -1) {
				imp := m[1]
				if pkg, ok := strings.CutPrefix(imp, "github.com/quilzo/quilzo/internal/"); ok {
					// Only demonstrations may reach a demonstration package,
					// or the marking below would understate what ships.
					if demoPackages[pkg] && !isDemo {
						t.Errorf("%s reaches internal/%s, which the inventory treats as "+
							"reached only by the demonstrations", filepath.ToSlash(path), pkg)
					}
					continue
				}
				into := product
				if isDemo {
					into = demo
				}
				if into[imp] == nil {
					into[imp] = map[string]bool{}
				}
				into[imp][dir] = true
			}
			return nil
		})
	}
	if len(demo) == 0 {
		t.Fatal("no demonstration imports any cryptography; this test has stopped looking")
	}

	for _, a := range Inventory() {
		onlyDemo := true
		for _, p := range strings.Split(a.Package, ",") {
			pkg := strings.TrimSpace(p)
			if len(product[pkg]) > 0 || len(demo[pkg]) == 0 {
				onlyDemo = false
			}
		}
		// Compared as a string so this reads the same before and after the
		// use was named.
		if onlyDemo != (string(a.Use) == "demonstration") {
			t.Errorf("%s: only the demonstrations reach it is %v, and its use is %q",
				a.Name, onlyDemo, a.Use)
		}
		if onlyDemo {
			continue
		}
		for _, w := range strings.Split(a.Where, ",") {
			if name := strings.Fields(strings.TrimSpace(w)); len(name) > 0 && demoPackages[name[0]] {
				t.Errorf("%s names %s where it is used, and only the demonstrations reach %s",
					a.Name, name[0], name[0])
			}
		}
	}
}
