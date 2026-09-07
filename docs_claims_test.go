// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// The README described a container this project does not build.
//
// It said the image is built `FROM scratch` and contains "the binary and
// nothing else". The Dockerfile has always used
// gcr.io/distroless/static-debian12:nonroot, which is shell-less and
// package-manager-less — both true things the README also said — but is not
// scratch and does not contain only the binary. It carries CA certificates, a
// passwd entry and timezone data.
//
// Nothing catches a documentation claim going stale. The build works, the
// image runs, every test passes, and the only person who finds out is somebody
// who believed the sentence in a security review.
//
// So the claim is checked against the file it is a claim about. This is a
// deliberately narrow test: it does not try to verify the whole README, only
// the sentences that name what the container is made of.
func TestTheReadmeDescribesTheContainerThisRepoBuilds(t *testing.T) {
	dockerfile := read(t, "Dockerfile")
	readme := read(t, "README.md")

	// The last FROM is the image that ships. An earlier one is the builder,
	// and describing the builder as the shipped image would be its own bug.
	from := regexp.MustCompile(`(?m)^FROM\s+(\S+)`).FindAllStringSubmatch(dockerfile, -1)
	if len(from) == 0 {
		t.Fatal("no FROM in the Dockerfile; this test cannot check anything")
	}
	base := from[len(from)-1][1]

	if strings.EqualFold(base, "scratch") {
		// If the image ever really is scratch, the claim becomes true and this
		// branch is the one that should hold.
		if !strings.Contains(readme, "FROM scratch") {
			t.Errorf("the image is built FROM scratch and the README does not say so")
		}
		return
	}

	if strings.Contains(readme, "FROM scratch") {
		t.Errorf("the README says the image is built FROM scratch; the "+
			"Dockerfile's final stage is %q.\n"+
			"  Both cannot be true, and the README is the one somebody quotes "+
			"in a security review.", base)
	}

	// Name the actual base, so a reader can check it rather than take the
	// adjective on trust.
	if !strings.Contains(readme, base) {
		t.Errorf("the README never names the base image %q, so a reader "+
			"cannot verify what it says about it", base)
	}
}

// The properties the README claims about that image, checked against it rather
// than repeated. Distroless static is shell-less and has no package manager;
// saying so is fair. Saying it contains "nothing else" was not.
func TestTheReadmeDoesNotClaimTheImageIsEmpty(t *testing.T) {
	readme := read(t, "README.md")
	for _, overclaim := range []string{
		"the binary and nothing else",
		"contains the binary and nothing else",
	} {
		if strings.Contains(readme, overclaim) {
			t.Errorf("the README says %q. The distroless base carries CA "+
				"certificates and a passwd entry as well.", overclaim)
		}
	}
}

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The licence the README claims is the licence in the file.
//
// Added when the project relicensed from AGPL-3.0-or-later to Apache-2.0 in
// August 2026, because that change touched five files and the failure mode is
// obvious in hindsight: one of them keeps saying the old thing, and the one
// that keeps saying it is the one somebody quotes.
//
// A licence claim is the highest-consequence sentence in a repository. Somebody
// decides whether they may use, embed or contribute to this on the strength of
// it, and a stale one is not a documentation bug — it is a person acting on
// terms that do not apply.
func TestTheReadmeClaimsTheLicenceThisRepositoryCarries(t *testing.T) {
	licence := read(t, "LICENSE")
	readme := read(t, "README.md")
	notice := read(t, "NOTICE")

	apache := strings.Contains(licence, "Apache License") &&
		strings.Contains(licence, "Version 2.0, January 2004")
	affero := strings.Contains(licence, "GNU AFFERO GENERAL PUBLIC LICENSE")

	switch {
	case apache && affero:
		t.Fatal("LICENSE contains both an Apache and an Affero header; the " +
			"relicensing left the file half-written")
	case !apache && !affero:
		t.Fatal("LICENSE is neither Apache-2.0 nor AGPL; this test cannot " +
			"check a claim about a licence it does not recognise")
	}

	want, wrong := "Apache-2.0", "AGPL-3.0-or-later"
	if affero {
		want, wrong = wrong, want
	}
	for _, file := range []struct{ name, body string }{
		{"README.md", readme}, {"NOTICE", notice},
	} {
		if !strings.Contains(file.body, want) {
			t.Errorf("LICENSE is %s and %s never says so", want, file.name)
		}
	}

	// The badge is the version most people read, and it is the one most likely
	// to be left behind because it is a URL rather than a sentence.
	badge := regexp.MustCompile(`licence-([A-Za-z0-9.\-]+)-blue`).
		FindStringSubmatch(readme)
	if badge == nil {
		t.Fatal("the README has no licence badge to check")
	}
	if got := strings.ReplaceAll(badge[1], "--", "-"); got != want {
		t.Errorf("the README badge says %q and LICENSE is %s", got, want)
	}

	// A licence change does not retract what was already granted, and saying so
	// is the difference between a licence change and a claim to have revoked
	// one. This runs in whichever direction the project is currently facing.
	if !strings.Contains(notice, wrong) {
		t.Errorf("NOTICE does not mention %s at all. This project has been "+
			"released under it, that grant is irrevocable, and a NOTICE that "+
			"omits a licence it once carried reads as a claim that it never "+
			"applied", wrong)
	}
}

// The Apache-2.0 window on 22 August 2026 stays written down.
//
// For about eighty minutes this project was public under Apache-2.0, and then it
// was not. That grant does not revert: anyone who took a copy in that window
// holds permissive terms to those commits permanently.
//
// This test exists because that is precisely the sort of fact that gets tidied
// away later — it is embarrassing, it is brief, and deleting the paragraph makes
// the history look cleaner than it was. Someone auditing where this code may
// have gone needs it to still be there.
func TestTheApacheWindowStaysRecorded(t *testing.T) {
	notice := read(t, "NOTICE")
	for _, required := range []string{
		"Apache-2.0", // the licence that applied
		"656bc88",    // where it started
		"67a85b8",    // where it stopped
		"irrevocable",
	} {
		if !strings.Contains(notice, required) {
			t.Errorf("NOTICE no longer records %q. The window was real and the "+
				"grant it made cannot be withdrawn, so the record of it is the "+
				"only honest thing left to keep", required)
		}
	}
}

// The proposal exists twice, and two copies of one document drift.
//
// ASF lists are plain text and strip HTML, so the Incubator proposal has a
// markdown source and a generated .txt. The .txt is what gets pasted into a
// mailing list that archives permanently and refuses removal requests.
//
// They drifted within a fortnight. The markdown was corrected to say the
// AgentDojo benchmark had been run; the text still said it never had. Nothing
// failed, because nothing was checking.
//
// So the text is generated by scripts/proposal/plaintext.py and this asserts
// the file in the tree is what that script produces. Same shape as the
// go-version check: one source, and a test on the pair rather than a habit.
func TestTheProposalPlainTextMatchesItsSource(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not available to run the generator")
	}
	out, err := exec.Command("python3",
		"scripts/proposal/plaintext.py", "--check").CombinedOutput()
	if err != nil {
		t.Errorf("docs/apache-incubator-proposal.txt is not what its source "+
			"renders to:\n%s\n"+
			"  Run: python3 scripts/proposal/plaintext.py", out)
	}

	// And the converter's own behaviour, on fixtures.
	//
	// Rendering the real proposal cannot catch a converter bug: it only shows
	// up when the source contains the shape that triggers it, and the source
	// stops containing that shape the moment somebody rewrites the paragraph.
	// "#33" rendered as a heading in the middle of a sentence, and became
	// untestable that way when the paragraph naming the issue was replaced.
	out, err = exec.Command("python3",
		"scripts/proposal/plaintext.py", "--self-test").CombinedOutput()
	if err != nil {
		t.Errorf("the plain-text converter fails its own checks:\n%s", out)
	}
}

// The two copies must not disagree about the benchmark, which is the highest-
// consequence sentence either of them contains and the one that already went
// stale once.
func TestBothCopiesOfTheProposalAgreeOnTheBenchmark(t *testing.T) {
	md := read(t, "docs/apache-incubator-proposal.md")
	txt := read(t, "docs/apache-incubator-proposal.txt")
	readme := read(t, "README.md")

	// The figure the README publishes has to be the figure the proposal sends.
	const figure = "26/26"
	for _, f := range []struct{ name, body string }{
		{"README.md", readme},
		{"docs/apache-incubator-proposal.md", md},
		{"docs/apache-incubator-proposal.txt", txt},
	} {
		if !strings.Contains(f.body, figure) {
			t.Errorf("%s does not carry the measured attack figure %q",
				f.name, figure)
		}
	}

	// And neither copy may still claim it was never run. The phrasing is
	// pinned because this exact sentence is the one that was left behind.
	stale := "this has never been run against AgentDojo"
	for _, f := range []struct{ name, body string }{
		{"docs/apache-incubator-proposal.md", md},
		{"docs/apache-incubator-proposal.txt", txt},
	} {
		if strings.Contains(f.body, stale) {
			t.Errorf("%s still says the benchmark was never run, and the "+
				"README publishes a measured figure", f.name)
		}
	}
}

// The SPDX expression is the licence claim most likely to be read by a machine,
// and the one most likely to disagree with itself.
//
// A single-licensed project can afford to state its licence once, in LICENSE,
// and let every file inherit it. A dual-licensed one cannot: a file with no
// header sits in a repository that says two things, and "which of the two"
// is not a question the file answers. That matters most in the case nobody
// plans for, where somebody vendors one file into another codebase and the
// only licence information that travels with it is the header it did or did
// not have.
//
// So the expression is checked for presence and for being *the same
// expression*. Two files claiming `AGPL-3.0-or-later OR LicenseRef-Commercial`
// and `AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial` would both look
// right in review and refer to different documents, one of which does not
// exist.
func TestEverySourceFileCarriesTheDualLicenceHeader(t *testing.T) {
	const want = "AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial"

	out, err := exec.Command("git", "ls-files",
		"*.go", "*.py", "*.mjs").Output()
	if err != nil {
		t.Skipf("git ls-files: %v", err)
	}
	files := strings.Fields(string(out))
	if len(files) < 100 {
		t.Fatalf("only %d source files found; this test is checking the "+
			"wrong tree", len(files))
	}

	id := regexp.MustCompile(`SPDX-License-Identifier:\s*(.+)`)
	for _, name := range files {
		body := read(t, name)
		m := id.FindStringSubmatch(body)
		if m == nil {
			t.Errorf("%s has no SPDX-License-Identifier. In a repository "+
				"offering two licences, a file that names neither is a file "+
				"whose terms have to be guessed", name)
			continue
		}
		if got := strings.TrimSpace(m[1]); got != want {
			t.Errorf("%s claims %q, every other file claims %q", name, got, want)
		}
	}
}

// Both halves of the expression resolve to a document.
//
// `LicenseRef-` is SPDX's escape hatch for a licence that is not on its list,
// and the whole point of using it rather than inventing a bare name is that a
// scanner can follow it to a file. An identifier that resolves to nothing is
// worse than no identifier: it reports as handled.
func TestBothLicencesInTheExpressionExist(t *testing.T) {
	for name, mustSay := range map[string]string{
		"LICENSES/AGPL-3.0-or-later.txt":            "GNU AFFERO GENERAL PUBLIC LICENSE",
		"LICENSES/LicenseRef-Quilzo-Commercial.txt": "commercial licence",
		"LICENSING.md": "AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial",
		"CLA.md":       "Harmony",
	} {
		if body := read(t, name); !strings.Contains(body, mustSay) {
			t.Errorf("%s does not contain %q", name, mustSay)
		}
	}

	// The AGPL half must be the same text as LICENSE, not a paraphrase of it
	// or a copy that drifted. This is the only licence in the pair whose
	// wording is not the project's to choose.
	if read(t, "LICENSES/AGPL-3.0-or-later.txt") != read(t, "LICENSE") {
		t.Error("LICENSES/AGPL-3.0-or-later.txt differs from LICENSE. The " +
			"AGPL text is not ours to edit, and two copies of it in one " +
			"repository must be one copy")
	}

	// A reader who finds only LICENSE has been told half the arrangement.
	if !strings.Contains(read(t, "README.md"), "LICENSING.md") {
		t.Error("the README never points at LICENSING.md, so the second " +
			"licence is discoverable only by reading source headers")
	}
}

// Dual licensing is one exception away from open core, and the exception
// always looks reasonable at the time.
//
// LICENSING.md and GOVERNANCE.md both promise there is one program: no feature
// held back, no separate build, no code path that branches on which licence the
// operator holds. That promise is prose, and prose does not fail a build.
//
// This checks the part a test can reach — that nothing in the tree reads a
// licence tier and decides what to do about it. It cannot prove the commitment
// is kept, because a determined open-core tier would not use any of these
// names. What it does catch is the realistic failure: somebody adds a licence
// check for a reason that seemed fine, and nobody reviewing it remembers this
// file exists. That is how open core actually arrives — as drift, not as a
// decision.
func TestNothingBranchesOnWhichLicenceTheOperatorHolds(t *testing.T) {
	out, err := exec.Command("git", "ls-files", "*.go").Output()
	if err != nil {
		t.Skipf("git ls-files: %v", err)
	}

	// Identifiers that would only exist to gate behaviour on a licence tier.
	// Deliberately narrow: each is a name somebody would reach for while
	// building the thing this project promised not to build.
	tiering := regexp.MustCompile(`(?i)\b(` +
		`licen[cs]eKey|licen[cs]e_key|` +
		`isEnterprise|enterpriseOnly|isPro\b|proOnly|` +
		`isLicen[cs]ed|hasLicen[cs]e|licen[cs]eTier|` +
		`checkLicen[cs]e|requireLicen[cs]e|` +
		`commercialOnly|paidOnly|premiumOnly)`)

	for _, name := range strings.Fields(string(out)) {
		if name == "docs_claims_test.go" {
			continue // the pattern above is in it
		}
		body := read(t, name)
		for _, m := range tiering.FindAllString(body, -1) {
			t.Errorf("%s contains %q. LICENSING.md and GOVERNANCE.md both "+
				"promise one program with no code path branching on the "+
				"operator's licence. If this is that path, the promise is "+
				"broken; if it is not, it needs a different name", name, m)
		}
	}
}

// The decision this reversed stays quoted.
//
// GOVERNANCE.md ruled dual licensing out, deliberately and with a reason, and
// then the project did it anyway. CONTRIBUTING.md promised there was no CLA
// waiting behind the DCO, and then one arrived. Both are reversals of positions
// somebody could have acted on.
//
// This is the same test as TestTheApacheWindowStaysRecorded and exists for the
// same reason: a retraction is exactly the sort of paragraph that gets tidied
// away later, because it is unflattering and the file reads more cleanly
// without it. A reader deciding whether to trust a commitment in one of these
// files needs to be able to see which commitments have already been withdrawn.
func TestTheReversedDecisionsStayRecorded(t *testing.T) {
	for _, want := range []struct{ file, phrase, why string }{
		{"GOVERNANCE.md", "ruled out by choice rather than by arithmetic",
			"the paragraph that ruled dual licensing out"},
		{"GOVERNANCE.md", "no open-core tier",
			"the commitment that was kept, which is what makes the other " +
				"reversal defensible rather than drift"},
		{"CONTRIBUTING.md", "no CLA waiting behind the DCO",
			"the promise the CLA withdrew"},
		{"CONTRIBUTING.md", "No longer true",
			"the bullet that said nobody could relicense your code without " +
				"asking, corrected rather than deleted"},
		{"NOTICE", "there was no contributor licence agreement",
			"the same withdrawal, in the file a packager reads"},
	} {
		if !strings.Contains(read(t, want.file), want.phrase) {
			t.Errorf("%s no longer contains %q — %s. A project that "+
				"documents a reversal and then removes the documentation has "+
				"done the reversal twice",
				want.file, want.phrase, want.why)
		}
	}
}
