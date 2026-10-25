// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

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

// The licence every document states is the licence in the file.
//
// A licence claim is the sentence somebody decides on whether they may use,
// embed or contribute to this, and a stale one is a person acting on terms
// that do not apply.
func TestTheReadmeClaimsTheLicenceThisRepositoryCarries(t *testing.T) {
	licence := read(t, "LICENSE")
	if !strings.Contains(licence, "Apache License") ||
		!strings.Contains(licence, "Version 2.0, January 2004") {
		t.Fatal("LICENSE is not the Apache License 2.0")
	}
	states := map[string]bool{"README.md": true, "NOTICE": true, "AUTHORS": true,
		"CONTRIBUTING.md": true, "GOVERNANCE.md": true, "INSTALL": true, "docs/cms.md": true}
	for _, name := range []string{"README.md", "NOTICE", "AUTHORS", "CONTRIBUTING.md",
		"GOVERNANCE.md", "INSTALL", "docs/cms.md", "NEWS", "SECURITY.md"} {
		body := read(t, name)
		if states[name] && !strings.Contains(body, "Apache") {
			t.Errorf("%s does not say the licence is Apache-2.0", name)
		}
		for _, stale := range []string{"AGPL", "Affero", "LicenseRef-Quilzo-Commercial",
			"LICENSING.md", "CLA.md"} {
			if strings.Contains(body, stale) {
				t.Errorf("%s still mentions %q, from a licence arrangement this "+
					"repository no longer has", name, stale)
			}
		}
	}

	// The badge is the version most people read, and the one most likely to
	// be left behind because it is a URL rather than a sentence.
	badge := regexp.MustCompile(`licence-([A-Za-z0-9.\-]+)-blue`).
		FindStringSubmatch(read(t, "README.md"))
	if badge == nil {
		t.Fatal("the README has no licence badge to check")
	}
	if got := strings.ReplaceAll(badge[1], "--", "-"); got != "Apache-2.0" {
		t.Errorf("the README badge says %q and LICENSE is Apache-2.0", got)
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

// Every source file says its licence, and says the same one.
//
// A file vendored into another codebase carries only its header, so the
// header has to be there and has to be the identifier LICENSE states.
func TestEverySourceFileCarriesTheLicenceHeader(t *testing.T) {
	const want = "Apache-2.0"

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
			t.Errorf("%s has no SPDX-License-Identifier", name)
			continue
		}
		if got := strings.TrimSpace(m[1]); got != want {
			t.Errorf("%s claims %q, every other file claims %q", name, got, want)
		}
	}
}

// The licence text is Apache's own, and the copy a REUSE scanner follows the
// identifier to is the same text, with no other licence beside it.
func TestTheLicenceTextIsOneText(t *testing.T) {
	if read(t, "LICENSES/Apache-2.0.txt") != read(t, "LICENSE") {
		t.Error("LICENSES/Apache-2.0.txt differs from LICENSE. The licence " +
			"text is not ours to edit, and two copies of it must be one copy")
	}
	entries, err := os.ReadDir("LICENSES")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "Apache-2.0.txt" {
			t.Errorf("LICENSES/%s is a licence no file in this repository is under", e.Name())
		}
	}
}

// Every copy carries the licence and the notices.
//
// A binary is a copy of the Go standard library, the Go vulnerability
// records, the FedRAMP indicators, the typeface and the icons as well as of Quilzo,
// and their licences ask for their notices to go with it. So NOTICE names each
// of them, and the release and the container image carry LICENSE and NOTICE.
func TestEveryCopyCarriesTheLicenceAndNotices(t *testing.T) {
	notice := read(t, "NOTICE")
	for _, embedded := range []string{"Go standard library", "internal/admin/assets/fonts",
		"internal/admin/assets/icons", "internal/icons",
		"internal/selfvuln", "internal/fedramp"} {
		if !strings.Contains(notice, embedded) {
			t.Errorf("NOTICE does not name %s, which the binary carries", embedded)
		}
	}
	release := read(t, ".github/workflows/release.yml")
	for _, f := range []string{"            LICENSE\n", "            NOTICE\n"} {
		if !strings.Contains(release, f) {
			t.Errorf("the release does not publish %s beside the binaries", strings.TrimSpace(f))
		}
	}
	if !strings.Contains(read(t, "Dockerfile"), "/src/LICENSE /src/NOTICE /usr/share/doc/quilzo/") {
		t.Error("the container image does not carry LICENSE and NOTICE")
	}
	// The image's binary is built from what .dockerignore lets in, and the
	// typeface's and icons' READMEs say what was changed.
	ignore := read(t, ".dockerignore")
	for _, f := range []string{"internal/admin/assets/fonts/README.md", "internal/admin/assets/icons/README.md"} {
		if !strings.Contains(ignore, "!"+f) {
			t.Errorf(".dockerignore leaves %s out of the image's binary", f)
		}
	}
}

// GOVERNANCE.md promises there is no open-core tier: no feature held back,
// no separate build, no code path that branches on which licence the operator
// holds. That promise is prose, and prose does not fail a build.
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
			t.Errorf("%s contains %q. GOVERNANCE.md promises one program "+
				"with no code path branching on the operator's licence. If "+
				"this is that path, the promise is broken; if it is not, it "+
				"needs a different name", name, m)
		}
	}
}

// INSTALL counts the test suite, so the count is derived rather than recalled.
//
// It said "sixty-six packages" from whenever that was true until September
// 2026, by which point the answer was seventy-nine. Nobody lied and nobody
// noticed: a number in prose has no relationship to the thing it counts, and
// the failure is silent in the direction that makes the project look smaller
// than it is.
//
// The interesting property is not that the number is right today. It is that
// being wrong is now a test failure that names the correct value, so the fix
// is mechanical and nobody has to decide whether it is worth chasing.
// spell writes a number the way INSTALL writes it, or says it cannot.
//
// Spelled out, because that is how INSTALL is written and a document that
// switches to digits for one number reads like it was patched.
func spell(n int) (string, bool) {
	tens := map[int]string{2: "twenty", 3: "thirty", 4: "forty", 5: "fifty",
		6: "sixty", 7: "seventy", 8: "eighty", 9: "ninety"}
	// One to nineteen in full, because a hundred and one needs the "one" and
	// deriving half of them from a tens map is how this went quiet the
	// first time.
	small := map[int]string{1: "one", 2: "two", 3: "three", 4: "four",
		5: "five", 6: "six", 7: "seven", 8: "eight", 9: "nine",
		10: "ten", 11: "eleven", 12: "twelve", 13: "thirteen",
		14: "fourteen", 15: "fifteen", 16: "sixteen", 17: "seventeen",
		18: "eighteen", 19: "nineteen"}
	if n < 20 || n > 999 {
		return "", false
	}
	hundreds, rest := n/100, n%100
	out := ""
	if hundreds > 0 {
		out = small[hundreds] + " hundred"
		if rest == 0 {
			return out, true
		}
		out += " and "
	}
	if rest < 20 {
		return out + small[rest], true
	}
	out += tens[rest/10]
	if u := rest % 10; u != 0 {
		out += "-" + small[u]
	}
	return out, true
}

func TestInstallCountsTheTestSuiteCorrectly(t *testing.T) {
	out, err := exec.Command("go", "list", "-f",
		"{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}", "./...").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	want := len(strings.Fields(string(out)))
	if want < 50 {
		t.Fatalf("only %d packages have tests; this is counting the wrong "+
			"tree", want)
	}

	spelled, ok := spell(want)
	if !ok {
		// Refused rather than skipped. This check used to build the words
		// from a tens map that stopped at ninety, so at one hundred it
		// produced an empty string and asked whether INSTALL contained
		// " packages" — which it always does. The guard went quiet at a
		// round number and nobody would have noticed until the figure was
		// out by twenty.
		t.Fatalf("%d cannot be spelled by this test, so it would check "+
			"nothing. Extend spell() rather than letting it pass", want)
	}

	install := read(t, "INSTALL")
	if !strings.Contains(install, spelled+" packages") {
		t.Errorf("INSTALL does not say %q. %d packages have tests, and the "+
			"suite it describes is the one `make check` runs",
			spelled+" packages", want)
	}
}

// No document asks for an image tag that begins with "v".
//
// The git tag is v0.1.0 and the image tags are 0.1.0, 0.1 and latest, because
// docker/metadata-action's semver patterns strip the prefix. So
// ghcr.io/quilzo/quilzo:v0.1.0 does not exist, and both INSTALL and the
// release workflow asked for it — the workflow in the very step written to
// prove the image is reachable, where a 404 for a tag that was never pushed
// is indistinguishable from a 404 for a private package.
//
// That is the expensive shape of this mistake. The check would have failed
// every release, for a reason that looked exactly like the reason it existed,
// until somebody decided the check was broken and removed it.
//
// Static, and deliberately narrow: it does not ask whether a tag exists, which
// would put the network in the test suite. It asks whether anything wrote the
// one form that cannot exist.
func TestNoDocumentAsksForAnImageTagWithAVeePrefix(t *testing.T) {
	files := []string{"README.md", "INSTALL", "NEWS",
		".github/workflows/release.yml", "docs/codeql-dismissals.md"}

	// ghcr.io/owner/name:vN..., in a command rather than in prose about it.
	bad := regexp.MustCompile(`ghcr\.io/[A-Za-z0-9._/-]+:v\d`)
	for _, name := range files {
		for _, line := range strings.Split(read(t, name), "\n") {
			m := bad.FindString(line)
			if m == "" {
				continue
			}
			t.Errorf("%s asks for %q. Image tags drop the v: the git tag "+
				"v0.1.0 publishes 0.1.0, 0.1 and latest, so this reference "+
				"404s and the 404 looks like the image being private",
				name, m)
		}
	}
}

// The guard above went quiet at a round number: it built the words from a
// tens map that stopped at ninety, so at one hundred it asked whether INSTALL
// contained " packages", which it always does. A check that stops checking
// and keeps passing is worse than one that was never written.
func TestTheSpellingGuardDoesNotGoQuietAtARoundNumber(t *testing.T) {
	for n, want := range map[int]string{
		42: "forty-two", 99: "ninety-nine", 100: "one hundred",
		101: "one hundred and one", 120: "one hundred and twenty",
		305: "three hundred and five",
	} {
		got, ok := spell(n)
		if !ok || got != want {
			t.Errorf("spell(%d) = %q (%v), want %q", n, got, ok, want)
		}
	}
	// And where it cannot spell a number it says so rather than producing
	// something that matches everything.
	for _, n := range []int{0, 7, 19, 1000, -3} {
		if got, ok := spell(n); ok && got == "" {
			t.Errorf("spell(%d) claimed success with an empty string", n)
		}
	}
	if got, _ := spell(0); strings.TrimSpace(got) != got {
		t.Error("a refusal returned padding")
	}
}

// The one rule CONTRIBUTING.md says will surprise people, held by a test
// rather than by review: go.mod requires nothing and there is no go.sum. A
// dependency added by `go get` in a hurry would otherwise arrive in a
// pull request whose diff looks like one line.
func TestGoModRequiresNothing(t *testing.T) {
	for _, line := range strings.Split(read(t, "go.mod"), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && (f[0] == "require" || f[0] == "replace") {
			t.Errorf("go.mod has %q. Quilzo has no third-party dependencies; "+
				"CONTRIBUTING.md says what to do instead", strings.TrimSpace(line))
		}
	}
	if _, err := os.Stat("go.sum"); err == nil {
		t.Error("there is a go.sum, so something outside the standard library was fetched")
	}
}
