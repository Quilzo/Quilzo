package main

import (
	"os"
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
