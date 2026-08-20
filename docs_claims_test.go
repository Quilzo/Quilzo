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
