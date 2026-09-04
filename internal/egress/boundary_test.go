package egress_test

import "github.com/quilzo/quilzo/internal/egress"

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Nothing reaches the network except through this package.
//
// A boundary a new feature can quietly step over is a boundary for exactly as
// long as nobody adds a feature. Before this existed there were six places
// constructing an HTTP client — internal/fetch and four others — and no list
// of them, so the question "what would this program talk to" was answered by
// reading all of it.
//
// So this reads all of it, once, and fails when a seventh appears. The same
// shape as the privilege table and the crypto inventory: a capability that is
// not written down is one nobody reviewed.
func TestNothingReachesTheNetworkOutsideThisPackage(t *testing.T) {
	// Each exemption is a real one, and each says why. A pattern-based excuse
	// would also excuse the next thing that happens to match it.
	exempt := map[string]string{
		"internal/egress/egress.go": "this package is the boundary",
		"internal/fetch/fetch.go": "builds a transport with its own address " +
			"rules — SSRF checks, per-hop revalidation — and calls " +
			"egress.Allowed in front of its dialler, which a test below checks",
		"internal/logd/logd.go": "dials a unix socket, which does not leave " +
			"the host and is not egress",
	}

	var found []string
	err := filepath.Walk("../..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "testdata", "scratchpad":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
		if _, ok := exempt[rel]; ok {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		text := string(body)
		for _, construct := range []string{
			"&http.Client{",
			"http.DefaultClient",
			"http.Get(",
			"http.Post(",
			"net.Dial(",
			"net.DialTimeout(",
		} {
			if strings.Contains(text, construct) {
				found = append(found, rel+": "+construct)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range found {
		t.Errorf("%s reaches the network without going through "+
			"internal/egress.\n"+
			"  An isolated deployment cannot be told what this program would "+
			"connect to,\n  and turning the network off would not turn this "+
			"off. Use egress.Client\n  with a declared purpose, or add an "+
			"exemption saying why it is not egress.", f)
	}
}

// The exemption for internal/fetch is only true while it consults the mode.
//
// It has its own dialler, for good reasons, so it cannot use egress.Client.
// That makes it the one place where the boundary depends on a call rather
// than on a type — which is exactly the kind of thing that gets refactored
// away by somebody who does not know why it is there.
func TestFetchStillConsultsTheMode(t *testing.T) {
	body, err := os.ReadFile("../fetch/fetch.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "egress.Allowed(") {
		t.Fatal("internal/fetch no longer checks the network mode, so an " +
			"offline\n  deployment still fetches remote actors, imports and " +
			"webfinger")
	}
}

// Every purpose says what stops working without it.
//
// The consequence has to be visible before the mode is turned on, not
// discovered after by somebody wondering why followers stopped receiving
// posts.
func TestEveryPurposeSaysWhatBreaks(t *testing.T) {
	if len(egress.Purposes) < 5 {
		t.Fatalf("%d purposes; the list is not the program's network use",
			len(egress.Purposes))
	}
	for _, p := range egress.Purposes {
		if strings.TrimSpace(p.What) == "" {
			t.Errorf("%s does not say what it is for", p.Name)
		}
		if strings.TrimSpace(p.Without) == "" {
			t.Errorf("%s does not say what stops working without it, so "+
				"turning the network off is a decision nobody can weigh",
				p.Name)
		}
	}
}
