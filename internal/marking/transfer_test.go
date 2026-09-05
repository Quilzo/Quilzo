package marking_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/marking"
)

func exported(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"pages/index.json": `{"title":"Home"}`,
		"pages/about.json": `{"title":"About"}`,
		"media/photo.png":  "\x89PNG\r\n\x1a\nnot really",
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func record(t *testing.T, dir string) *marking.Transfer {
	t.Helper()
	rec, err := marking.RecordTransfer(dir, marking.Transfer{
		Banner: "SECRET//NOFORN", Approved: "Ops Lead", Carried: "R. Adhikari",
		Reason: "quarterly content refresh", From: "low", To: "high",
	}, time.Unix(1787000000, 0))
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// A transfer that arrives intact verifies.
func TestATransferVerifiesOnArrival(t *testing.T) {
	dir := exported(t)
	rec := record(t, dir)
	if len(rec.Files) != 3 {
		t.Fatalf("%d files recorded, want 3", len(rec.Files))
	}

	got, problems, err := marking.VerifyTransfer(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 0 {
		t.Errorf("an intact transfer reported problems: %v", problems)
	}
	if got.Approved != "Ops Lead" || got.Carried != "R. Adhikari" {
		t.Errorf("the manifest lost who is accountable: %+v", got)
	}
}

// A file altered in transit is caught.
func TestAnAlteredFileIsCaught(t *testing.T) {
	dir := exported(t)
	record(t, dir)

	p := filepath.Join(dir, "pages", "index.json")
	if err := os.WriteFile(p, []byte(`{"title":"Something else"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, problems, err := marking.VerifyTransfer(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) == 0 {
		t.Fatal("an altered file verified")
	}
	if !strings.Contains(problems[0], "does not match") {
		t.Errorf("the problem is not described: %v", problems)
	}
}

// A file that joined the transfer after it was recorded is caught.
//
// The direction nobody looks for. A corrupted file is obvious; a file that
// arrived and was never on the manifest is content that entered somewhere
// between the two networks.
func TestAFileThatJoinedTheTransferIsCaught(t *testing.T) {
	dir := exported(t)
	record(t, dir)

	if err := os.WriteFile(filepath.Join(dir, "extra.json"),
		[]byte(`{"nobody":"asked for this"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, problems, err := marking.VerifyTransfer(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) == 0 {
		t.Fatal("a file that was never on the manifest verified")
	}
	if !strings.Contains(strings.Join(problems, " "), "joined the transfer") {
		t.Errorf("the problem is not described: %v", problems)
	}
}

// A file that did not arrive is caught.
func TestAMissingFileIsCaught(t *testing.T) {
	dir := exported(t)
	record(t, dir)
	if err := os.Remove(filepath.Join(dir, "pages", "about.json")); err != nil {
		t.Fatal(err)
	}

	_, problems, err := marking.VerifyTransfer(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "did not arrive") {
		t.Errorf("a missing file was not reported: %v", problems)
	}
}

// Nobody accountable, no manifest.
//
// The whole point: a transfer nobody is named on is a directory that appeared
// on the other side, and the receiving authority can only trust it or refuse
// it.
func TestATransferWithNobodyAccountableIsRefused(t *testing.T) {
	dir := exported(t)
	for name, rec := range map[string]marking.Transfer{
		"no approver": {Carried: "someone", Reason: "why"},
		"no carrier":  {Approved: "someone", Reason: "why"},
		"no reason":   {Approved: "someone", Carried: "someone"},
	} {
		if _, err := marking.RecordTransfer(dir, rec, time.Now()); err == nil {
			t.Errorf("%s: a manifest was written anyway", name)
		}
	}
}

// An arriving directory with no manifest at all says so plainly.
func TestADirectoryWithNoManifestIsNotATransfer(t *testing.T) {
	_, _, err := marking.VerifyTransfer(exported(t))
	if err == nil {
		t.Fatal("a directory with no manifest verified")
	}
	if !strings.Contains(err.Error(), "cannot be checked") {
		t.Errorf("the refusal does not explain: %v", err)
	}
}
