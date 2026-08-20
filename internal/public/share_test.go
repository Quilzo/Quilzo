package public

import (
	"strings"
	"testing"
)

// A share target whose form cannot be satisfied is refused at startup.
//
// The failure this catches is silent and late: a share carries at most a
// title, a text and a url, so a form with a required field none of those map
// onto refuses every share — weeks after the manifest was published, from
// somebody's phone, with no error anybody sees.
func TestAShareTargetThatCouldNeverWorkIsRefused(t *testing.T) {
	good := &ShareTarget{Form: "enquiry", TitleField: "subject", TextField: "body"}
	if err := good.Validate([]string{"subject"}); err != nil {
		t.Fatalf("a workable target was refused: %v", err)
	}

	// A required field no shared value reaches.
	err := good.Validate([]string{"subject", "email"})
	if err == nil {
		t.Fatal("a form requiring a field no share carries was accepted, so " +
			"every share would be refused at the phone")
	}
	if !strings.Contains(err.Error(), "email") {
		t.Errorf("the refusal does not name the unreachable field: %v", err)
	}

	// Mapping nothing means a share arrives empty.
	if err := (&ShareTarget{Form: "enquiry"}).Validate(nil); err == nil {
		t.Error("a target mapping none of title, text or url was accepted")
	}
	// And no form at all.
	if err := (&ShareTarget{}).Validate(nil); err == nil {
		t.Error("a target naming no form was accepted")
	}
}

// The manifest fragment is what makes the OS offer this in the share sheet.
//
// POST with multipart/form-data specifically: a GET share target puts whatever
// somebody shared into a query string, and therefore into every access log
// between them and here.
func TestTheManifestDeclaresAServerSideShare(t *testing.T) {
	st := &Site{Share: &ShareTarget{
		Form: "enquiry", TitleField: "subject", TextField: "body",
		URLField: "link"}}
	m := st.shareManifest()
	if m == nil {
		t.Fatal("no share_target produced for a configured target")
	}
	if m["method"] != "POST" {
		t.Errorf("method is %v; a GET share puts the shared text in a query "+
			"string and therefore in every access log on the way", m["method"])
	}
	if m["enctype"] != "multipart/form-data" {
		t.Errorf("enctype is %v, which is what selects the form POST a plain "+
			"server handler can read", m["enctype"])
	}
	if m["action"] != "/share" {
		t.Errorf("action is %v", m["action"])
	}
	params := m["params"].(map[string]any)
	for shared, want := range map[string]string{
		"title": "subject", "text": "body", "url": "link"} {
		if params[shared] != want {
			t.Errorf("%s maps to %v, want %q", shared, params[shared], want)
		}
	}

	// Nothing configured, nothing declared. A share_target pointing at a form
	// that does not exist is an entry in the OS share sheet that fails when
	// somebody picks it.
	if (&Site{}).shareManifest() != nil {
		t.Error("a site with no share target declared one anyway")
	}
	if (&Site{Share: &ShareTarget{Form: "enquiry"}}).shareManifest() != nil {
		t.Error("a target mapping no fields was declared in the manifest")
	}
}

// A shared value that is enormous is clamped rather than stored whole.
func TestSharedValuesAreBounded(t *testing.T) {
	long := strings.Repeat("x", maxShareField*3)
	if got := clampShare(long); len(got) != maxShareField {
		t.Errorf("a %d-character share came through at %d", len(long), len(got))
	}
	if got := clampShare("short"); got != "short" {
		t.Errorf("an ordinary value was altered: %q", got)
	}
}
