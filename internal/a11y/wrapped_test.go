package a11y

import "testing"

// A control inside its own label is labelled.
//
// This was reported as a blocking failure for as long as the rule existed. It
// is the standard markup for a checkbox — the HTML specification calls it
// implicit association — so the checker was telling authors to fix content
// that was already correct, on the strictest severity it has.
func TestAControlInsideItsLabelIsLabelled(t *testing.T) {
	page := `<!doctype html><html lang="en"><head><title>t</title></head><body>
	<h1>t</h1>
	<form>
	  <label>Find <input name="find"></label>
	  <label><input type="checkbox" name="deny"> Refuse instead of allow</label>
	  <label>Role <select name="role"><option>editor</option></select></label>
	  <label>Notes <textarea name="notes"></textarea></label>
	</form></body></html>`

	for _, f := range Check("wrapped", page).Findings {
		if f.Rule == "input-has-no-label" {
			t.Errorf("a wrapped control was reported unlabelled: %s", f.Detail)
		}
	}
}

// And a control outside one still is not.
//
// The pair matters: a fix that made the rule stop firing would also have made
// it stop working, and only one of the two tests would have caught that.
func TestAControlWithNoLabelAtAllIsStillReported(t *testing.T) {
	page := `<!doctype html><html lang="en"><head><title>t</title></head><body>
	<h1>t</h1><form><input name="value"></form></body></html>`

	found := false
	for _, f := range Check("bare", page).Findings {
		if f.Rule == "input-has-no-label" {
			found = true
		}
	}
	if !found {
		t.Error("an input with no label of any kind was not reported")
	}
}
