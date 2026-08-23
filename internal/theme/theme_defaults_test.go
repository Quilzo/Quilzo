package theme

import "testing"

// Every value this program ships has to be a value it accepts.
//
// text-base ships as 1.0625rem and the length pattern allowed three decimal
// places, so the default was a value the tool refused: setting it back by hand
// was impossible, and the error said the shipped design was malformed.
//
// This walks the catalogue rather than listing cases, so a default added later
// with a shape nothing accepts fails here instead of in somebody's terminal.
func TestEveryShippedDefaultIsAValueTheToolAccepts(t *testing.T) {
	th, problems := New(map[string]string{}, nil)
	for _, p := range problems {
		t.Fatalf("the shipped theme did not load cleanly: %s", p.Detail)
	}
	for _, tok := range Tokens() {
		for scheme, value := range map[string]string{
			"light": tok.Light, "dark": tok.Dark,
		} {
			if value == "" {
				continue
			}
			if err := th.validate(tok, value); err != nil {
				t.Errorf("the %s default for %s is %q, which this tool refuses:"+
					"\n\t%v", scheme, tok.Name, value, err)
			}
		}
	}
}
