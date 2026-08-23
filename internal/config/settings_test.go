package config

import "testing"

// A crawl term is checked when it is set, not when the server starts.
//
// `quilzo config set licence.permits ai-training-with-attribution` used to
// report success, write the value, and leave a site whose public server refused
// to start — the vocabulary was enforced at boot and nowhere else. A command
// that says it worked and produces a server that will not run is worse than a
// refusal, which is the same reasoning that put the brand-colour check here.
func TestALicenceTermIsRefusedWhereItIsSet(t *testing.T) {
	for _, key := range []string{"licence.permits", "licence.prohibits"} {
		s, ok := Lookup(key)
		if !ok {
			t.Fatalf("%s is not a setting", key)
		}
		if err := s.Validate("ai-training-with-attribution"); err == nil {
			t.Errorf("%s accepted a use outside the vocabulary; the public "+
				"server will refuse to start on this value", key)
		}
		for _, good := range []string{"search", "search,train", "none",
			"search, ai-summarize", ""} {
			if err := s.Validate(good); err != nil {
				t.Errorf("%s refused %q, which is in the vocabulary: %v",
					key, good, err)
			}
		}
	}
}
