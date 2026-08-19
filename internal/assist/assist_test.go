package assist

import (
	"strings"
	"testing"
)

// A model on this machine needs no key; a hosted one does.
//
// Requiring a key refused the arrangement that costs nothing: Ollama,
// llama.cpp, LM Studio and vLLM all serve this protocol and none of them wants
// one. Keyless against a public endpoint stays refused, because that is not a
// cheaper deployment — it is an operator who believes they are authenticated
// and is not.
func TestALocalModelNeedsNoKey(t *testing.T) {
	for _, tc := range []struct {
		url   string
		local bool
	}{
		{"http://127.0.0.1:11434/v1", true},   // Ollama's default
		{"http://localhost:8080/v1", true},    // llama.cpp
		{"http://[::1]:1234/v1", true},        // LM Studio over v6
		{"http://192.168.1.50:8000/v1", true}, // a box on the LAN
		{"https://api.openai.com/v1", false},
		{"https://ollama.com/v1", false},
		{"not a url", false},
		{"", false},
	} {
		got, why := isLocalEndpoint(tc.url)
		if got != tc.local {
			t.Errorf("%q: local=%v want %v (%s)", tc.url, got, tc.local, why)
		}
		if !got && why == "" {
			t.Errorf("%q was refused without saying why", tc.url)
		}
	}
}

// An unresolvable host is not local.
//
// An endpoint nobody can reach is a misconfiguration either way, and guessing
// permissively would let a typo become a keyless call to whatever the name
// eventually resolves to.
func TestAnUnresolvableEndpointIsNotLocal(t *testing.T) {
	got, why := isLocalEndpoint("http://this-host-does-not-exist.invalid/v1")
	if got {
		t.Error("an unresolvable host was treated as local")
	}
	if why == "" {
		t.Error("the refusal says nothing")
	}
}

// The end-to-end decision: a keyless local endpoint builds, a keyless public
// one does not.
func TestKeylessConfigurationIsAcceptedOnlyForALocalModel(t *testing.T) {
	t.Setenv("QUILZO_MODEL_KEY", "")
	t.Setenv("OLLAMA_API_KEY", "")

	t.Setenv("QUILZO_MODEL_URL", "http://127.0.0.1:11434/v1")
	if _, err := NewHTTPModel(); err != nil {
		t.Errorf("a keyless local model was refused: %v", err)
	}

	t.Setenv("QUILZO_MODEL_URL", "https://api.openai.com/v1")
	err := NewHTTPModel2Err()
	if err == nil {
		t.Fatal("a keyless public endpoint was accepted; the operator would " +
			"believe they were authenticated and would not be")
	}
	if !strings.Contains(err.Error(), "local") {
		t.Errorf("the refusal does not point at the local option: %v", err)
	}
}

// NewHTTPModel2Err is NewHTTPModel's error, named so the test above reads as
// one assertion per line.
func NewHTTPModel2Err() error { _, err := NewHTTPModel(); return err }
