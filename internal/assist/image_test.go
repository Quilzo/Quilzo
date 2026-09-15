// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assist

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/fetch"
)

// painterAt builds a model pointed at a test endpoint.
//
// Keyless and on loopback, which is the arrangement the address rule permits:
// a model with no key has to be on this machine or this network, and a test
// server is.
func painterAt(t *testing.T, url string) *HTTPModel {
	t.Helper()
	t.Setenv("QUILZO_IMAGE_MODEL", "a-painter")
	return &HTTPModel{
		BaseURL: strings.TrimSuffix(url, "/") + "/v1",
		Model:   "a-writer",
		Client:  fetch.Speaking("assistant", fetch.OnThisNetwork, 10*time.Second),
	}
}

// The bytes are asked for, not a link.
func TestPaintAsksForTheBytes(t *testing.T) {
	var asked map[string]any
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&asked)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []any{map[string]any{
					"b64_json": base64.StdEncoding.EncodeToString([]byte("PNG-ish")),
				}},
			})
		}))
	defer srv.Close()

	pic, err := painterAt(t, srv.URL).Paint(
		context.Background(), "a brass pen", "512x512")
	if err != nil {
		t.Fatal(err)
	}
	if asked["response_format"] != "b64_json" {
		t.Errorf("it asked for %v", asked["response_format"])
	}
	if asked["model"] != "a-painter" {
		t.Errorf("it asked model %v; the image model is a separate setting "+
			"from the one that writes pages", asked["model"])
	}
	if asked["size"] != "512x512" {
		t.Errorf("it asked for size %v", asked["size"])
	}
	// The prompt and the model travel with the bytes, because both belong in
	// the provenance record and a caller that had to carry them is a caller
	// that will not.
	if pic.Prompt != "a brass pen" || pic.Model != "a-painter" {
		t.Errorf("the picture does not carry what made it: %+v", pic)
	}
	if string(pic.Body) != "PNG-ish" {
		t.Errorf("the bytes are %q", pic.Body)
	}
}

// A link in the reply is refused, and the address in it is never dialled.
//
// A URL in a model's reply is a host chosen by the model's output. Fetching it
// would mean this program making a request to an address a language model
// picked — and the rule a keyed endpoint is reached under is Anywhere, which
// permits link-local, which is where cloud metadata lives.
func TestALinkInTheReplyIsRefusedAndNeverFetched(t *testing.T) {
	var reached bool
	target := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			reached = true
			_, _ = w.Write([]byte("secrets"))
		}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": []any{map[string]any{"url": target.URL + "/creds"}},
			})
		}))
	defer srv.Close()

	_, err := painterAt(t, srv.URL).Paint(context.Background(), "anything", "")
	if err == nil {
		t.Fatal("a link was accepted")
	}
	if reached {
		t.Error("the address the model named was fetched")
	}
	if !strings.Contains(err.Error(), "b64_json") {
		t.Errorf("the refusal does not say which knob turns it into a yes: %v",
			err)
	}
}

// No image model configured is a refusal that names the setting.
//
// There is no name that is right across Ollama, a gateway and a hosted
// provider, and guessing one produces a request that fails at the far end with
// a message about the far end.
func TestPaintRefusesWithNoImageModel(t *testing.T) {
	t.Setenv("QUILZO_IMAGE_MODEL", "")
	h := &HTTPModel{BaseURL: "http://127.0.0.1:1/v1"}
	_, err := h.Paint(context.Background(), "anything", "")
	if err == nil {
		t.Fatal("it tried to paint with no model")
	}
	if !strings.Contains(err.Error(), "QUILZO_IMAGE_MODEL") {
		t.Errorf("the refusal does not name the setting: %v", err)
	}
}

// Nonsense in the reply is refused rather than stored.
func TestPaintRefusesAnUnusableReply(t *testing.T) {
	for name, reply := range map[string]string{
		"no data":      `{"data":[]}`,
		"empty entry":  `{"data":[{}]}`,
		"not base64":   `{"data":[{"b64_json":"!!! not base64 !!!"}]}`,
		"empty base64": `{"data":[{"b64_json":""}]}`,
		"not json":     `this is not json`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(reply))
			}))
		if _, err := painterAt(t, srv.URL).Paint(
			context.Background(), "anything", ""); err == nil {
			t.Errorf("%s was accepted", name)
		}
		srv.Close()
	}
}

// A size has one shape, because it goes into a request to somebody else.
func TestPaintChecksTheSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			t.Error("the request was made; the size was not checked")
		}))
	defer srv.Close()
	h := painterAt(t, srv.URL)
	for _, bad := range []string{"big", "1024", "1024x", "0x0", "-1x-1",
		"1024x1024; DROP", "999999x999999"} {
		if _, err := h.Paint(context.Background(), "anything", bad); err == nil {
			t.Errorf("%q was accepted as a size", bad)
		}
	}
}

// An empty instruction is refused before anything is asked.
func TestPaintNeedsSomethingToDraw(t *testing.T) {
	t.Setenv("QUILZO_IMAGE_MODEL", "a-painter")
	h := &HTTPModel{BaseURL: "http://127.0.0.1:1/v1"}
	if _, err := h.Paint(context.Background(), "   ", ""); err == nil {
		t.Error("an empty instruction was accepted")
	}
	if _, err := h.Paint(context.Background(),
		strings.Repeat("a", MaxInstruction+1), ""); err == nil {
		t.Error("an unbounded instruction was accepted")
	}
}
