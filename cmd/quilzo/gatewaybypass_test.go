// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/gateway"
)

// A picture is drawn through the gateway's route that draws, with what may
// not leave taken out of its prompt, and the drawing is in the ledger
// under media; the writing assistant goes through the gateway too.
func TestPicturesAndWritingGoThroughTheGateway(t *testing.T) {
	root := demoStore(t)
	png := smallPNG(t)
	asked := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
		asked <- body["prompt"].(string)
		json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{
			"b64_json": base64.StdEncoding.EncodeToString(png)}}})
	}))
	defer srv.Close()
	// The configured model is not used: nothing listens there.
	t.Setenv("QUILZO_MODEL_URL", "http://127.0.0.1:9/v1")
	cfg := &gateway.Config{Routes: []gateway.Route{
		{Name: "words", URL: "http://127.0.0.1:9/v1", Model: "m"},
		{Name: "pictures", URL: srv.URL + "/v1", Model: "a-painter", Draws: true},
	}}
	if err := gateway.Save(gatewayPath(root), cfg); err != nil {
		t.Fatal(err)
	}
	if err := cmdMedia(root, []string{"generate", "a brass pen on a desk, for dana@hartsbakery.co.uk",
		"--alt", "A brass pen on an oak desk", "--author", "dana"}); err != nil {
		t.Fatal(err)
	}
	if p := <-asked; strings.Contains(p, "dana@hartsbakery.co.uk") {
		t.Fatalf("the prompt left with an address: %q", p)
	}
	b, _ := os.ReadFile(usagePath(root))
	if !strings.Contains(string(b), `"consumer":"media"`) || !strings.Contains(string(b), `"route":"pictures"`) {
		t.Fatalf("the picture is not in the ledger: %s", b)
	}

	m, err := assistModel(root, "dana")
	if err != nil || m.Name() != "gateway:assist" {
		t.Fatalf("the assistant does not go through the gateway: %v %v", m, err)
	}
}
