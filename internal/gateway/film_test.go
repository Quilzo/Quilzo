// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// A route that makes video names a provider that does, takes none of a
// conversation's parameters, does nothing else, and only it may have a
// price for a video.
func TestAVideoRouteIsOnlyThat(t *testing.T) {
	r := Route{Name: "veo", Model: "veo-x", Films: true}
	if err := r.CheckWire(WireVeo); err != nil {
		t.Fatal(err)
	}
	if err := r.CheckWire(WireOpenAI); err == nil {
		t.Error("a chat wire made video")
	}
	if err := (Route{Name: "veo", Model: "veo-x"}).CheckWire(WireFalQueue); err == nil {
		t.Error("a video wire used for words")
	}
	hot := 0.7
	r.Params.Temperature = &hot
	if err := r.CheckWire(WireVeo); err == nil {
		t.Error("a temperature on a video")
	}
	c := Config{Currency: "USD", Routes: []Route{{Name: "v", URL: "https://x.example/v1", Model: "m", Films: true, Speaks: true}}}
	if err := c.Validate(); err == nil {
		t.Error("a route that makes video and speaks")
	}
	c = Config{Currency: "USD", Routes: []Route{{Name: "v", URL: "https://x.example/v1", Model: "m", PriceVideo: "0.5"}}}
	if err := c.Validate(); err == nil {
		t.Error("a price for a video on a route that makes none")
	}
}
