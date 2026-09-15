// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assist

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// Asking a model for a picture.
//
// # Why this is the same client
//
// The endpoint is the one the operator already named, reached through the same
// guarded client with the same address rule: a keyless model must be on this
// machine or this network, a keyed one may be anywhere because saying so is
// what supplying a key means. None of that reasoning changes because the reply
// is pixels instead of words.
//
// # Why a link in the reply is refused
//
// The OpenAI-shaped image API can answer with base64 or with a URL. This asks
// for base64 and refuses the URL, and the refusal is the interesting half.
//
// A URL in the reply is a host chosen by the model's output. Fetching it would
// mean this program making a request to an address a language model picked,
// which is the textbook shape of the vulnerability internal/webhook opens by
// naming: "a webhook is an SSRF primitive with a friendly name". Worse, the
// rule the model endpoint is reached under is Anywhere for a keyed provider —
// deliberately, because the operator named that host — and Anywhere permits
// link-local, which is where cloud metadata lives. Handing that rule to an
// address the reply chose would hand a prompt-injected model the credentials
// of the machine it runs on.
//
// So the answer is no, and it says which knob turns it into a yes.
// response_format is part of the API every implementation of it supports, and
// an endpoint that ignores it is one this program cannot safely use.

// A Picture is what a model returned, before anything has been decided about
// whether it is acceptable.
type Picture struct {
	// Body is the encoded image, exactly as it arrived.
	Body []byte
	// Prompt is what was asked for, and Model is what answered. Both travel
	// with the bytes because both belong in the provenance record, and a
	// caller that had to remember to carry them is a caller that will not.
	Prompt string
	Model  string
}

// reSize matches the one shape a size may be written in.
var reSize = regexp.MustCompile(`^[1-9][0-9]{1,4}x[1-9][0-9]{1,4}$`)

// ImageModel is which model makes pictures.
//
// Separate from QUILZO_MODEL, because the model that writes a page and the
// model that draws a picture are almost never the same one and a single
// setting would make configuring either of them break the other.
//
// No default. There is no name that is right across Ollama, a gateway and a
// hosted provider, and guessing one produces a request that fails at the far
// end with a message about the far end rather than about the configuration.
func ImageModel() string { return strings.TrimSpace(os.Getenv("QUILZO_IMAGE_MODEL")) }

// Paint asks for one picture.
func (h *HTTPModel) Paint(ctx context.Context, prompt, size string) (Picture, error) {
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return Picture{}, fmt.Errorf("a picture needs something to be asked for")
	}
	if len(prompt) > MaxInstruction {
		return Picture{}, fmt.Errorf(
			"that instruction is %d characters and the limit is %d",
			len(prompt), MaxInstruction)
	}
	size = strings.TrimSpace(size)
	if size == "" {
		size = "1024x1024"
	}
	if !reSize.MatchString(size) {
		return Picture{}, fmt.Errorf(
			"%q is not a size; they are written like 1024x1024", size)
	}
	model := ImageModel()
	if model == "" {
		return Picture{}, fmt.Errorf(
			"no image model is configured. Set QUILZO_IMAGE_MODEL to the one " +
				"this endpoint serves — there is no name that is right for " +
				"every provider, and guessing one fails at the far end with a " +
				"message about the far end")
	}

	payload := map[string]any{
		"model": model, "prompt": prompt, "n": 1, "size": size,
		// The bytes, not a link. See the note at the top of this file.
		"response_format": "b64_json",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Picture{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		h.BaseURL+"/images/generations", bytes.NewReader(body))
	if err != nil {
		return Picture{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+h.APIKey)
	}

	resp, err := h.Client.Do(req)
	if err != nil {
		return Picture{}, fmt.Errorf("the image request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(io.LimitReader(resp.Body, 4096))
		snippet := strings.TrimSpace(buf.String())
		if len(snippet) > 300 {
			snippet = snippet[:300]
		}
		return Picture{}, fmt.Errorf("the model returned %d: %s",
			resp.StatusCode, snippet)
	}

	var out struct {
		Data []struct {
			B64 string `json:"b64_json"`
			URL string `json:"url"`
		} `json:"data"`
	}
	// Bounded, because this is a body from elsewhere and a base64 image is
	// large enough that "large" is not by itself a reason to stop reading.
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxImageReply)).
		Decode(&out); err != nil {
		return Picture{}, fmt.Errorf("cannot read the model's reply: %w", err)
	}
	if len(out.Data) == 0 {
		return Picture{}, fmt.Errorf("the model returned no picture")
	}
	if out.Data[0].B64 == "" {
		if out.Data[0].URL != "" {
			return Picture{}, fmt.Errorf(
				"this endpoint answered with a link rather than the picture, " +
					"and a link in a model's reply is an address the model " +
					"chose. Fetching it would mean this program making a " +
					"request to a host a language model named. Ask the " +
					"provider for response_format=b64_json, or use one that " +
					"honours it")
		}
		return Picture{}, fmt.Errorf("the model's reply carries no image data")
	}
	raw, err := base64.StdEncoding.DecodeString(out.Data[0].B64)
	if err != nil {
		return Picture{}, fmt.Errorf(
			"the model's reply is not the base64 it was asked for: %w", err)
	}
	if len(raw) == 0 {
		return Picture{}, fmt.Errorf("the model returned an empty picture")
	}
	return Picture{Body: raw, Prompt: prompt, Model: model}, nil
}

// MaxImageReply bounds a reply carrying a base64 picture.
//
// Base64 is a third larger than the bytes it carries, and internal/media
// refuses an image over 24 MiB anyway — so anything past this is either a
// reply that will be refused later or a server sending something that is not
// a picture.
const MaxImageReply = 48 << 20

// MaxInstruction bounds what may be asked for.
const MaxInstruction = 4000
