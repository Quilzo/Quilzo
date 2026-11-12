// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/quilzo/quilzo/internal/plaintext"
)

// Text to speech, from an endpoint that serves OpenAI's /audio/speech:
// OpenAI, and the servers that run a voice on this machine (Kokoro,
// Piper and others behind Speaches or openedai-speech).
//
// What comes back is asked for as MP3 and checked to be one; the caller
// stores it marked as a synthetic voice, which is what EU AI Act Article
// 50 asks of it.

// MaxSpeech is the most text one request speaks: OpenAI's own limit.
const MaxSpeech = 4096

// MaxSpoken is the most audio that is read back.
const MaxSpoken = 32 << 20

var reVoice = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,47}$`)

// Speak asks for text read aloud, as MP3, in the voice named.
func (h *HTTPModel) Speak(ctx context.Context, text, voice string) ([]byte, Usage, error) {
	if h.Wire == WireAnthropic {
		return nil, Usage{}, fmt.Errorf("%s answers in words and does not speak", h.Model)
	}
	if strings.TrimSpace(text) == "" || len(text) > MaxSpeech {
		return nil, Usage{}, fmt.Errorf("what is spoken is 1 to %d characters", MaxSpeech)
	}
	if !reVoice.MatchString(voice) {
		return nil, Usage{}, fmt.Errorf("%q is not a voice's name", voice)
	}
	b, err := json.Marshal(map[string]any{"model": h.Model, "input": text, "voice": voice, "response_format": "mp3"})
	if err != nil {
		return nil, Usage{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.BaseURL+"/audio/speech", bytes.NewReader(b))
	if err != nil {
		return nil, Usage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := h.prepare(req); err != nil {
		return nil, Usage{}, err
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, Usage{}, fmt.Errorf("speech request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(io.LimitReader(resp.Body, 4<<10))
		return nil, Usage{}, &StatusError{Code: resp.StatusCode, Body: plaintext.Clip(strings.TrimSpace(buf.String()), 300, "")}
	}
	audio, err := io.ReadAll(io.LimitReader(resp.Body, MaxSpoken+1))
	if err != nil {
		return nil, Usage{}, fmt.Errorf("cannot read the speech: %w", err)
	}
	if len(audio) > MaxSpoken {
		return nil, Usage{}, errors.New("the speech is longer than any text sent could make")
	}
	mp3 := bytes.HasPrefix(audio, []byte("ID3")) ||
		(len(audio) > 1 && audio[0] == 0xFF && audio[1]&0xE0 == 0xE0)
	if !mp3 {
		return nil, Usage{}, errors.New("the endpoint did not answer with MP3, which this asked for")
	}
	return audio, Usage{In: (len(text) + 3) / 4}, nil
}
