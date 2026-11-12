// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package assist

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/quilzo/quilzo/internal/plaintext"
)

// Speech to text, from an endpoint that serves OpenAI's
// /audio/transcriptions: OpenAI, Groq, and the servers that run Whisper on
// this machine (whisper.cpp, faster-whisper, Speaches).
//
// The reply is asked for as WebVTT, timed, so it can become a video's
// captions; what comes back is checked to be WebVTT and nothing else is
// accepted. It is a draft: a model hears the words and not the door
// closing, nor who is speaking, which is what captions are for (WCAG
// 1.2.2). A person reads it and attaches it.

// MaxTranscribeBytes is the most a recording sent to be transcribed may be:
// OpenAI's own limit, and more than most endpoints take.
const MaxTranscribeBytes = 25 << 20

// MaxTranscript is the most of a transcript that is read.
const MaxTranscript = 4 << 20

var reAudioName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,120}\.(mp3|mp4|mpeg|mpga|m4a|ogg|oga|wav|webm|flac)$`)

// reLanguage is an ISO 639-1 code, which is what these endpoints take.
var reLanguage = regexp.MustCompile(`^[a-z]{2}$`)

// Transcribe asks for a recording's words, timed, as WebVTT. name is the
// recording's file name, whose extension tells the endpoint its format;
// lang, when given, is the language it is spoken in.
func (h *HTTPModel) Transcribe(ctx context.Context, audio []byte, name, lang string) (string, Usage, error) {
	if h.Wire == WireAnthropic {
		return "", Usage{}, fmt.Errorf("%s answers in words and does not transcribe", h.Model)
	}
	if len(audio) == 0 || len(audio) > MaxTranscribeBytes {
		return "", Usage{}, fmt.Errorf("a recording sent to be transcribed is at most %d MB", MaxTranscribeBytes>>20)
	}
	if !reAudioName.MatchString(name) {
		return "", Usage{}, fmt.Errorf("%q is not a recording's file name this sends", name)
	}
	if lang != "" && !reLanguage.MatchString(lang) {
		return "", Usage{}, fmt.Errorf("%q is not a two-letter language code, like en or fr", lang)
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fields := [][2]string{{"model", h.Model}, {"response_format", "vtt"}}
	if lang != "" {
		fields = append(fields, [2]string{"language", lang})
	}
	for _, f := range fields {
		if err := mw.WriteField(f[0], f[1]); err != nil {
			return "", Usage{}, err
		}
	}
	part, err := mw.CreateFormFile("file", filepath.Base(name))
	if err != nil {
		return "", Usage{}, err
	}
	if _, err := part.Write(audio); err != nil {
		return "", Usage{}, err
	}
	if err := mw.Close(); err != nil {
		return "", Usage{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.BaseURL+"/audio/transcriptions", &body)
	if err != nil {
		return "", Usage{}, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if err := h.prepare(req); err != nil {
		return "", Usage{}, err
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return "", Usage{}, fmt.Errorf("transcription request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(io.LimitReader(resp.Body, 4<<10))
		return "", Usage{}, &StatusError{Code: resp.StatusCode, Body: plaintext.Clip(strings.TrimSpace(buf.String()), 300, "")}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxTranscript+1))
	if err != nil {
		return "", Usage{}, fmt.Errorf("cannot read the transcript: %w", err)
	}
	if len(raw) > MaxTranscript {
		return "", Usage{}, errors.New("the transcript is longer than any recording sent could make")
	}
	vtt := strings.TrimPrefix(string(raw), "\uFEFF")
	if !strings.HasPrefix(vtt, "WEBVTT") {
		return "", Usage{}, errors.New("the endpoint did not answer with WebVTT: it may not honour " +
			"response_format=vtt, which captions need")
	}
	return vtt, Usage{Out: (len(vtt) + 3) / 4}, nil
}
