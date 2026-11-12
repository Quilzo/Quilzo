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
	"net/url"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/plaintext"
)

// Video from a prompt, by the two asynchronous shapes the providers serve
// it in:
//
//   - Google's Veo through the Gemini API (WireVeo): models/MODEL:
//     predictLongRunning starts it, the operation it names is asked after
//     until it is done, and the video is fetched from the address in the
//     answer, with the key.
//   - fal's queue (WireFalQueue): queue.fal.run/MODEL takes the request
//     and names where to ask after it and where its answer will be; the
//     answer names the video, on fal's own storage, fetched without the
//     key.
//
// What comes back is checked to be an MP4, and the caller stores it marked
// as generated. A key never follows a redirect to another host, and every
// address an answer names is https on the provider's host, or for the
// finished file, https anywhere but this network.

// The protocols that make video.
const (
	WireVeo      = "google-veo"
	WireFalQueue = "fal-queue"
)

// MaxFilm is the most video read back.
const MaxFilm = 256 << 20

// FilmWait is how long a video is waited for: the providers say minutes.
var FilmWait = 10 * time.Minute

// filmPoll is how often an unfinished video is asked after.
var filmPoll = 10 * time.Second

// Aspects are the shapes a video may be asked for.
var Aspects = []string{"16:9", "9:16"}

// Film asks for a video of the prompt, in the shape asked for.
func (h *HTTPModel) Film(ctx context.Context, prompt, aspect string) ([]byte, Usage, error) {
	prompt = strings.TrimSpace(prompt)
	if prompt == "" || len(prompt) > 4000 {
		return nil, Usage{}, errors.New("a video is asked for in 1 to 4,000 characters")
	}
	if aspect == "" {
		aspect = "16:9"
	}
	if aspect != "16:9" && aspect != "9:16" {
		return nil, Usage{}, fmt.Errorf("%q is not a shape: 16:9 or 9:16", aspect)
	}
	ctx, cancel := context.WithTimeout(ctx, FilmWait)
	defer cancel()
	var (
		video []byte
		err   error
	)
	switch h.Wire {
	case WireVeo:
		video, err = h.veo(ctx, prompt, aspect)
	case WireFalQueue:
		video, err = h.fal(ctx, prompt, aspect)
	default:
		return nil, Usage{}, fmt.Errorf("%s does not make video: a route that makes video names a provider that does", h.Model)
	}
	if err != nil {
		return nil, Usage{}, err
	}
	if len(video) < 12 || string(video[4:8]) != "ftyp" {
		return nil, Usage{}, errors.New("what came back is not an MP4 video")
	}
	return video, Usage{In: (len(prompt) + 3) / 4}, nil
}

// keyless is a client that drops the key and the profile's headers on a
// redirect to another host, and follows only https.
func (h *HTTPModel) keyless() *http.Client {
	c := *h.Client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("a redirect away from https")
		}
		if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
			req.Header.Del("Authorization")
			if name, ok := strings.CutPrefix(h.Auth, "header:"); ok {
				req.Header.Del(name)
			}
			for k := range h.Headers {
				req.Header.Del(k)
			}
		}
		return nil
	}
	return &c
}

// do sends one request and reads its answer, bounded. Only the fetch of a
// finished file follows a redirect (a provider's file links do redirect);
// a call to the API itself does not, as no model call does.
func (h *HTTPModel) do(ctx context.Context, method, u string, body any, keyed bool, max int64) ([]byte, error) {
	return h.doFollowing(ctx, method, u, body, keyed, max, false)
}

func (h *HTTPModel) fetchFile(ctx context.Context, u string, keyed bool) ([]byte, error) {
	return h.doFollowing(ctx, http.MethodGet, u, nil, keyed, MaxFilm, true)
}

func (h *HTTPModel) doFollowing(ctx context.Context, method, u string, body any, keyed bool, max int64, follow bool) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := h.Client
	if follow {
		client = h.keyless()
	}
	if keyed {
		if err := h.prepare(req); err != nil {
			return nil, err
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(io.LimitReader(resp.Body, 4<<10))
		return nil, &StatusError{Code: resp.StatusCode, Body: plaintext.Clip(strings.TrimSpace(buf.String()), 300, "")}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("the answer is larger than one can be")
	}
	return b, nil
}

// onHost reports whether an address an answer names is https on the
// route's own host.
func (h *HTTPModel) onHost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	base, err := url.Parse(h.BaseURL)
	return err == nil && strings.EqualFold(u.Host, base.Host)
}

func (h *HTTPModel) wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("the video was not ready within %s", FilmWait)
	case <-time.After(filmPoll):
		return nil
	}
}

func (h *HTTPModel) veo(ctx context.Context, prompt, aspect string) ([]byte, error) {
	start := map[string]any{"instances": []any{map[string]any{"prompt": prompt}},
		"parameters": map[string]any{"aspectRatio": aspect}}
	b, err := h.do(ctx, http.MethodPost, h.BaseURL+"/models/"+url.PathEscape(h.Model)+":predictLongRunning", start, true, 64<<10)
	if err != nil {
		return nil, fmt.Errorf("starting the video: %w", err)
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(b, &op) != nil || op.Name == "" || strings.Contains(op.Name, "..") || strings.ContainsAny(op.Name, "?#") {
		return nil, errors.New("the provider started the video and named no operation to ask after")
	}
	for {
		b, err = h.do(ctx, http.MethodGet, h.BaseURL+"/"+op.Name, nil, true, 1<<20)
		if err != nil {
			return nil, fmt.Errorf("asking after the video: %w", err)
		}
		var st struct {
			Done  bool `json:"done"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
			Response struct {
				GenerateVideoResponse struct {
					GeneratedSamples []struct {
						Video struct {
							URI string `json:"uri"`
						} `json:"video"`
					} `json:"generatedSamples"`
					RaiFilteredReasons []string `json:"raiMediaFilteredReasons"`
				} `json:"generateVideoResponse"`
			} `json:"response"`
		}
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, errors.New("the provider's answer about the video is not one this can read")
		}
		if st.Error != nil {
			return nil, fmt.Errorf("the provider did not make the video: %s", plaintext.Clip(st.Error.Message, 300, ""))
		}
		if !st.Done {
			if err := h.wait(ctx); err != nil {
				return nil, err
			}
			continue
		}
		g := st.Response.GenerateVideoResponse
		if len(g.GeneratedSamples) == 0 {
			if len(g.RaiFilteredReasons) > 0 {
				return nil, &Declined{Model: h.Model, Category: plaintext.Clip(strings.Join(g.RaiFilteredReasons, "; "), 300, "")}
			}
			return nil, errors.New("the provider finished and made no video")
		}
		uri := g.GeneratedSamples[0].Video.URI
		if !h.onHost(uri) {
			return nil, fmt.Errorf("the video is at %q, which is not https on the provider's host", plaintext.Clip(uri, 300, ""))
		}
		return h.fetchFile(ctx, uri, true)
	}
}

func (h *HTTPModel) fal(ctx context.Context, prompt, aspect string) ([]byte, error) {
	b, err := h.do(ctx, http.MethodPost, h.BaseURL+"/"+strings.TrimPrefix(h.Model, "/"),
		map[string]any{"prompt": prompt, "aspect_ratio": aspect}, true, 64<<10)
	if err != nil {
		return nil, fmt.Errorf("starting the video: %w", err)
	}
	var q struct {
		ID       string `json:"request_id"`
		Status   string `json:"status_url"`
		Response string `json:"response_url"`
	}
	if json.Unmarshal(b, &q) != nil || q.ID == "" || !h.onHost(q.Status) || !h.onHost(q.Response) {
		return nil, errors.New("the queue took the request and named nowhere on its own host to ask after it")
	}
	for {
		b, err = h.do(ctx, http.MethodGet, q.Status, nil, true, 64<<10)
		if err != nil {
			return nil, fmt.Errorf("asking after the video: %w", err)
		}
		var st struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, errors.New("the queue's answer about the video is not one this can read")
		}
		if st.Error != "" {
			return nil, fmt.Errorf("the provider did not make the video: %s", plaintext.Clip(st.Error, 300, ""))
		}
		if st.Status == "COMPLETED" {
			break
		}
		if st.Status != "IN_QUEUE" && st.Status != "IN_PROGRESS" {
			return nil, fmt.Errorf("the queue says %q", plaintext.Clip(st.Status, 300, ""))
		}
		if err := h.wait(ctx); err != nil {
			return nil, err
		}
	}
	b, err = h.do(ctx, http.MethodGet, q.Response, nil, true, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("reading the finished video's answer: %w", err)
	}
	var out struct {
		Video struct {
			URL string `json:"url"`
		} `json:"video"`
	}
	if json.Unmarshal(b, &out) != nil || out.Video.URL == "" {
		return nil, errors.New("the finished answer names no video")
	}
	u, err := url.Parse(out.Video.URL)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return nil, fmt.Errorf("the video is at %q, which is not https", plaintext.Clip(out.Video.URL, 300, ""))
	}
	// On fal's storage, a public address: fetched without the key, by the
	// checked client, which refuses this network.
	return h.fetchFile(ctx, out.Video.URL, false)
}
