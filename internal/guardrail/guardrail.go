// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package guardrail asks an outside safety classifier about text, after
// Quilzo's own checks.
//
// Quilzo gates on structure: what an agent may do, what it read, whether a
// person must decide. It does not gate on a classifier's opinion, because a
// classifier is probabilistic and the gate must not be. But a classifier
// trained on far more attacks than a rule list will notice some a rule
// list does not, so one can be added as a second look: Lakera Guard (now
// Check Point's), Google Cloud's Model Armor, or a prompt-injection
// classifier served on this network, such as Llama Prompt Guard 2 behind a
// small HTTP wrapper.
//
// It fails open, and says so. A classifier that does not answer in time
// leaves the text as Quilzo's own checks left it, and the miss is counted,
// so an outage is a number somebody sees rather than an outage of the site.
package guardrail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Kinds of service.
const (
	Lakera     = "lakera"
	ModelArmor = "model-armor"
	Generic    = "generic"
)

// DefaultLakera is Lakera Guard's v2 endpoint.
const DefaultLakera = "https://api.lakera.ai/v2/guard"

// MaxText bounds what is sent in one request.
const MaxText = 16 << 10

// Post performs one request: the host's, with its address checks.
type Post func(ctx context.Context, url string, body []byte, headers map[string]string) (status int, reply []byte, err error)

// Service is one classifier.
type Service struct {
	Kind string
	URL  string
	// Key is the bearer credential: Lakera's API key, or an access token
	// for Model Armor. Never stored in the configuration.
	Key     string
	Timeout time.Duration
	Post    Post
}

// Check says whether the configuration can be used.
func (s Service) Check() error {
	switch s.Kind {
	case Lakera, ModelArmor, Generic:
	default:
		return fmt.Errorf("%q is not a guardrail: lakera, model-armor or generic", s.Kind)
	}
	if s.URL == "" && s.Kind != Lakera {
		return fmt.Errorf("a %s guardrail names its address", s.Kind)
	}
	if s.Post == nil {
		return errors.New("nothing to send requests with")
	}
	return nil
}

// ErrUnavailable is a classifier that did not answer usably.
var ErrUnavailable = errors.New("the guardrail did not answer")

// Flagged asks whether text is an attack. An error is ErrUnavailable, and
// the caller fails open.
func (s Service) Flagged(ctx context.Context, text string) (bool, error) {
	if err := s.Check(); err != nil {
		return false, err
	}
	if len(text) > MaxText {
		text = text[:MaxText]
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var req any
	url := s.URL
	switch s.Kind {
	case Lakera:
		if url == "" {
			url = DefaultLakera
		}
		req = map[string]any{"messages": []map[string]string{{"role": "user", "content": text}}}
	case ModelArmor:
		req = map[string]any{"userPromptData": map[string]string{"text": text}}
	default:
		req = map[string]string{"text": text}
	}
	body, _ := json.Marshal(req)
	headers := map[string]string{"Content-Type": "application/json", "Accept": "application/json"}
	if s.Key != "" {
		headers["Authorization"] = "Bearer " + s.Key
	}
	status, reply, err := s.Post(ctx, url, body, headers)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if status != 200 {
		return false, fmt.Errorf("%w: it answered %d", ErrUnavailable, status)
	}
	switch s.Kind {
	case ModelArmor:
		var r struct {
			SanitizationResult struct {
				FilterMatchState string `json:"filterMatchState"`
			} `json:"sanitizationResult"`
		}
		if json.Unmarshal(reply, &r) != nil || r.SanitizationResult.FilterMatchState == "" {
			return false, fmt.Errorf("%w: the answer could not be read", ErrUnavailable)
		}
		return strings.EqualFold(r.SanitizationResult.FilterMatchState, "MATCH_FOUND"), nil
	default:
		var r struct {
			Flagged *bool `json:"flagged"`
		}
		if json.Unmarshal(reply, &r) != nil || r.Flagged == nil {
			return false, fmt.Errorf("%w: the answer could not be read", ErrUnavailable)
		}
		return *r.Flagged, nil
	}
}

// Many asks about several texts, a few at a time, within a total budget,
// and says which were flagged; how many went unanswered is counted, and an
// unanswered one is not flagged.
func (s Service) Many(ctx context.Context, texts []string, budget time.Duration) (flagged []bool, unanswered int) {
	flagged = make([]bool, len(texts))
	if len(texts) == 0 {
		return flagged, 0
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	type result struct {
		i       int
		flagged bool
		err     error
	}
	work := make(chan int)
	results := make(chan result)
	const workers = 4
	for w := 0; w < workers; w++ {
		go func() {
			for i := range work {
				f, err := s.Flagged(ctx, texts[i])
				results <- result{i, f, err}
			}
		}()
	}
	go func() {
		for i := range texts {
			work <- i
		}
		close(work)
	}()
	for range texts {
		r := <-results
		if r.err != nil {
			unanswered++
			continue
		}
		flagged[r.i] = r.flagged
	}
	return flagged, unanswered
}
