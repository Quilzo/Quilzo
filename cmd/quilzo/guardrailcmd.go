// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/guardrail"
)

// The outside classifier asked after Quilzo's own checks. See
// internal/guardrail.

// guardrailService is the configured guardrail, or nil when none is set.
// Its key is QUILZO_GUARDRAIL_KEY; without one it must be on this network,
// as a keyless model must, and a key is sent only over https.
func guardrailService(root string) (*guardrail.Service, error) {
	cfg := mustConfig(root)
	kind := strings.TrimSpace(cfg.Raw("guardrail.kind"))
	if kind == "" {
		return nil, nil
	}
	key := os.Getenv("QUILZO_GUARDRAIL_KEY")
	address := strings.TrimSpace(cfg.Raw("guardrail.url"))
	if address == "" && kind == guardrail.Lakera {
		address = guardrail.DefaultLakera
	}
	if u, err := url.Parse(address); err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("guardrail.url %q is not an address", address)
	} else if key != "" && u.Scheme != "https" {
		return nil, errors.New("a guardrail's key is sent only over https")
	}
	reach := fetch.Anywhere
	if key == "" {
		reach = fetch.OnThisNetwork
	}
	client := fetch.Speaking("guardrail", reach, 5*time.Second)
	s := &guardrail.Service{Kind: kind, URL: address, Key: key, Timeout: 3 * time.Second,
		Post: func(ctx context.Context, target string, body []byte, headers map[string]string) (int, []byte, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
			if err != nil {
				return 0, nil, err
			}
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			res, err := client.Do(req)
			if err != nil {
				return 0, nil, err
			}
			defer res.Body.Close()
			b, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
			return res.StatusCode, b, err
		}}
	if err := s.Check(); err != nil {
		return nil, err
	}
	return s, nil
}

// guardrailHooks are the public site's: the classifier, and a record of
// what it flagged or did not answer, counts only.
func guardrailHooks(root string) (func(context.Context, []string) ([]bool, int), func(name, what string, n int), error) {
	s, err := guardrailService(root)
	if err != nil || s == nil {
		return nil, nil, err
	}
	ask := func(ctx context.Context, texts []string) ([]bool, int) {
		deadline, ok := ctx.Deadline()
		budget := 30 * time.Second
		if ok {
			budget = time.Until(deadline)
		}
		return s.Many(ctx, texts, budget)
	}
	tell := func(name, what string, n int) {
		record(root, audit.Record{Action: "guardrail." + what, Resource: "/assistants/" + name, Outcome: audit.Success,
			Principal: "quilzo", Kind: audit.KindService, Verified: true,
			Detail: map[string]string{"chatbot": name, "guardrail": s.Kind, "count": fmt.Sprint(n)}})
	}
	return ask, tell, nil
}
