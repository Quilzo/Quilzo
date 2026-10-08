// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package assistant

import (
	"context"
	"fmt"
	"strings"
)

// Measuring an assistant before a visitor does.
//
// The question an owner cannot answer by trying it a few times: how often it
// finds the right page, how often what it says is supported, and — the one
// every chatbot product skips — how often it correctly says it does not know.
// A test set that only contains answerable questions rewards an assistant
// that always answers, which is the opposite of what a site wants.

// Case is one question with what a correct assistant does with it.
type Case struct {
	Question string `json:"question"`
	// Page is where the answer lives. Empty means the site does not answer
	// this, and the correct response is to say so.
	Page string `json:"page,omitempty"`
	// Contains are words the answer must include, when the case cares.
	Contains []string `json:"contains,omitempty"`
}

// Result is how a set of cases went.
type Result struct {
	Cases int `json:"cases"`
	// Answerable and Unanswerable split the set, because the two rates below
	// are over different halves of it.
	Answerable   int `json:"answerable"`
	Unanswerable int `json:"unanswerable"`
	// HitAt1 and HitAtK are how often the right page was the first passage
	// retrieved, and anywhere in what was retrieved.
	HitAt1 int `json:"hit_at_1"`
	HitAtK int `json:"hit_at_k"`
	// MRR is mean reciprocal rank of the right page.
	MRR float64 `json:"mrr"`
	// Answered is answerable cases it answered; Refused unanswerable ones it
	// refused. Hallucinated is unanswerable cases it answered anyway — the
	// number that matters most.
	Answered     int `json:"answered"`
	Refused      int `json:"refused"`
	Hallucinated int `json:"hallucinated"`
	// WrongRefusal is answerable cases it refused.
	WrongRefusal int `json:"wrong_refusal"`
	// Missing is answers without a required word.
	Missing int `json:"missing"`
	// Dropped counts sentences removed by verification, across all answers.
	Dropped  int      `json:"dropped"`
	Failures []string `json:"failures,omitempty"`
}

// Evaluate runs every case.
func Evaluate(ctx context.Context, a Assistant, idx *Index, m Model,
	cases []Case) (Result, error) {

	var r Result
	var rr float64
	for _, c := range cases {
		r.Cases++
		ans, err := Respond(ctx, a, idx, m, c.Question)
		if err != nil {
			return r, fmt.Errorf("%q: %w", c.Question, err)
		}
		r.Dropped += len(ans.Dropped)
		if c.Page == "" {
			r.Unanswerable++
			if ans.Refused {
				r.Refused++
			} else {
				r.Hallucinated++
				r.Failures = append(r.Failures, fmt.Sprintf(
					"answered %q, which the site does not answer: %s",
					c.Question, ans.Text))
			}
			continue
		}
		r.Answerable++
		for i, h := range ans.Sources {
			if h.Page == c.Page {
				if i == 0 {
					r.HitAt1++
				}
				r.HitAtK++
				rr += 1 / float64(i+1)
				break
			}
		}
		if ans.Refused {
			r.WrongRefusal++
			r.Failures = append(r.Failures, fmt.Sprintf(
				"refused %q, which %s answers", c.Question, c.Page))
			continue
		}
		r.Answered++
		for _, w := range c.Contains {
			if !strings.Contains(strings.ToLower(ans.Text), strings.ToLower(w)) {
				r.Missing++
				r.Failures = append(r.Failures, fmt.Sprintf(
					"%q: the answer does not mention %q: %s", c.Question, w,
					ans.Text))
				break
			}
		}
	}
	if r.Answerable > 0 {
		r.MRR = rr / float64(r.Answerable)
	}
	return r, nil
}
