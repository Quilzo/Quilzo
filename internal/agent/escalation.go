// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Escalations have a destination.
//
// Two things stop a run because a check says a person must decide: a
// decider whose answer is less sure than its declaration demands, and the
// reviewer refusing an action. Each becomes the run's question, kept with
// the run and answered from its record like any other.
//
// A decider's escalation is a typed question: the person answers what the
// decider was asked, in the shape it was asked in, with the model's guess
// and how sure it was beside it, and the run continues with the person's
// answer as the decider's. A reviewer's refusal is a hold on the exact
// action: letting it through performs that action, as asking first does,
// and declining tells the model.

// Pending kinds, for what a run is waiting on.
const (
	// WaitAsk is an action the declaration or a check asks about first.
	WaitAsk = ""
	// WaitQuestion is a decider's question a person answers instead.
	WaitQuestion = "question"
	// WaitReview is an action the reviewer refused, for a person to let
	// through or not.
	WaitReview = "review"
)

// Question is one typed question a person answers instead of a decider.
type Question struct {
	Decider string `json:"decider"`
	Name    string `json:"name"`
	Ask     string `json:"ask"`
	// Kind is choice, yesno or score (a number from 0 to 1).
	Kind    string   `json:"kind"`
	Options []string `json:"options,omitempty"`
	// Guess is the model's answer, shown to the person and not taken.
	Guess string `json:"guess,omitempty"`
	// Confidence is how sure the model was, and Threshold how sure the
	// decider's declaration demands.
	Confidence float64 `json:"confidence"`
	Threshold  float64 `json:"threshold"`
}

// Escalation is an action's way of saying that a person decides before the
// run goes on: a decider that was not sure enough.
type Escalation struct {
	Why       string
	Questions []Question
}

func (e *Escalation) Error() string { return e.Why }

// Held is a decision a check stopped, for a person to let through: the
// reviewer's refusal of an action the model chose.
type Held struct {
	Action Action
	Why    string
}

func (h *Held) Error() string { return h.Why }

// AnswerQuestions checks a person's answers against the questions asked:
// every question answered, each in its own shape. It returns them as the
// text the run continues with.
func AnswerQuestions(qs []Question, answers map[string]string) (string, error) {
	var lines []string
	for _, q := range qs {
		v := strings.TrimSpace(answers[q.Name])
		if v == "" {
			return "", fmt.Errorf("%s is not answered", q.Name)
		}
		switch q.Kind {
		case "choice":
			ok := false
			for _, o := range q.Options {
				ok = ok || o == v
			}
			if !ok {
				return "", fmt.Errorf("%q is not one of the options for %s (%s)", v, q.Name, strings.Join(q.Options, ", "))
			}
		case "yesno":
			v = strings.ToLower(v)
			if v != "yes" && v != "no" {
				return "", fmt.Errorf("%s is answered yes or no", q.Name)
			}
		case "score":
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || f < 0 || f > 1 {
				return "", fmt.Errorf("%s is answered with a number from 0 to 1", q.Name)
			}
			v = strconv.FormatFloat(f, 'f', -1, 64)
		default:
			return "", fmt.Errorf("%s is of a kind this cannot take an answer to (%s)", q.Name, q.Kind)
		}
		lines = append(lines, q.Name+": "+v)
	}
	extra := []string{}
	for name := range answers {
		found := false
		for _, q := range qs {
			found = found || q.Name == name
		}
		if !found {
			extra = append(extra, name)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return "", fmt.Errorf("nothing asked %s", strings.Join(extra, ", "))
	}
	return strings.Join(lines, "\n"), nil
}
