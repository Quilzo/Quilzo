// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/evals"
)

// The latest measurement of a chatbot or a decider: when, by whom, on
// which model, and what it found.
//
// What an evaluation finds holds only for the model it measured, since
// models behave differently from one release to the next. A chatbot's
// evaluation was audited without its model, and a decider's kept nothing at
// all, so nobody could tell whether the figures on hand were of the model
// answering now, or say when a decider was last measured. Agents keep their
// reports with evals.Report, which names its model the same way.

// measurement is one evaluation of a chatbot or a decider, kept whole.
type measurement struct {
	At time.Time `json:"at"`
	By string    `json:"by"`
	// Model and Route are what was measured: the model by the name its
	// provider gives it, and the gateway's route it was reached by, empty
	// without the gateway. Both empty is an evaluation with no model.
	Model  string          `json:"model,omitempty"`
	Route  string          `json:"route,omitempty"`
	Report json.RawMessage `json:"report"`
}

// reMeasured is what a chatbot's or a decider's name must be to become a
// file name here: both packages allow no more, and it reaches a path.
var reMeasured = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// measurementPath is where the latest measurement of a kind ("chatbot" or
// "decider") of thing is kept.
func measurementPath(root, kind, name string) (string, error) {
	if !reMeasured.MatchString(name) {
		return "", fmt.Errorf("%q is not a %s's name", name, kind)
	}
	return filepath.Join(evalsDir(root), kind+"s", name+".json"), nil
}

// keepMeasurement keeps an evaluation's report as the latest measurement,
// with what was measured and by whom.
func keepMeasurement(root, kind, name, by string, served evals.Served, at time.Time, report any) error {
	path, err := measurementPath(root, kind, name)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(measurement{At: at.UTC(), By: by, Model: served.Model,
		Route: served.Route, Report: raw}, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}

// lastMeasurement is the latest measurement kept, and false for none.
func lastMeasurement(root, kind, name string) (measurement, bool) {
	path, err := measurementPath(root, kind, name)
	if err != nil {
		return measurement{}, false
	}
	b, err := readBounded(path, 8<<20)
	if err != nil {
		return measurement{}, false
	}
	var m measurement
	if json.Unmarshal(b, &m) != nil || m.At.IsZero() {
		return measurement{}, false
	}
	return m, true
}

// Served is the model a measurement measured.
func (m measurement) Served() evals.Served { return evals.Served{Model: m.Model, Route: m.Route} }

// String is the measurement as a person reads it: "measured on MODEL, DATE".
func (m measurement) String() string {
	if m.Model == "" {
		return "measured with no model, " + m.At.Format("2 Jan 2006")
	}
	return fmt.Sprintf("measured on %s, %s", m.Served(), m.At.Format("2 Jan 2006"))
}

// measuredOn is a measurement as a list of deciders gives it to a program.
type measuredOn struct {
	At    string `json:"at"`
	By    string `json:"by"`
	Model string `json:"model,omitempty"`
	Route string `json:"route,omitempty"`
}

// listedMeasurement is the latest measurement for a list, nil for none.
func listedMeasurement(root, kind, name string) *measuredOn {
	m, ok := lastMeasurement(root, kind, name)
	if !ok {
		return nil
	}
	return &measuredOn{At: m.At.Format(time.RFC3339), By: m.By, Model: m.Model, Route: m.Route}
}
