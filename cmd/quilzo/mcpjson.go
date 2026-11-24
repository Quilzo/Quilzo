// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"

	"github.com/quilzo/quilzo/internal/out"
)

// mcpJSON is json.Marshal for an operation that writes its own answer, with
// an empty list in it written as [] rather than null (out.EmptyLists), as
// the command line and the machine interface's other answers write it.
//
// These operations encoded what they answered for themselves, so the rule
// the command line keeps did not reach them: a decider, an experiment or an
// assistant with nothing in a list answered null, and an agent iterating it
// failed where it had nothing to do.
func mcpJSON(v any) ([]byte, error) { return json.Marshal(out.EmptyLists(v)) }

// mcpJSONIndent is mcpJSON indented, as json.MarshalIndent is.
func mcpJSONIndent(v any, prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(out.EmptyLists(v), prefix, indent)
}
