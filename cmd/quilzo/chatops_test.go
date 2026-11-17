// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
)

// A site with no chatbots lists none over the agent interface as it does
// on the command line: an empty list, not the JSON null a nil slice
// marshals to, which a client expecting a list had to special-case.
func TestNoChatbotsListAsAnEmptyListOverTheInterface(t *testing.T) {
	root := publishedShop(t)
	text, merr := callTool(t, assistantMCP(t, root), "quilzo_read", "list_assistants", map[string]any{})
	if merr != nil {
		t.Fatal(merr.Message)
	}
	if text != "[]" {
		t.Fatalf("a site with no chatbots listed %q", text)
	}
}
