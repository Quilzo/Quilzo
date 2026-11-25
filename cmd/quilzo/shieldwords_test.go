// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/out"
)

// A dry run says how far back it looked with the count and its noun in
// agreement: `shield dry-run --days 1` said "over the last 1 days".
func TestADryRunSaysHowFarBackInWords(t *testing.T) {
	old := w
	t.Cleanup(func() { w = old })
	for days, want := range map[string]string{"1": "over the last day:", "30": "over the last 30 days:"} {
		w = out.New(false)
		var said bytes.Buffer
		w.Out = &said
		if err := shieldDryRun(shieldRoot(t), []string{"--days", days}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(said.String(), want) {
			t.Errorf("--days %s: %q, not %q", days, said.String(), want)
		}
	}
}
