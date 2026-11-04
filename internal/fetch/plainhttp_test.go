// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package fetch

import (
	"context"
	"strings"
	"testing"
)

// Plain http is refused for every purpose, and the reason given is the
// purpose's. An identity provider's issuer at http://localhost was refused
// because "imported content gets published", which is about importing, so
// somebody setting up sign-in was told about a risk that was not theirs.
func TestPlainHTTPIsRefusedForWhatTheConnectionIsFor(t *testing.T) {
	ctx := context.Background()
	if _, err := New().Get(ctx, "http://example.com/page"); err == nil ||
		!strings.Contains(err.Error(), "publish") {
		t.Errorf("an import over http: %v", err)
	}
	for purpose, says := range map[string]string{"sso": "sign", "webhook": "webhook",
		"integrations": "anyone on the path"} {
		_, err := For(purpose).Get(ctx, "http://example.com/x")
		if err == nil || !strings.Contains(err.Error(), "only https") {
			t.Errorf("%s over http: %v", purpose, err)
			continue
		}
		if strings.Contains(err.Error(), "publish") || !strings.Contains(err.Error(), says) {
			t.Errorf("%s over http is refused for another purpose's reason: %v", purpose, err)
		}
	}
}
