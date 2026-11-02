// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/newsletter"
)

// A newsletter issue an agent proposed is on Approvals with everything else
// that waits on a person, saying that nothing goes until a person sends it.
func TestAProposedIssueIsOnApprovals(t *testing.T) {
	srv, token := setup(t)
	srv.Newsletter = &NewsletterHooks{Issues: func() ([]newsletter.Issue, error) {
		return []newsletter.Issue{
			{ID: "i1", Page: "index", Subject: "Autumn at the bakery", State: newsletter.Proposed,
				By: "writer", Note: "the new loaves", Proposed: time.Now().Add(-time.Hour)},
			{ID: "i2", Page: "index", Subject: "Sent last week", State: newsletter.Sent},
		}, nil
	}}
	body := get(t, srv, "/approvals", token).Body.String()
	for _, want := range []string{"Send the issue “Autumn at the bakery”", "nothing is sent until a person sends it"} {
		if !strings.Contains(body, want) {
			t.Errorf("Approvals does not say %q", want)
		}
	}
	if strings.Contains(body, "Sent last week") {
		t.Error("a sent issue is waiting")
	}
}
