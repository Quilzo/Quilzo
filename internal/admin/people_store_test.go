// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
)

// An access change made here is applied to the policy as stored, so a
// revocation made elsewhere after this server read the policy is not
// written back over; and saving a session never rewrites the policy.
func TestAPeopleChangeIsAppliedToThePolicyAsStored(t *testing.T) {
	srv, token := setup(t)
	stored := &auth.Policy{}
	for _, b := range srv.Policy.Snapshot() {
		if err := stored.Grant(b); err != nil {
			t.Fatal(err)
		}
	}
	// Somebody revoked "leaver" on the command line after this server
	// read its policy, and granted "newcomer".
	if err := srv.Policy.Grant(auth.Binding{Principal: "leaver", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := stored.Grant(auth.Binding{Principal: "newcomer", Role: auth.RoleReader, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	srv.UpdatePolicy = func(change func(*auth.Policy) error) (*auth.Policy, error) {
		return stored, change(stored)
	}
	postForm(t, srv, "/people/grant", token, "principal=ria&role=author&resource=/")
	if !stored.Evaluate("ria", auth.ActEditDraft, "/").Allowed {
		t.Fatal("the grant was not applied to the stored policy")
	}
	if stored.Evaluate("leaver", auth.ActGrant, "/").Allowed {
		t.Error("a revocation made elsewhere was written back over")
	}
	if !srv.Policy.Evaluate("newcomer", auth.ActView, "/").Allowed {
		t.Error("the server did not take the policy as stored")
	}
}
