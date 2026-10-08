// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package scim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fixture is a handler whose sync is recorded: what each person would hold.
type fixture struct {
	h         *Handler
	held      map[string][]string
	suspended map[string]bool
	log       []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{held: map[string][]string{}, suspended: map[string]bool{}}
	f.h = &Handler{
		Store:        &Store{Path: filepath.Join(t.TempDir(), "scim.json")},
		Authenticate: func(tok string) bool { return tok == "right-token" },
		Sync: func(name string, grants []string, suspended bool) error {
			if suspended {
				f.suspended[strings.ToLower(name)] = true
			} else {
				delete(f.suspended, strings.ToLower(name))
			}
			if suspended || len(grants) == 0 {
				delete(f.held, strings.ToLower(name))
			} else {
				f.held[strings.ToLower(name)] = grants
			}
			return nil
		},
		Audit: func(action, subject string, ok bool) { f.log = append(f.log, action+" "+subject) },
	}
	_ = f.h.Store.Update(func(st *State) error {
		st.Mapping["Security team"] = "analyst"
		st.Mapping["Editors"] = "publisher"
		return nil
	})
	return f
}

func (f *fixture) do(t *testing.T, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, "/scim/v2"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer right-token")
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestOnlyTheProvisioningTokenIsAccepted(t *testing.T) {
	f := newFixture(t)
	for _, auth := range []string{"", "Bearer wrong", "Basic right-token", "right-token"} {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%q answered %d", auth, w.Code)
		}
	}
}

// The whole of an Okta lifecycle: create, put in a group, deactivate.
func TestOktaProvisionsAndDeprovisionsSomebody(t *testing.T) {
	f := newFixture(t)
	code, u := f.do(t, http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"ada@example.com","name":{"givenName":"Ada","familyName":"L"},
		"emails":[{"primary":true,"value":"ada@example.com","type":"work"}],"active":true}`)
	if code != http.StatusCreated {
		t.Fatalf("creating a user: %d %v", code, u)
	}
	id := u["id"].(string)
	if code, _ := f.do(t, http.MethodPost, "/Users", `{"userName":"ADA@example.com"}`); code != http.StatusConflict {
		t.Errorf("the same user name twice answered %d", code)
	}
	code, list := f.do(t, http.MethodGet, `/Users?filter=userName%20eq%20%22ada@example.com%22`, "")
	if code != 200 || list["totalResults"].(float64) != 1 {
		t.Errorf("looking the user up by name: %d %v", code, list)
	}

	code, g := f.do(t, http.MethodPost, "/Groups", `{"displayName":"Security team","members":[]}`)
	if code != http.StatusCreated {
		t.Fatalf("creating a group: %d", code)
	}
	gid := g["id"].(string)
	f.do(t, http.MethodPatch, "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"add","path":"members","value":[{"value":"`+id+`"}]}]}`)
	if got := f.held["ada@example.com"]; len(got) != 1 || got[0] != "analyst" {
		t.Fatalf("joining the mapped group gave %v", got)
	}

	// Okta deactivates with a path-less replace.
	f.do(t, http.MethodPatch, "/Users/"+id, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","value":{"active":false}}]}`)
	if _, has := f.held["ada@example.com"]; has {
		t.Error("a deactivated person still holds access")
	}
	if !f.suspended["ada@example.com"] {
		t.Error("a deactivated person is not suspended")
	}
	// Reactivated, they are back as they were.
	f.do(t, http.MethodPatch, "/Users/"+id, `{"Operations":[{"op":"replace","value":{"active":true}}]}`)
	if f.suspended["ada@example.com"] || len(f.held["ada@example.com"]) != 1 {
		t.Errorf("reactivating left them suspended %v holding %v", f.suspended, f.held)
	}
	found := false
	for _, l := range f.log {
		if l == "scim.user-deactivated ada@example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("the deactivation is not on record: %v", f.log)
	}
}

// Entra writes PATCH differently: capitalised ops, a path, "False" as text,
// and removes a member by a filter in the path.
func TestEntraProvisionsAndDeprovisionsSomebody(t *testing.T) {
	f := newFixture(t)
	_, u := f.do(t, http.MethodPost, "/Users", `{"userName":"bo@contoso.com","externalId":"0a1b","active":true}`)
	id := u["id"].(string)
	_, g := f.do(t, http.MethodPost, "/Groups", `{"displayName":"Editors","externalId":"g1"}`)
	gid := g["id"].(string)
	f.do(t, http.MethodPatch, "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"Add","path":"members","value":[{"value":"`+id+`"}]}]}`)
	if got := f.held["bo@contoso.com"]; len(got) != 1 || got[0] != "publisher" {
		t.Fatalf("Entra adding a member gave %v", got)
	}
	f.do(t, http.MethodPatch, "/Groups/"+gid, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"Remove","path":"members[value eq \"`+id+`\"]"}]}`)
	if _, has := f.held["bo@contoso.com"]; has {
		t.Error("removed from the group, they still hold its access")
	}
	f.do(t, http.MethodPatch, "/Groups/"+gid, `{"Operations":[{"op":"Add","path":"members","value":[{"value":"`+id+`"}]}]}`)
	f.do(t, http.MethodPatch, "/Users/"+id, `{"Operations":[{"op":"Replace","path":"active","value":"False"}]}`)
	if _, has := f.held["bo@contoso.com"]; has {
		t.Error("Entra's \"False\" did not deactivate")
	}
	// And deleting removes them from every group.
	code, _ := f.do(t, http.MethodDelete, "/Users/"+id, "")
	if code != http.StatusNoContent {
		t.Fatalf("deleting: %d", code)
	}
	if !f.suspended["bo@contoso.com"] {
		t.Error("a deleted person is not suspended")
	}
	_, after := f.do(t, http.MethodGet, "/Groups/"+gid, "")
	if members, _ := after["members"].([]any); len(members) != 0 {
		t.Errorf("a deleted user is still a member: %v", members)
	}
}

// A group nobody mapped grants nothing, and provisioning cannot map one.
func TestAnUnmappedGroupGrantsNothing(t *testing.T) {
	f := newFixture(t)
	_, u := f.do(t, http.MethodPost, "/Users", `{"userName":"eve@example.com"}`)
	id := u["id"].(string)
	f.do(t, http.MethodPost, "/Groups", `{"displayName":"Domain Admins","members":[{"value":"`+id+`"}]}`)
	if got := f.held["eve@example.com"]; len(got) != 0 {
		t.Errorf("an unmapped group granted %v", got)
	}
	// Renaming a group to a mapped name is a change in what it means, and
	// moves its members with it — the provider can do that, because the
	// mapping a person made says what that name means.
	_, list := f.do(t, http.MethodGet, `/Groups?filter=displayName%20eq%20%22Domain%20Admins%22`, "")
	gid := list["Resources"].([]any)[0].(map[string]any)["id"].(string)
	f.do(t, http.MethodPatch, "/Groups/"+gid, `{"Operations":[{"op":"replace","value":{"displayName":"Editors"}}]}`)
	if got := f.held["eve@example.com"]; len(got) != 1 || got[0] != "publisher" {
		t.Errorf("renaming the group into a mapping gave %v", got)
	}
}

func TestAPersonInSeveralGroupsHoldsEachOnce(t *testing.T) {
	f := newFixture(t)
	_, u := f.do(t, http.MethodPost, "/Users", `{"userName":"cy@example.com"}`)
	id := u["id"].(string)
	for _, g := range []string{"Security team", "Editors", "Also editors"} {
		f.do(t, http.MethodPost, "/Groups", `{"displayName":"`+g+`","members":[{"value":"`+id+`"}]}`)
	}
	_ = f.h.Store.Update(func(st *State) error { st.Mapping["Also editors"] = "publisher"; return nil })
	f.h.SyncAll()
	got := append([]string(nil), f.held["cy@example.com"]...)
	sort.Strings(got)
	if strings.Join(got, ",") != "analyst,publisher" {
		t.Errorf("they hold %v", got)
	}
}

// A rename moves access to the new name. The old name is no longer anybody,
// so it loses what provisioning gave it and is not suspended: suspending it
// would lock out whoever is given that name next.
func TestARenameMovesAccessWithoutSuspendingTheOldName(t *testing.T) {
	f := newFixture(t)
	_, u := f.do(t, http.MethodPost, "/Users", `{"userName":"dee@example.com"}`)
	id := u["id"].(string)
	f.do(t, http.MethodPost, "/Groups", `{"displayName":"Editors","members":[{"value":"`+id+`"}]}`)
	f.do(t, http.MethodPatch, "/Users/"+id, `{"Operations":[{"op":"replace","path":"userName","value":"dee.smith@example.com"}]}`)
	if _, has := f.held["dee@example.com"]; has || f.suspended["dee@example.com"] {
		t.Errorf("the old name holds %v, suspended %v", f.held["dee@example.com"], f.suspended["dee@example.com"])
	}
	if got := f.held["dee.smith@example.com"]; len(got) != 1 {
		t.Errorf("the new name holds %v", got)
	}
}

func TestTheDiscoveryEndpointsAnswer(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"/ServiceProviderConfig", "/ResourceTypes", "/Schemas"} {
		if code, _ := f.do(t, http.MethodGet, p, ""); code != 200 {
			t.Errorf("%s answered %d", p, code)
		}
	}
	if code, out := f.do(t, http.MethodGet, `/Users?filter=name.givenName%20sw%20%22A%22`, ""); code != 400 || out["scimType"] != "invalidFilter" {
		t.Errorf("an unsupported filter answered %d %v", code, out)
	}
}
