// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/member"
	"github.com/quilzo/quilzo/internal/webauthn"
)

func wireMembers(t *testing.T, srv *Server) *member.Store {
	t.Helper()
	store, err := member.Open(filepath.Join(t.TempDir(), "members"))
	if err != nil {
		t.Fatal(err)
	}
	srv.Members = &MembersAdmin{
		Mode: func() string { return "invite" }, List: store.List, Sessions: store.Sessions,
		SetDisabled: func(id string, d bool, _ string) error { return store.SetDisabled(id, d) },
		Remove:      func(id, _ string) error { return store.Delete(id) },
		Invite:      store.NewInvite, Invites: store.Invites,
		Revoke: func(h, _ string) error { return store.RevokeInvite(h) },
	}
	return store
}

func TestTheMembersScreenManagesAccounts(t *testing.T) {
	srv, token := setup(t)
	store := wireMembers(t, srv)
	m, _, err := store.Create("Ada Lovelace", webauthn.Credential{ID: []byte("k"), PublicKey: []byte("p")})
	if err != nil {
		t.Fatal(err)
	}
	if body := get(t, srv, "/members", token).Body.String(); !strings.Contains(body, "Ada Lovelace") ||
		!strings.Contains(body, "by invitation") {
		t.Fatal("the screen does not list the account or the mode")
	}

	postForm(t, srv, "/members/act", token, "do=disable&id="+m.ID)
	if got, _ := store.Get(m.ID); !got.Disabled {
		t.Error("disabling did not disable")
	}
	postForm(t, srv, "/members/act", token, "do=remove&id="+m.ID+"&confirm=nope")
	if _, err := store.Get(m.ID); err != nil {
		t.Error("an account was removed without the confirmation")
	}
	postForm(t, srv, "/members/act", token, "do=remove&id="+m.ID+"&confirm=remove")
	if _, err := store.Get(m.ID); err == nil {
		t.Error("removing did not remove")
	}

	// An invitation code is shown once, in the response that made it.
	w := postForm(t, srv, "/members/act", token, "do=invite&note=for+Bo")
	code := regexp.MustCompile(`<code>([0-9A-Z]{4}(?:-[0-9A-Z]{4}){3})</code>`).FindStringSubmatch(w.Body.String())
	if w.Code != http.StatusOK || code == nil {
		t.Fatalf("making an invitation: %d", w.Code)
	}
	if err := store.CheckInvite(code[1]); err != nil {
		t.Errorf("the code shown is not a live invitation: %v", err)
	}
	if strings.Contains(get(t, srv, "/members", token).Body.String(), code[1]) {
		t.Error("the invitation code is shown again")
	}
}

// Who has an account, and whether they keep it, is an administrator's call.
func TestOnlyAnAdministratorSeesTheMembers(t *testing.T) {
	author, atoken := asRole(t, auth.RoleAuthor)
	store := wireMembers(t, author)
	m, _, _ := store.Create("Ada", webauthn.Credential{ID: []byte("k"), PublicKey: []byte("p")})
	if w := get(t, author, "/members", atoken); w.Code == http.StatusOK && strings.Contains(w.Body.String(), "Ada") {
		t.Error("an author read the list of members")
	}
	postForm(t, author, "/members/act", atoken, "do=remove&id="+m.ID+"&confirm=remove")
	if _, err := store.Get(m.ID); err != nil {
		t.Error("an author removed an account")
	}
}
