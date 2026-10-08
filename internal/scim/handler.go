// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package scim

import (
	"encoding/json"
	"github.com/quilzo/quilzo/internal/clientip"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/throttle"
)

// Handler serves /scim/v2 for an identity provider.
type Handler struct {
	Store *Store
	// Authenticate reports whether a bearer token is this install's
	// provisioning token. Nil refuses everybody.
	Authenticate func(token string) bool
	// Sync makes a person's access here match what provisioning says.
	// grants is what they should hold. suspended says the provider
	// deactivated or deleted them: they have left, and hold nothing here at
	// all, whatever was granted by hand. Called after every change, for
	// every user it touched; a renamed person's old name is synced with no
	// grants and not suspended, because that name is simply no longer them.
	Sync func(userName string, grants []string, suspended bool) error
	// Audit records each change, by user name and action, never content.
	Audit func(action, subject string, ok bool)
	// Limit bounds refused attempts per address.
	Limit *throttle.Limiter
	// Prefix is where it is mounted, "/scim/v2" by default.
	Prefix string
}

const contentType = "application/scim+json"

func (h *Handler) prefix() string {
	if h.Prefix != "" {
		return strings.TrimRight(h.Prefix, "/")
	}
	return "/scim/v2"
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func fail(w http.ResponseWriter, code int, scimType, detail string) {
	body := map[string]any{"schemas": []string{SchemaError}, "status": strconv.Itoa(code), "detail": detail}
	if scimType != "" {
		body["scimType"] = scimType
	}
	reply(w, code, body)
}

func source(r *http.Request) string { return clientip.SourceFrom(r) }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	subj := throttle.Subject{Source: source(r)}
	if h.Limit != nil {
		if d := h.Limit.Check(subj); !d.Allowed {
			fail(w, http.StatusTooManyRequests, "", "too many refused requests from here")
			return
		}
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || h.Authenticate == nil || !h.Authenticate(strings.TrimSpace(token)) {
		if h.Limit != nil {
			h.Limit.Spend(subj)
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
		fail(w, http.StatusUnauthorized, "", "a provisioning token is required")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, h.prefix())
	resource, id, _ := strings.Cut(strings.Trim(path, "/"), "/")
	switch resource {
	case "ServiceProviderConfig":
		reply(w, http.StatusOK, serviceProviderConfig)
	case "ResourceTypes":
		reply(w, http.StatusOK, resourceTypes(h.prefix()))
	case "Schemas":
		reply(w, http.StatusOK, map[string]any{"schemas": []string{SchemaList}, "totalResults": 0, "Resources": []any{}})
	case "Users":
		h.users(w, r, id)
	case "Groups":
		h.groups(w, r, id)
	default:
		fail(w, http.StatusNotFound, "", "no such endpoint")
	}
}

var serviceProviderConfig = map[string]any{
	"schemas":        []string{SchemaSPConfig},
	"patch":          map[string]bool{"supported": true},
	"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
	"filter":         map[string]any{"supported": true, "maxResults": 200},
	"changePassword": map[string]bool{"supported": false},
	"sort":           map[string]bool{"supported": false},
	"etag":           map[string]bool{"supported": false},
	"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Bearer token",
		"description": "The provisioning token made with quilzo scim token"}},
}

func resourceTypes(prefix string) map[string]any {
	return map[string]any{"schemas": []string{SchemaList}, "totalResults": 2, "Resources": []map[string]any{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User",
			"endpoint": "/Users", "schema": SchemaUser},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group",
			"endpoint": "/Groups", "schema": SchemaGroup},
	}}
}

func (h *Handler) userJSON(u User) map[string]any {
	return map[string]any{"schemas": []string{SchemaUser}, "id": u.ID, "userName": u.UserName,
		"externalId": u.ExternalID, "active": u.Active,
		"meta": map[string]any{"resourceType": "User", "created": u.Created, "lastModified": u.Modified,
			"location": h.prefix() + "/Users/" + u.ID}}
}

func (h *Handler) groupJSON(g Group, st *State) map[string]any {
	members := []map[string]string{}
	for _, m := range g.Members {
		row := map[string]string{"value": m}
		if u, ok := st.User(m); ok {
			row["display"] = u.UserName
		}
		members = append(members, row)
	}
	return map[string]any{"schemas": []string{SchemaGroup}, "id": g.ID, "displayName": g.DisplayName,
		"externalId": g.ExternalID, "members": members,
		"meta": map[string]any{"resourceType": "Group", "created": g.Created, "lastModified": g.Modified,
			"location": h.prefix() + "/Groups/" + g.ID}}
}

var reFilter = regexp.MustCompile(`^\s*(userName|externalId|displayName)\s+eq\s+"([^"]*)"\s*$`)

// list answers a GET on a collection: a filter by one attribute, and
// startIndex and count as RFC 7644 §3.4.2.4 has them.
func list(w http.ResponseWriter, r *http.Request, all []map[string]any, keys map[string]func(map[string]any) string) {
	q := r.URL.Query()
	items := all
	if f := q.Get("filter"); f != "" {
		m := reFilter.FindStringSubmatch(f)
		if m == nil || keys[m[1]] == nil {
			fail(w, http.StatusBadRequest, "invalidFilter", "only `attribute eq \"value\"` on userName, externalId or displayName is supported")
			return
		}
		items = nil
		for _, it := range all {
			if strings.EqualFold(keys[m[1]](it), m[2]) {
				items = append(items, it)
			}
		}
	}
	start, _ := strconv.Atoi(q.Get("startIndex"))
	if start < 1 {
		start = 1
	}
	count, err := strconv.Atoi(q.Get("count"))
	if err != nil || count < 0 || count > 200 {
		count = 200
	}
	page := []map[string]any{}
	for i := start - 1; i < len(items) && len(page) < count; i++ {
		page = append(page, items[i])
	}
	reply(w, http.StatusOK, map[string]any{"schemas": []string{SchemaList}, "totalResults": len(items),
		"startIndex": start, "itemsPerPage": len(page), "Resources": page})
}

func field(name string) func(map[string]any) string {
	return func(m map[string]any) string { s, _ := m[name].(string); return s }
}

func readBody(w http.ResponseWriter, r *http.Request, into any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(into); err != nil {
		fail(w, http.StatusBadRequest, "invalidSyntax", "the body is not the JSON this expects")
		return false
	}
	return true
}

// boolOf reads a SCIM boolean, which Entra sends as the string "False".
func boolOf(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		b, err := strconv.ParseBool(strings.ToLower(strings.TrimSpace(t)))
		return b, err == nil
	}
	return false, false
}

type userIn struct {
	UserName   string `json:"userName"`
	ExternalID string `json:"externalId"`
	Active     *bool  `json:"active"`
}

func validUserName(n string) bool {
	n = strings.TrimSpace(n)
	return n != "" && len(n) <= 256 && !strings.ContainsAny(n, "\x00\r\n\t ")
}

func (h *Handler) users(w http.ResponseWriter, r *http.Request, id string) {
	switch {
	case id == "" && r.Method == http.MethodGet:
		var rows []map[string]any
		_ = h.Store.Read(func(st *State) {
			for _, u := range st.Users {
				rows = append(rows, h.userJSON(u))
			}
		})
		list(w, r, rows, map[string]func(map[string]any) string{"userName": field("userName"), "externalId": field("externalId")})
	case id == "" && r.Method == http.MethodPost:
		var in userIn
		if !readBody(w, r, &in) {
			return
		}
		if !validUserName(in.UserName) {
			fail(w, http.StatusBadRequest, "invalidValue", "userName is required, without spaces")
			return
		}
		var made User
		err := h.Store.Update(func(st *State) error {
			if _, taken := st.UserNamed(in.UserName); taken {
				return ErrConflict
			}
			now := h.Store.now()
			made = User{ID: newID(), UserName: strings.TrimSpace(in.UserName), ExternalID: in.ExternalID,
				Active: in.Active == nil || *in.Active, Created: now, Modified: now}
			st.Users = append(st.Users, made)
			return nil
		})
		if err == ErrConflict {
			fail(w, http.StatusConflict, "uniqueness", "a user with that userName exists")
			return
		}
		if err != nil {
			fail(w, http.StatusInternalServerError, "", "that user could not be stored")
			return
		}
		h.audit("scim.user-created", made.UserName, true)
		h.sync(made.ID)
		reply(w, http.StatusCreated, h.userJSON(made))
	case id != "":
		h.user(w, r, id)
	default:
		fail(w, http.StatusMethodNotAllowed, "", "not on this collection")
	}
}

func (h *Handler) user(w http.ResponseWriter, r *http.Request, id string) {
	var found User
	exists := false
	_ = h.Store.Read(func(st *State) {
		if u, ok := st.User(id); ok {
			found, exists = *u, true
		}
	})
	if !exists {
		fail(w, http.StatusNotFound, "", "no such user")
		return
	}
	switch r.Method {
	case http.MethodGet:
		reply(w, http.StatusOK, h.userJSON(found))
	case http.MethodPut, http.MethodPatch:
		var changes map[string]any
		if r.Method == http.MethodPut {
			var in userIn
			if !readBody(w, r, &in) {
				return
			}
			changes = map[string]any{"externalId": in.ExternalID}
			if in.UserName != "" {
				changes["userName"] = in.UserName
			}
			if in.Active != nil {
				changes["active"] = *in.Active
			}
		} else {
			var op patchOp
			if !readBody(w, r, &op) {
				return
			}
			changes = op.userChanges()
		}
		var after User
		err := h.Store.Update(func(st *State) error {
			u, ok := st.User(id)
			if !ok {
				return ErrNotFound
			}
			if v, ok := changes["userName"].(string); ok && validUserName(v) && !strings.EqualFold(v, u.UserName) {
				if _, taken := st.UserNamed(v); taken {
					return ErrConflict
				}
				u.UserName = strings.TrimSpace(v)
			}
			if v, ok := changes["externalId"].(string); ok {
				u.ExternalID = v
			}
			if v, ok := boolOf(changes["active"]); ok {
				u.Active = v
			}
			u.Modified = h.Store.now()
			after = *u
			return nil
		})
		if err == ErrConflict {
			fail(w, http.StatusConflict, "uniqueness", "a user with that userName exists")
			return
		}
		if err != nil {
			fail(w, http.StatusInternalServerError, "", "that user could not be changed")
			return
		}
		// A renamed person's access moves with them: the old name loses it.
		if !strings.EqualFold(after.UserName, found.UserName) && h.Sync != nil {
			_ = h.Sync(found.UserName, nil, false)
		}
		action := "scim.user-changed"
		if found.Active && !after.Active {
			action = "scim.user-deactivated"
		}
		h.audit(action, after.UserName, true)
		h.sync(id)
		reply(w, http.StatusOK, h.userJSON(after))
	case http.MethodDelete:
		err := h.Store.Update(func(st *State) error {
			for i := range st.Users {
				if st.Users[i].ID == id {
					st.Users = append(st.Users[:i], st.Users[i+1:]...)
					st.removeMember(id)
					return nil
				}
			}
			return ErrNotFound
		})
		if err != nil {
			fail(w, http.StatusNotFound, "", "no such user")
			return
		}
		if h.Sync != nil {
			_ = h.Sync(found.UserName, nil, true)
		}
		h.audit("scim.user-deleted", found.UserName, true)
		w.WriteHeader(http.StatusNoContent)
	default:
		fail(w, http.StatusMethodNotAllowed, "", "not on a user")
	}
}

type memberRef struct {
	Value string `json:"value"`
}

type groupIn struct {
	DisplayName string      `json:"displayName"`
	ExternalID  string      `json:"externalId"`
	Members     []memberRef `json:"members"`
}

func (h *Handler) groups(w http.ResponseWriter, r *http.Request, id string) {
	switch {
	case id == "" && r.Method == http.MethodGet:
		var rows []map[string]any
		_ = h.Store.Read(func(st *State) {
			for _, g := range st.Groups {
				rows = append(rows, h.groupJSON(g, st))
			}
		})
		list(w, r, rows, map[string]func(map[string]any) string{"displayName": field("displayName"), "externalId": field("externalId")})
	case id == "" && r.Method == http.MethodPost:
		var in groupIn
		if !readBody(w, r, &in) {
			return
		}
		name := strings.TrimSpace(in.DisplayName)
		if name == "" || len(name) > 256 {
			fail(w, http.StatusBadRequest, "invalidValue", "displayName is required")
			return
		}
		var made Group
		var touched []string
		err := h.Store.Update(func(st *State) error {
			for _, g := range st.Groups {
				if strings.EqualFold(g.DisplayName, name) {
					return ErrConflict
				}
			}
			now := h.Store.now()
			made = Group{ID: newID(), DisplayName: name, ExternalID: in.ExternalID, Created: now, Modified: now}
			for _, m := range in.Members {
				if _, ok := st.User(m.Value); ok {
					made.Members = append(made.Members, m.Value)
				}
			}
			touched = made.Members
			st.Groups = append(st.Groups, made)
			return nil
		})
		if err == ErrConflict {
			fail(w, http.StatusConflict, "uniqueness", "a group with that displayName exists")
			return
		}
		if err != nil {
			fail(w, http.StatusInternalServerError, "", "that group could not be stored")
			return
		}
		h.audit("scim.group-created", made.DisplayName, true)
		h.sync(touched...)
		var out map[string]any
		_ = h.Store.Read(func(st *State) { out = h.groupJSON(made, st) })
		reply(w, http.StatusCreated, out)
	case id != "":
		h.group(w, r, id)
	default:
		fail(w, http.StatusMethodNotAllowed, "", "not on this collection")
	}
}

func (h *Handler) group(w http.ResponseWriter, r *http.Request, id string) {
	var before Group
	exists := false
	_ = h.Store.Read(func(st *State) {
		if g, ok := st.Group(id); ok {
			before, exists = *g, true
			before.Members = append([]string(nil), g.Members...)
		}
	})
	if !exists {
		fail(w, http.StatusNotFound, "", "no such group")
		return
	}
	switch r.Method {
	case http.MethodGet:
		var out map[string]any
		_ = h.Store.Read(func(st *State) { out = h.groupJSON(before, st) })
		reply(w, http.StatusOK, out)
	case http.MethodPut, http.MethodPatch:
		var after Group
		var apply func(*State, *Group)
		if r.Method == http.MethodPut {
			var in groupIn
			if !readBody(w, r, &in) {
				return
			}
			apply = func(st *State, g *Group) {
				if n := strings.TrimSpace(in.DisplayName); n != "" {
					g.DisplayName = n
				}
				g.Members = nil
				for _, m := range in.Members {
					if _, ok := st.User(m.Value); ok {
						g.Members = append(g.Members, m.Value)
					}
				}
			}
		} else {
			var op patchOp
			if !readBody(w, r, &op) {
				return
			}
			apply = op.applyToGroup
		}
		err := h.Store.Update(func(st *State) error {
			g, ok := st.Group(id)
			if !ok {
				return ErrNotFound
			}
			apply(st, g)
			g.Members = unique(g.Members)
			g.Modified = h.Store.now()
			after = *g
			return nil
		})
		if err != nil {
			fail(w, http.StatusInternalServerError, "", "that group could not be changed")
			return
		}
		h.audit("scim.group-changed", after.DisplayName, true)
		// Everybody who was in it or is now: a rename changes what the
		// group means, and membership changes who it means it for.
		h.sync(unique(append(before.Members, after.Members...))...)
		var out map[string]any
		_ = h.Store.Read(func(st *State) { out = h.groupJSON(after, st) })
		reply(w, http.StatusOK, out)
	case http.MethodDelete:
		err := h.Store.Update(func(st *State) error {
			for i := range st.Groups {
				if st.Groups[i].ID == id {
					st.Groups = append(st.Groups[:i], st.Groups[i+1:]...)
					return nil
				}
			}
			return ErrNotFound
		})
		if err != nil {
			fail(w, http.StatusNotFound, "", "no such group")
			return
		}
		h.audit("scim.group-deleted", before.DisplayName, true)
		h.sync(before.Members...)
		w.WriteHeader(http.StatusNoContent)
	default:
		fail(w, http.StatusMethodNotAllowed, "", "not on a group")
	}
}

func unique(ids []string) []string {
	seen := map[string]bool{}
	out := ids[:0:0]
	for _, id := range ids {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// sync tells the host what each of these users should now hold.
func (h *Handler) sync(ids ...string) {
	if h.Sync == nil {
		return
	}
	type want struct {
		name   string
		grants []string
		active bool
	}
	var wants []want
	_ = h.Store.Read(func(st *State) {
		for _, id := range ids {
			if u, ok := st.User(id); ok {
				wants = append(wants, want{u.UserName, st.Grants(id), u.Active})
			}
		}
	})
	for _, x := range wants {
		if err := h.Sync(x.name, x.grants, !x.active); err != nil {
			h.audit("scim.sync-failed", x.name, false)
		}
	}
}

func (h *Handler) audit(action, subject string, ok bool) {
	if h.Audit != nil {
		h.Audit(action, subject, ok)
	}
}

// SyncAll re-applies every user's grants: after the mapping changes.
func (h *Handler) SyncAll() {
	var ids []string
	_ = h.Store.Read(func(st *State) {
		for _, u := range st.Users {
			ids = append(ids, u.ID)
		}
	})
	h.sync(ids...)
}

// -- PATCH ------------------------------------------------------------------

type patchOp struct {
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"Operations"`
}

// userChanges reads the operations a provider sends for a user: a path with
// a value (Entra), or no path and an object of values (Okta).
func (p patchOp) userChanges() map[string]any {
	out := map[string]any{}
	for _, o := range p.Operations {
		op := strings.ToLower(o.Op)
		if op != "replace" && op != "add" {
			continue
		}
		var v any
		_ = json.Unmarshal(o.Value, &v)
		switch strings.TrimSpace(o.Path) {
		case "":
			if m, ok := v.(map[string]any); ok {
				for _, k := range []string{"active", "userName", "externalId"} {
					if x, has := m[k]; has {
						out[k] = x
					}
				}
			}
		case "active", "userName", "externalId":
			out[o.Path] = v
		}
	}
	return out
}

var reMemberPath = regexp.MustCompile(`^members\[value eq "([^"]+)"\]$`)

// applyToGroup applies the membership and name operations providers send.
func (p patchOp) applyToGroup(st *State, g *Group) {
	refs := func(raw json.RawMessage) []string {
		var many []memberRef
		if json.Unmarshal(raw, &many) == nil {
			var out []string
			for _, m := range many {
				out = append(out, m.Value)
			}
			return out
		}
		var one memberRef
		if json.Unmarshal(raw, &one) == nil && one.Value != "" {
			return []string{one.Value}
		}
		return nil
	}
	known := func(ids []string) []string {
		var out []string
		for _, id := range ids {
			if _, ok := st.User(id); ok {
				out = append(out, id)
			}
		}
		return out
	}
	without := func(ids []string) {
		drop := map[string]bool{}
		for _, id := range ids {
			drop[id] = true
		}
		kept := g.Members[:0]
		for _, m := range g.Members {
			if !drop[m] {
				kept = append(kept, m)
			}
		}
		g.Members = kept
	}
	for _, o := range p.Operations {
		op, path := strings.ToLower(o.Op), strings.TrimSpace(o.Path)
		switch {
		case path == "members" && op == "add":
			g.Members = append(g.Members, known(refs(o.Value))...)
		case path == "members" && op == "replace":
			g.Members = known(refs(o.Value))
		case path == "members" && op == "remove":
			if ids := refs(o.Value); len(ids) > 0 {
				without(ids)
			} else {
				g.Members = nil
			}
		case reMemberPath.MatchString(path) && op == "remove":
			without([]string{reMemberPath.FindStringSubmatch(path)[1]})
		case path == "displayName" && (op == "replace" || op == "add"):
			var name string
			if json.Unmarshal(o.Value, &name) == nil && strings.TrimSpace(name) != "" {
				g.DisplayName = strings.TrimSpace(name)
			}
		case path == "" && (op == "replace" || op == "add"):
			var m map[string]json.RawMessage
			if json.Unmarshal(o.Value, &m) == nil {
				if raw, ok := m["displayName"]; ok {
					var name string
					if json.Unmarshal(raw, &name) == nil && strings.TrimSpace(name) != "" {
						g.DisplayName = strings.TrimSpace(name)
					}
				}
				if raw, ok := m["members"]; ok {
					if op == "replace" {
						g.Members = known(refs(raw))
					} else {
						g.Members = append(g.Members, known(refs(raw))...)
					}
				}
			}
		}
	}
}
