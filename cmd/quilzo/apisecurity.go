// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/api"
	"github.com/quilzo/quilzo/internal/attest"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/profile"
)

// The security record's routes on the HTTP API: the profile, and what the
// public instance is sent. Each is behind the content API's own door
// (api.Server.Guard), is asked of the policy as the command line asks it,
// and writes as the command line writes, recorded, with a reason.

// apiRoute is one security route: its address, as the mux takes it.
type apiRoute struct {
	path   string
	handle func(root string, c *Caller, w http.ResponseWriter, r *http.Request)
}

// securityRoutes is every route this file and its siblings add.
var securityRoutes = []apiRoute{
	{"/api/v1/profile", apiProfile},
	{"/api/v1/profile/features/", apiProfileFeature},
	{"/api/v1/attestations", apiAttestations},
	{"/api/v1/attestations/publish", apiAttestationsPublish},
}

// securityAPI is the content API with the security routes in front of it.
func securityAPI(root string, apiSrv *api.Server) http.Handler {
	content := apiSrv.Handler()
	mux := http.NewServeMux()
	for _, rt := range securityRoutes {
		handle := rt.handle
		mux.Handle(rt.path, apiSrv.Guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := api.TokenOf(r)
			if tok == nil {
				apiFail(w, http.StatusUnauthorized, errors.New("not authenticated"))
				return
			}
			handle(root, tokenCaller(tok), w, r)
		})))
	}
	mux.Handle("/", content)
	return mux
}

// tokenCaller is the caller a token the API authenticated makes, as
// resolveCaller makes one on the command line.
func tokenCaller(tok *auth.Token) *Caller {
	kind := audit.KindService
	if tok.Person() {
		kind = audit.KindHuman
	}
	return &Caller{Name: tok.Principal, Role: tok.Role, Scope: tok.Resource,
		Limits: tok.Scope, Kind: kind, Verified: true, Credential: tok.Name}
}

// apiFail answers with the content API's error shape and the status the
// error is: a refusal by a gate is 403, a request that does not make sense
// is 400, something missing 404.
func apiFail(w http.ResponseWriter, status int, err error) {
	if status == 0 {
		var blocked errBlocked
		var misused errMisused
		var missing errNotFound
		switch {
		case errors.As(err, &blocked):
			status = http.StatusForbidden
		case errors.As(err, &misused):
			status = http.StatusBadRequest
		case errors.As(err, &missing):
			status = http.StatusNotFound
		default:
			status = http.StatusInternalServerError
		}
	}
	apiJSON(w, status, map[string]string{"error": err.Error()})
}

func apiJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// onlyMethods refuses any method but those given, with the Allow header
// that says which.
func onlyMethods(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	apiFail(w, http.StatusMethodNotAllowed, errors.New(r.Method+" is not answered here"))
	return false
}

// readBody is a small JSON body, refused when it is not one.
func readBody(r *http.Request, into any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return errMisused{errors.New("the body is not what this route takes: " + err.Error())}
	}
	return nil
}

// apiProfile is GET /api/v1/profile: the profile and the signed manifest.
func apiProfile(root string, c *Caller, w http.ResponseWriter, r *http.Request) {
	if !onlyMethods(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	if err := authoriseUnder(root, c, auth.ActView, auth.AreaSecurity); err != nil {
		apiFail(w, 0, err)
		return
	}
	v, err := viewProfile(root)
	if err != nil {
		apiFail(w, 0, err)
		return
	}
	sm, _, _ := storedManifest(root)
	apiJSON(w, http.StatusOK, map[string]any{"profile": v, "signed_manifest": sm})
}

// apiProfileFeature is POST /api/v1/profile/features/NAME with
// {"on": true, "reason": "..."}: an administrator switching one feature.
func apiProfileFeature(root string, c *Caller, w http.ResponseWriter, r *http.Request) {
	if !onlyMethods(w, r, http.MethodPost) {
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/profile/features/")
	var body struct {
		On     bool   `json:"on"`
		Reason string `json:"reason"`
	}
	if err := readBody(r, &body); err != nil {
		apiFail(w, 0, err)
		return
	}
	action := "profile.feature.off"
	if body.On {
		action = "profile.feature.on"
	}
	sm, err := changeProfile(root, c, action, map[string]string{"feature": name, "reason": body.Reason,
		"surface": "api"}, func(st *profile.State, now time.Time) error {
		_, err := st.Switch(name, body.On, body.Reason, c.Name, now)
		return err
	})
	if err != nil {
		apiFail(w, 0, err)
		return
	}
	apiJSON(w, http.StatusOK, map[string]string{"feature": name, "state": onOff(body.On), "manifest": sm.Digest})
}

// apiAttestations is GET /api/v1/attestations, the public instance as the
// internal one sees it, and PUT with a file of attestations, which keeps it
// as the draft.
func apiAttestations(root string, c *Caller, w http.ResponseWriter, r *http.Request) {
	if !onlyMethods(w, r, http.MethodGet, http.MethodHead, http.MethodPut) {
		return
	}
	if r.Method == http.MethodPut {
		body, err := io.ReadAll(io.LimitReader(r.Body, attest.MaxBytes+1))
		if err != nil {
			apiFail(w, http.StatusBadRequest, err)
			return
		}
		f, err := setDraft(root, c, body, "api")
		if err != nil {
			apiFail(w, 0, err)
			return
		}
		apiJSON(w, http.StatusOK, map[string]string{"draft_digest": f.Digest()})
		return
	}
	if err := authoriseUnder(root, c, auth.ActView, auth.AreaSecurity); err != nil {
		apiFail(w, 0, err)
		return
	}
	v, err := viewPublic(root)
	if err != nil {
		apiFail(w, 0, err)
		return
	}
	apiJSON(w, http.StatusOK, v)
}

// apiAttestationsPublish is POST /api/v1/attestations/publish with
// {"reason": "..."}: a proposal, which a second administrator approves
// before anything is sent.
func apiAttestationsPublish(root string, c *Caller, w http.ResponseWriter, r *http.Request) {
	if !onlyMethods(w, r, http.MethodPost) {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if err := readBody(r, &body); err != nil {
		apiFail(w, 0, err)
		return
	}
	sent, err := proposePublication(root, c, body.Reason)
	if err != nil {
		apiFail(w, 0, err)
		return
	}
	state := "waiting for a second administrator"
	if sent {
		state = "published, approved alone"
	}
	v, _ := viewPublic(root)
	apiJSON(w, http.StatusOK, map[string]string{"state": state, "request": v.Waiting})
}
