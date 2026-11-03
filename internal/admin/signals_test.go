// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/a11y"
	"github.com/quilzo/quilzo/internal/auth"
)

// pushCounter stands in for the receiver: it counts what reached it.
type pushCounter struct{ n int }

func (p *pushCounter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.n++
	w.WriteHeader(http.StatusAccepted)
}

func pushTo(srv *Server) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, SignalsPath, strings.NewReader("eyJ.e30.sig"))
	req.Header.Set("Authorization", "Bearer qzsig_given-to-the-transmitter")
	req.Header.Set("Content-Type", "application/secevent+jwt")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// The transmitter's push reaches the receiver at /sso/signals, with no
// session and no same-site check in the way, and its bearer, which is no
// credential of this store's, is not reported as a guessed token.
func TestThePushReachesTheReceiverWithoutBeingTakenForAGuess(t *testing.T) {
	srv, _ := setup(t)
	rcv := &pushCounter{}
	srv.Signals = &SignalsAdmin{Handler: rcv}
	guessed := 0
	srv.OnBadToken = func(*http.Request, string, error) { guessed++ }
	if w := pushTo(srv); w.Code != http.StatusAccepted || rcv.n != 1 {
		t.Fatalf("the push was answered %d and reached the receiver %d times", w.Code, rcv.n)
	}
	if guessed != 0 {
		t.Error("the push bearer was reported to the shield as a token nobody issued")
	}
}

// With the shield's "signals" off the route answers 503 with when to come
// back, so the transmitter retries later, and the receiver is not reached.
func TestTheShieldTurnsTheSignalsRouteOff(t *testing.T) {
	srv, _ := setup(t)
	rcv := &pushCounter{}
	srv.Signals = &SignalsAdmin{Handler: rcv}
	srv.Shield = func(target string) (time.Time, bool) {
		return time.Now().Add(time.Hour), target == "signals"
	}
	w := pushTo(srv)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" || rcv.n != 0 {
		t.Errorf("shielded off: %d, retry %q, reached %d", w.Code, w.Header().Get("Retry-After"), rcv.n)
	}
}

// The Sign-ins screen says which sign-in the stream speaks for, whether it
// is verified, what the transmitter says of it, the last event and the
// counts; and it says so when nothing is connected, or the stream cannot
// be read. Each passes the checks the admin holds its own pages to.
func TestTheSignInsScreenShowsTheStream(t *testing.T) {
	srv, token := setup(t)
	now := time.Now()
	st := &SignalsStatus{Provider: "oidc", Issuer: "https://idp.example", State: "enabled",
		Connected: now.Add(-72 * time.Hour), Verified: now.Add(-50 * time.Hour), Asked: now.Add(-2 * time.Hour),
		LastAt: now.Add(-time.Hour), LastType: "session-revoked", Received: 9, Acted: 6, Unmatched: 2, Refused: 1}
	var stErr error
	srv.Signals = &SignalsAdmin{Handler: &pushCounter{},
		Status: func() (*SignalsStatus, error) { return st, stErr }}

	check := func(want ...string) {
		t.Helper()
		w := get(t, srv, "/security/signins", token)
		if w.Code != http.StatusOK {
			t.Fatalf("Sign-ins answered %d", w.Code)
		}
		body := w.Body.String()
		for _, s := range want {
			if !strings.Contains(body, s) {
				t.Errorf("Sign-ins does not say %q", s)
			}
		}
		if r := a11y.Check("/security/signins", body); r.Blocks() {
			for _, f := range r.Findings {
				if f.Severity == a11y.Blocking {
					t.Errorf("%s (%s): %s", f.Rule, f.Criterion, f.Detail)
				}
			}
		}
	}
	check("From the identity provider", "oidc sign-ins, from <code>https://idp.example</code>", "silent", "enabled",
		"session-revoked", "Unmatched")

	st.Manual = true
	check("cannot be asked")

	st = nil
	check("No stream is connected", "quilzo signals connect")

	stErr = errors.New("signals.json cannot be read")
	check("signals.json cannot be read")
}

// What is wrong with a stream is said, not left to be guessed, in the
// house's list of facts. One never asked to verify says so, where it said
// "asked, not answered yet"; a request that failed says why; a stream the
// provider paused is marked; events past the hourly cap are drawn as the
// worst figure on the screen, which the stylesheet did not draw at all; and
// with none connected the command shown is one that works as written, where
// it lacked the client and failed. The hint no longer says a passkey
// session is left alone when the provider reports a credential stolen.
func TestTheSignInsScreenSaysWhatIsWrongWithTheStream(t *testing.T) {
	srv, token := setup(t)
	now := time.Now()
	st := &SignalsStatus{Provider: "saml:okta", Issuer: "https://okta.example", State: "paused",
		Connected: now.Add(-time.Hour), AskFailed: "QUILZO_SIGNALS_SECRET is not set in this process's environment",
		Acted: 20, Capped: 3}
	srv.Signals = &SignalsAdmin{Handler: &pushCounter{},
		Status: func() (*SignalsStatus, error) { return st, nil }}
	page := func() string {
		t.Helper()
		w := get(t, srv, "/security/signins", token)
		if w.Code != http.StatusOK {
			t.Fatalf("Sign-ins answered %d", w.Code)
		}
		body := w.Body.String()
		if r := a11y.Check("/security/signins", body); r.Blocks() {
			for _, f := range r.Findings {
				if f.Severity == a11y.Blocking {
					t.Errorf("%s (%s): %s", f.Rule, f.Criterion, f.Detail)
				}
			}
		}
		return body
	}
	body := page()
	for _, want := range []string{`<dl class="kv">`, "not asked yet; the server asks within a day",
		"Last request", "failed</span> QUILZO_SIGNALS_SECRET is not set", "paused</span> as the identity provider last said",
		"nothing is sent while it is", `class="critical"><dt>Past the hourly cap`, "confirm it is them"} {
		if !strings.Contains(body, want) {
			t.Errorf("Sign-ins does not say %q", want)
		}
	}
	for _, wrong := range []string{"asked, not answered", "Held back", ">silent<", "Passkey sessions, tokens and connected apps are left alone"} {
		if strings.Contains(body, wrong) {
			t.Errorf("Sign-ins says %q", wrong)
		}
	}
	if !strings.Contains(string(mustAsset(t, "style.css")), ".stats-row > div.critical {") {
		t.Error("a figure marked critical is drawn like every other")
	}

	st = nil
	body = page()
	for _, want := range []string{"quilzo signals connect --provider oidc --client-id ID", "QUILZO_SIGNALS_SECRET", "--jwks URL"} {
		if !strings.Contains(body, want) {
			t.Errorf("with none connected, Sign-ins does not say %q", want)
		}
	}
}

// The deny the receiver adds when the provider disables an account is the
// one passkey sign-in refuses as a suspension: a live deny of the reader
// role on the whole site, given by "signals".
func TestADenyFromTheProvidersSignalRefusesThePasskey(t *testing.T) {
	srv, token := fullyWired(t)
	f := newFake(t, "credential-signalled")
	f.register(t, srv, token)
	who := srv.Passkeys.Credentials[0].Principal
	srv.Policy.Bindings = append(srv.Policy.Bindings, auth.Binding{Principal: who, Role: auth.RoleReader,
		Resource: "/", Deny: true, GrantedBy: "signals", GrantedAt: time.Now().Unix(),
		Note: "suspended: the identity provider disabled their account"})
	sessions := len(srv.Tokens.Snapshot())
	f.count++
	w := f.signIn(t, srv)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "suspended") {
		t.Fatalf("the passkey answered %d: %s", w.Code, w.Body)
	}
	if len(srv.Tokens.Snapshot()) != sessions {
		t.Fatal("a session was given")
	}
}
