// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/clientip"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/evals"
	"github.com/quilzo/quilzo/internal/shield"
)

// shieldRoot is a store with an audit key, as a server has one.
func shieldRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	key, err := audit.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(auditKeyPath(root)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditKeyPath(root), key, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func fromAddr(addr string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pages", nil)
	r.RemoteAddr = addr + ":4000"
	return clientip.With(r, (*clientip.Resolver)(nil).From(r))
}

func TestADecoyPresentedShutsItsHolderOutAndSaysWhereItWasPlanted(t *testing.T) {
	root := shieldRoot(t)
	secret, d, err := shield.AddDecoy(root, "the deploy job's variables", "dana", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := newShieldHost(root)
	h.badToken(fromAddr("203.0.113.9"), secret, errors.New("no such token"))
	h.guard.Refresh()
	if _, blocked := h.guard.Blocked("203.0.113.9", shield.Admin, time.Now()); !blocked {
		t.Fatal("the decoy's holder still reaches the admin")
	}
	st, _ := shield.Load(root)
	if len(st.Responses) == 0 {
		t.Fatal("no response recorded")
	}
	sum := shieldSummary("A decoy was touched", st.Responses[0], shield.Signal{Name: "decoy", Subject: d.ID}, st)
	if !strings.HasPrefix(sum, "Shield: A decoy was touched (stage 1). Blocked") ||
		!strings.Contains(sum, "planted in the deploy job's variables") {
		t.Fatalf("%q", sum)
	}
}

// A decoy presented to the command line is a decoy touched: recorded with
// where it was planted and who ran the command, once however often the
// command asks who is running it, and told to the shield, which tells the
// security contact and opens a case. Nothing is blocked: it came from this
// machine, which the shield never blocks, and the command line is the way
// out of anything the shield does. It is refused as any unknown token is.
//
// It was only "no such token": no record, no response, nobody told, so the
// one place a decoy planted in a laptop's configuration is most likely to
// be tried was the one place trying it went unheard.
func TestADecoyPresentedToTheCommandLineIsTold(t *testing.T) {
	t.Setenv("USER", "mallory")
	root := shieldRoot(t)
	secret, d, err := shield.AddDecoy(root, "the old laptop's quilzo token file", "dana", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if c := resolveCaller(root, secret); c.Verified || !strings.Contains(c.Why, "no such token") {
			t.Fatalf("a decoy was taken as somebody, or said as something else: %+v", c)
		}
	}
	finishBackground(10 * time.Second)
	recs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(auditKeyPath(root))
	if err != nil {
		t.Fatal(err)
	}
	touched := 0
	for _, r := range recs {
		if r.Action == "shield.decoy-touched" {
			touched++
			// The account that ran it, under the log's handle for it.
			if r.Detail["decoy"] != d.ID || r.Detail["planted"] != d.Note || r.Principal != audit.Pseudonym(key, "mallory") ||
				r.Detail["surface"] != "command line" || r.Detail["from"] != "--token" {
				t.Errorf("the record does not say what was touched, where, or by whom: %+v", r)
			}
		}
	}
	if touched != 1 {
		t.Fatalf("%d shield.decoy-touched records for one command", touched)
	}
	st, _ := shield.Load(root)
	var resp *shield.Response
	for i := range st.Responses {
		if st.Responses[i].Playbook == "decoy-touched" {
			resp = &st.Responses[i]
		}
	}
	if resp == nil {
		t.Fatalf("the shield did not respond: %+v", st.Responses)
	}
	did := strings.Join(resp.Did, "; ")
	if !strings.Contains(did, "told the security contact") || !strings.Contains(did, "opened a case") ||
		!strings.Contains(did, "this machine") || len(resp.Applied) != 0 {
		t.Fatalf("the response: %+v", resp)
	}
	// The dry run sees it as the engine did: from this machine, which no
	// playbook blocks, so not as a source it would have blocked.
	sigs, err := history(root, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sigs {
		if s.Name == "decoy" && s.Handle != "" {
			t.Fatalf("the dry run counts the command line as a source to block: %+v", s)
		}
	}
}

func TestANamedProxysOwnRequestIsCountedAndBlocked(t *testing.T) {
	// Being named as a proxy is being believed about the people it
	// forwards. A request it makes itself, with nobody forwarded, is its
	// own: a decoy presented that way blocks the proxy's address, as it
	// would anybody's, on a private network as on the internet, and what
	// the proxy forwards is still judged by the address forwarded.
	for _, tc := range []struct{ named, proxy string }{
		{"192.0.2.0/24", "192.0.2.10"},
		{"10.0.0.5", "10.0.0.5"},
	} {
		root := shieldRoot(t)
		cfg := config.New()
		if err := cfg.Set("network.trusted_proxies", tc.named, "", "test"); err != nil {
			t.Fatal(err)
		}
		if err := saveConfig(root, cfg); err != nil {
			t.Fatal(err)
		}
		secret, _, err := shield.AddDecoy(root, "the deploy job's variables", "dana", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		h := newShieldHost(root)
		reached := 0
		srv := edge(root, "admin.trusted_proxy", h.guard.Wrap(shield.Admin,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached++
				if r.Header.Get("Authorization") != "" {
					h.badToken(r, secret, errors.New("no such token"))
				}
			})))
		send := func(xff string, token bool) int {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/pages", nil)
			r.RemoteAddr = tc.proxy + ":443"
			if xff != "" {
				r.Header.Set("X-Forwarded-For", xff)
			}
			if token {
				r.Header.Set("Authorization", "Bearer "+secret)
			}
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			return w.Code
		}
		if code := send("", true); code != http.StatusOK || reached != 1 {
			t.Fatalf("%s, the first request: %d", tc.proxy, code)
		}
		h.guard.Refresh()
		if code := send("", false); code != http.StatusTooManyRequests || reached != 1 {
			t.Fatalf("the proxy at %s that presented a decoy still reaches the admin: %d", tc.proxy, code)
		}
		if code := send("203.0.113.10", false); code != http.StatusOK || reached != 2 {
			t.Fatalf("somebody %s forwards was refused for it: %d", tc.proxy, code)
		}
	}
}

func TestGuessesAreCountedAndLateCredentialsAreNot(t *testing.T) {
	root := shieldRoot(t)
	h := newShieldHost(root)
	expired := errors.New("token expired")
	for i := 0; i < 10; i++ {
		// Somebody's real token, used late: not an attack.
		h.badToken(fromAddr("198.51.100.7"), "qz_"+strings.Repeat("a", 52), expired)
		// Not shaped like a token at all: a misconfigured client.
		h.badToken(fromAddr("198.51.100.8"), "eyJhbGciOi.jwt", errUnknownForTest())
	}
	for i := 0; i < 5; i++ {
		h.badToken(fromAddr("198.51.100.9"), "qz_"+strings.Repeat("b", 52), errUnknownForTest())
	}
	h.guard.Refresh()
	now := time.Now()
	if _, b := h.guard.Blocked("198.51.100.7", shield.Admin, now); b {
		t.Fatal("a late credential was taken for guessing")
	}
	if _, b := h.guard.Blocked("198.51.100.8", shield.Admin, now); b {
		t.Fatal("a misconfigured client was taken for guessing")
	}
	if _, b := h.guard.Blocked("198.51.100.9", shield.Admin, now); !b {
		t.Fatal("five guesses were not stopped")
	}
}

// Passkey sign-ins that prove nobody are failed sign-ins from their source,
// as guessed tokens are: five within the hour and the source is stopped at
// the admin. They were only slowed by the throttle, and the playbook for
// repeated failed sign-ins never heard of them.
func TestFailedPasskeySignInsFromOneSourceAreStopped(t *testing.T) {
	root := shieldRoot(t)
	h := newShieldHost(root)
	h.where = shield.Admin
	for i := 0; i < 4; i++ {
		h.failedSignIn(fromAddr("198.51.100.20"))
	}
	h.guard.Refresh()
	if _, b := h.guard.Blocked("198.51.100.20", shield.Admin, time.Now()); b {
		t.Fatal("four failures were taken for an attack")
	}
	h.failedSignIn(fromAddr("198.51.100.20"))
	h.guard.Refresh()
	if _, b := h.guard.Blocked("198.51.100.20", shield.Admin, time.Now()); !b {
		t.Fatal("five passkey sign-ins that proved nobody were not stopped")
	}
	st, _ := shield.Load(root)
	if len(st.Responses) != 1 || st.Responses[0].Playbook != "signin-attack" {
		t.Fatalf("%+v", st.Responses)
	}
}

// errUnknownForTest is what the token store answers for a secret it never
// issued.
func errUnknownForTest() error {
	_, err := (&auth.TokenStore{}).Authenticate("qz_"+strings.Repeat("z", 52), time.Now())
	return err
}

func TestTheLockdownGatesTheServersStoresAndNotTheMachines(t *testing.T) {
	root := shieldRoot(t)
	ts := &auth.TokenStore{}
	old, _, err := ts.Issue("laptop", "dana", auth.RoleAdmin, "", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // tokens and lockdowns are to the second
	p := shield.Protection{Kind: shield.Lockdown, Reason: "testing", By: "dana", Until: time.Now().Add(time.Hour)}
	if _, _, err := shield.Apply(root, p, time.Now()); err != nil {
		t.Fatal(err)
	}
	h := newShieldHost(root)
	if _, err := h.gate(ts).Authenticate(old, time.Now()); !errors.Is(err, auth.ErrLockedDown) {
		t.Fatalf("a server's store let a pre-lockdown token in: %v", err)
	}
	ts.Admit = nil // the command line on the machine loads its own, ungated
	if _, err := ts.Authenticate(old, time.Now()); err != nil {
		t.Fatalf("the machine was locked out: %v", err)
	}
}

func TestAPausedAgentIsRefusedAndStillEvaluated(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := demoStore(t)
	admin := asAdmin("dana")
	if err := declareAgent(root, writer("styler"), true, true, admin); err != nil {
		t.Fatal(err)
	}
	p := shield.Protection{Kind: shield.Agent, Target: "styler", Reason: "followed a planted instruction",
		By: "dana", Until: time.Now().Add(time.Hour)}
	if _, _, err := shield.Apply(root, p, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := executeAgentFrom(t.Context(), root, "styler", "tidy", false, admin, nil); err == nil ||
		!strings.Contains(err.Error(), "paused") {
		t.Fatalf("a paused agent ran: %v", err)
	}
	if _, err := addEvalCase(root, "styler", evals.Case{Goal: "tidy the pages",
		Expect: evals.Expect{Uses: []string{"list_pages"}}}); err != nil {
		t.Fatal(err)
	}
	// Re-testing it is how anybody knows the pause can be lifted.
	if rep, err := runEvaluation(root, "styler", 1, false, admin); err != nil || rep.Cases != 1 {
		t.Fatalf("a paused agent could not be evaluated: %+v %v", rep, err)
	}
}

func TestOnlyAnAdministratorsPasskeyMakesALockdownSafe(t *testing.T) {
	root := t.TempDir()
	if canSignInStrongly(root) {
		t.Fatal("nobody can get in, and a lockdown was called safe")
	}
	// Single sign-on alone: the identity provider can be down.
	if err := saveJSON(oidcPath(root), map[string]any{"issuer": "https://idp.example", "client_id": "x"}); err != nil {
		t.Fatal(err)
	}
	if canSignInStrongly(root) {
		t.Fatal("single sign-on alone was taken as a way in")
	}
	pol := &auth.Policy{}
	if err := pol.Grant(auth.Binding{Principal: "dana", Role: auth.RoleAdmin, Resource: "/"}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(policyPath(root), pol); err != nil {
		t.Fatal(err)
	}
	pk := map[string]any{"credentials": []map[string]any{{"id": "AQID", "public_key": "AQID", "algorithm": -7,
		"principal": "eve", "label": "k", "created_at": 1, "relying_party": "x"}}}
	if err := saveJSON(passkeysPath(root), pk); err != nil {
		t.Fatal(err)
	}
	if canSignInStrongly(root) {
		t.Fatal("a passkey of somebody who is not an administrator was taken as a way in")
	}
	pk["credentials"].([]map[string]any)[0]["principal"] = "dana"
	if err := saveJSON(passkeysPath(root), pk); err != nil {
		t.Fatal(err)
	}
	if !canSignInStrongly(root) {
		t.Fatal("an administrator's passkey was not taken as a way in")
	}
}

func TestADryRunSeesWhatTheEngineWouldHave(t *testing.T) {
	root := shieldRoot(t)
	// One source sends three injection attempts in five minutes: the site
	// records each (threshold one), with the window's running count.
	for n := 1; n <= 3; n++ {
		record(root, audit.Record{Action: "site.chatbot-injection", Resource: "/", Outcome: audit.Denied,
			Principal: "203.0.113.9", Kind: audit.KindUnknown,
			Detail: map[string]string{"count": strconv.Itoa(n), "distinct": "1"}})
	}
	sigs, err := history(root, 30, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 3 {
		t.Fatalf("%d signals from three records with running counts", len(sigs))
	}
	var pb shield.Playbook
	for _, x := range shield.Builtins() {
		if x.Name == "chatbot-injection" {
			pb = x
		}
	}
	runs := shield.Try([]shield.Playbook{pb}, sigs, &shield.State{}, time.Now())
	if runs[0].Responses != 1 {
		t.Fatalf("the dry run said %+v; the live engine would have acted once", runs[0])
	}
}

func TestASuspendedTokenAndItsSessionsAreRefusedUntilLifted(t *testing.T) {
	root := shieldRoot(t)
	ts := &auth.TokenStore{}
	secret, tok, err := ts.Issue("ci", "deploy-bot", auth.RoleAdmin, "", time.Hour, auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	sess, _, err := ts.Exchange(secret, auth.RoleNone, "", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := shield.Apply(root, shield.Protection{Kind: shield.Token, Target: tok.ID, Reason: "leaked in a log",
		By: "dana", Until: time.Now().Add(time.Hour)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := newShieldHost(root)
	h.gate(ts)
	for _, s := range []string{secret, sess} {
		if _, err := ts.Authenticate(s, time.Now()); err == nil || !strings.Contains(err.Error(), "suspended") {
			t.Fatalf("a suspended credential: %v", err)
		}
	}
	shield.Lift(root, p.ID, "dana", time.Now())
	h.guard.Refresh()
	if _, err := ts.Authenticate(secret, time.Now()); err != nil {
		t.Fatalf("lifted, still refused: %v", err)
	}
}

// Suspending an app connection holds the access tokens it was already
// given, not only the ones a refresh would give it next.
func TestASuspendedAppConnectionRefusesTheTokensItAlreadyHas(t *testing.T) {
	root := shieldRoot(t)
	ts := &auth.TokenStore{}
	const mcp = "https://admin.example.org/mcp"
	now := time.Now()
	held, _, err := ts.IssueForGrant("dana", auth.RoleAuthor, auth.Scope{}, "https://app.example.com/meta", "gr_00000000000000aa", mcp, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ts.IssueForGrant("dana", auth.RoleAuthor, auth.Scope{}, "https://other.example.com/meta", "gr_00000000000000bb", mcp, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := shield.Apply(root, shield.Protection{Kind: shield.Token, Target: "gr_00000000000000aa", Reason: "acting oddly",
		By: "dana", Until: now.Add(time.Hour)}, now); err != nil {
		t.Fatal(err)
	}
	newShieldHost(root).gate(ts)
	if _, err := ts.AuthenticateFor(held, mcp, now); err == nil || !strings.Contains(err.Error(), "suspended") {
		t.Fatalf("a suspended connection's token: %v", err)
	}
	if _, err := ts.AuthenticateFor(other, mcp, now); err != nil {
		t.Fatalf("another connection was held with it: %v", err)
	}
}

// A credential caught in a prompt is recorded as a count and handed to the
// shield, which opens a case; personal data alone is only recorded.
func TestACredentialInAPromptIsTheShields(t *testing.T) {
	root := shieldRoot(t)
	noteMasked(root, "chatbot:help", "hosted", map[string]int{"email": 2})
	if st, _ := shield.Load(root); len(st.Responses) != 0 {
		t.Fatalf("an email address reached the shield: %+v", st.Responses)
	}
	noteMasked(root, "agent:tidy", "hosted", map[string]int{"secret": 1, "email": 1})
	st, _ := shield.Load(root)
	if len(st.Responses) != 1 || st.Responses[0].Playbook != "secret-in-prompt" ||
		!strings.Contains(strings.Join(st.Responses[0].Did, "; "), "case") {
		t.Fatalf("%+v", st.Responses)
	}
	recs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	masked := 0
	for _, r := range recs {
		if r.Action == "model.masked" {
			masked++
			for _, v := range r.Detail {
				if strings.Contains(v, "@") {
					t.Fatalf("a value reached the log: %v", r.Detail)
				}
			}
		}
	}
	if masked != 2 {
		t.Fatalf("%d model.masked records", masked)
	}
	if last := recs[len(recs)-1]; last.Action != "model.masked" || last.Detail["masked_credential"] != "1" {
		// The record of a credential taken out was once refused whole.
		for _, r := range recs {
			if r.Action == "model.masked" && r.Detail["masked_credential"] == "1" {
				return
			}
		}
		t.Fatal("the credential taken out is not counted")
	}
}

// A new page winning ten different questions within the hour is a case;
// the same question asked ten times is one question.
func TestANewPageWinningEverythingIsACase(t *testing.T) {
	root := shieldRoot(t)
	h := newShieldHost(root)
	for i := 0; i < 12; i++ {
		h.takeover("help", "shipping", "same-question")
	}
	if st, _ := shield.Load(root); len(st.Responses) != 0 {
		t.Fatalf("one question asked again was counted as many: %+v", st.Responses)
	}
	for i := 0; i < 10; i++ {
		h.takeover("help", "shipping", "q"+strconv.Itoa(i))
	}
	st, _ := shield.Load(root)
	if len(st.Responses) != 1 || st.Responses[0].Playbook != "knowledge-takeover" ||
		!strings.Contains(strings.Join(st.Responses[0].Did, "; "), "case") {
		t.Fatalf("%+v", st.Responses)
	}
}

// The command line says what it did to a network, and to which.
//
// `shield trust remove` answered "no longer trusted" and exited 0 for a
// network it did not remove: one never added, or one added from an address
// inside it and kept in that spelling. A block of an IPv4 network written
// inside IPv6 was taken, listed as in force and refused nobody.
func TestTheShieldCommandsNameTheNetworkTheyActedOn(t *testing.T) {
	root, token := accessStore(t)
	o, e, code := cliRun(t, root, token, "shield", "trust", "add", "198.51.100.7/24")
	if code != 0 || !strings.Contains(o, "never blocked: 198.51.100.0/24") {
		t.Fatalf("trust add exited %d: %s%s", code, o, e)
	}
	if _, e, code = cliRun(t, root, token, "shield", "trust", "remove", "203.0.113.0/24"); code != 4 || !strings.Contains(e, "203.0.113.0/24 is not a trusted network") {
		t.Fatalf("removing a network that was never trusted exited %d: %s", code, e)
	}
	if o, e, code = cliRun(t, root, token, "shield", "trust", "remove", "198.51.100.0/24"); code != 0 || !strings.Contains(o, "no longer trusted: 198.51.100.0/24") {
		t.Fatalf("trust remove exited %d: %s%s", code, o, e)
	}
	if o, _, _ = cliRun(t, root, token, "shield", "trust", "list"); strings.Contains(o, "198.51.100") {
		t.Fatalf("still listed: %s", o)
	}
	if _, e, code = cliRun(t, root, token, "shield", "trust", "remove", "198.51.100.0/24"); code != 4 {
		t.Fatalf("removing it twice exited %d: %s", code, e)
	}
	if _, e, code = cliRun(t, root, token, "shield", "trust", "add", "0.0.0.0/0"); code == 0 || !strings.Contains(e, "wider than a /8") ||
		!strings.Contains(e, "hold every playbook") {
		t.Fatalf("trusting the internet exited %d: %s", code, e)
	}
	o, e, code = cliRun(t, root, token, "shield", "block", "::ffff:203.0.113.0/120", "--where", "site", "--reason", "probing")
	if code != 0 || !strings.Contains(o, "blocked the network 203.0.113.0/24 on the site") {
		t.Fatalf("a block written as IPv4 inside IPv6 exited %d: %s%s", code, o, e)
	}
	if _, e, code = cliRun(t, root, token, "shield", "block", "::ffff:127.0.0.1/128", "--reason", "x"); code == 0 || !strings.Contains(e, "this machine") {
		t.Fatalf("blocking this machine, written as IPv6, exited %d: %s", code, e)
	}
}
