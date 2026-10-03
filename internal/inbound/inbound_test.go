// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package inbound

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func TestAStaticSecretMatchesOnlyItself(t *testing.T) {
	secret, digest, err := NewSecret()
	if err != nil || len(secret) < 40 {
		t.Fatal(secret, err)
	}
	if !StaticMatches(secret, digest) || !StaticMatches(BearerOrRaw("Bearer "+secret), digest) {
		t.Error("the secret did not match its own digest")
	}
	for _, bad := range []string{"", secret + "x", strings.ToUpper(secret), digest} {
		if StaticMatches(bad, digest) {
			t.Errorf("%q matched", bad)
		}
	}
	if StaticMatches(secret, "") {
		t.Error("a feed with no digest accepted a secret")
	}
}

func standardSign(secret, id string, ts int64, body string) string {
	key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "%s.%d.%s", id, ts, body)
	return "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func TestStandardWebhooksAreVerified(t *testing.T) {
	secret, _ := NewWebhookSecret()
	old, _ := NewWebhookSecret()
	body := `{"type":"user.created","timestamp":"2026-10-02T12:00:00Z","data":{"id":"u1"}}`
	h := func(id string, ts int64, sig string) http.Header {
		x := http.Header{}
		x.Set("webhook-id", id)
		x.Set("webhook-timestamp", fmt.Sprint(ts))
		x.Set("webhook-signature", sig)
		return x
	}
	good := h("msg_1", now.Unix(), standardSign(secret, "msg_1", now.Unix(), body))
	if id, err := VerifyStandard(good, []byte(body), secret, now); err != nil || id != "msg_1" {
		t.Fatalf("a good delivery: %q %v", id, err)
	}
	// While a key is rotated both signatures come, and either is enough.
	both := h("msg_2", now.Unix(), standardSign(old, "msg_2", now.Unix(), body)+" "+standardSign(secret, "msg_2", now.Unix(), body))
	if _, err := VerifyStandard(both, []byte(body), secret, now); err != nil {
		t.Errorf("a rotation delivery: %v", err)
	}
	for name, c := range map[string]struct {
		h    http.Header
		body string
	}{
		"another key":      {h("msg_1", now.Unix(), standardSign(old, "msg_1", now.Unix(), body)), body},
		"altered body":     {good, strings.Replace(body, "u1", "u2", 1)},
		"another id":       {h("msg_9", now.Unix(), standardSign(secret, "msg_1", now.Unix(), body)), body},
		"old":              {h("msg_1", now.Add(-6*time.Minute).Unix(), standardSign(secret, "msg_1", now.Add(-6*time.Minute).Unix(), body)), body},
		"future":           {h("msg_1", now.Add(6*time.Minute).Unix(), standardSign(secret, "msg_1", now.Add(6*time.Minute).Unix(), body)), body},
		"no signature":     {h("msg_1", now.Unix(), ""), body},
		"another version":  {h("msg_1", now.Unix(), strings.Replace(standardSign(secret, "msg_1", now.Unix(), body), "v1,", "v2,", 1)), body},
		"signature as hex": {h("msg_1", now.Unix(), "v1,"+hex.EncodeToString([]byte("x"))), body},
	} {
		if _, err := VerifyStandard(c.h, []byte(c.body), secret, now); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestGitHubDeliveriesAreVerified(t *testing.T) {
	secret := "a-github-webhook-secret-of-some-length"
	body := []byte(`{"action":"deleted","repository":{"full_name":"acme/x"}}`)
	sign := func(b []byte, s string) string {
		m := hmac.New(sha256.New, []byte(s))
		m.Write(b)
		return "sha256=" + hex.EncodeToString(m.Sum(nil))
	}
	h := http.Header{}
	h.Set("X-GitHub-Delivery", "d-1")
	h.Set("X-Hub-Signature-256", sign(body, secret))
	if id, err := VerifyGitHub(h, body, secret); err != nil || id != "d-1" {
		t.Fatalf("%q %v", id, err)
	}
	h.Set("X-Hub-Signature-256", sign(body, "another-secret-entirely-here"))
	if _, err := VerifyGitHub(h, body, secret); err == nil {
		t.Error("another key's signature was accepted")
	}
	h.Set("X-Hub-Signature-256", sign(body, secret))
	if _, err := VerifyGitHub(h, append(body, ' '), secret); err == nil {
		t.Error("an altered body was accepted")
	}
	h.Set("X-Hub-Signature-256", strings.Replace(sign(body, secret), "sha256=", "sha1=", 1))
	if _, err := VerifyGitHub(h, body, secret); err == nil {
		t.Error("a sha1-labelled signature was accepted")
	}
}

func TestADeliveryIsTakenOnce(t *testing.T) {
	s := &Seen{Max: 3}
	if !s.First("a", now) || s.First("a", now.Add(time.Hour)) {
		t.Error("the same id was taken twice within a day")
	}
	if !s.First("a", now.Add(25*time.Hour)) {
		t.Error("an id a day old was still remembered")
	}
	for _, id := range []string{"b", "c", "d", "e"} {
		s.First(id, now.Add(26*time.Hour))
	}
	if len(s.ids) > 3 {
		t.Errorf("%d ids held past the limit of 3", len(s.ids))
	}
}

func TestOktaIsAnsweredAndRead(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/feeds/okta/main", nil)
	r.Header.Set("X-Okta-Verification-Challenge", "abc123")
	b, ok := OktaChallenge(r)
	if !ok || string(b) != `{"verification":"abc123"}` {
		t.Errorf("answered %s", b)
	}
	if _, ok := OktaChallenge(httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Error("a request without the challenge was answered")
	}
	d, err := ParseOkta([]byte(`{"eventType":"com.okta.event_hook","eventId":"e1","data":{"events":[{"uuid":"u1","eventType":"user.session.start"}]}}`))
	if err != nil || len(d.Data.Events) != 1 || d.EventID != "e1" {
		t.Errorf("%+v %v", d, err)
	}
	if _, err := ParseOkta([]byte(`{"eventType":"something.else","data":{"events":[]}}`)); err == nil {
		t.Error("a delivery that is not an event hook was read")
	}
}

func TestAWebhookBodyBecomesRecords(t *testing.T) {
	for body, n := range map[string]int{
		`{"id":1}`: 1, `[{"id":1},{"id":2}]`: 2, `{"data":[{"id":1},{"id":2},{"id":3}]}`: 3, `{"events":[{"id":1}]}`: 1,
	} {
		if recs, err := Records([]byte(body)); err != nil || len(recs) != n {
			t.Errorf("%s: %d %v", body, len(recs), err)
		}
	}
	if _, err := Records([]byte(`"just a string"`)); err == nil {
		t.Error("a string became records")
	}
}

func oktaEvent(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestOktaEventsThatMeanSomethingBecomeSignals(t *testing.T) {
	for _, c := range []struct {
		ev           string
		typ, person  string
		field, value string
		ok           bool
	}{
		{`{"eventType":"user.lifecycle.suspend","outcome":{"result":"SUCCESS"},"actor":{"type":"User","alternateId":"admin@x.example"},
		   "target":[{"type":"User","alternateId":"Ivo.Petrov@X.example"}]}`, "account-disabled", "ivo.petrov@x.example", "okta_event", "user.lifecycle.suspend", true},
		{`{"eventType":"user.account.report_suspicious_activity_by_enduser","outcome":{"result":"SUCCESS"},
		   "actor":{"type":"User","alternateId":"gus@x.example"}}`, "reported", "gus@x.example", "", "", true},
		{`{"eventType":"user.risk.detect","outcome":{"result":"SUCCESS"},"target":[{"type":"User","alternateId":"nia@x.example"}],
		   "debugContext":{"debugData":{"risk":"{level=HIGH, reasons=Anomalous location}","previousRiskLevel":"LOW"}}}`, "risk-level-change", "nia@x.example", "current_level", "high", true},
		{`{"eventType":"user.mfa.factor.deactivate","outcome":{"result":"SUCCESS"},"target":[{"type":"User","alternateId":"ada@x.example"}]}`,
			"credential-change", "ada@x.example", "change_type", "revoke", true},
		// A failure to suspend is not a suspension.
		{`{"eventType":"user.lifecycle.suspend","outcome":{"result":"FAILURE"},"target":[{"type":"User","alternateId":"ivo@x.example"}]}`, "", "", "", "", false},
		// An ordinary sign-in is for the detections, not a signal.
		{`{"eventType":"user.session.start","outcome":{"result":"SUCCESS"},"actor":{"type":"User","alternateId":"ada@x.example"}}`, "", "", "", "", false},
		// Done to an app, by a service: nobody to act on.
		{`{"eventType":"user.session.clear","outcome":{"result":"SUCCESS"},"actor":{"type":"PublicClientApp","alternateId":"svc"},
		   "target":[{"type":"AppInstance","alternateId":"app"}]}`, "", "", "", "", false},
	} {
		typ, person, fields, ok := OktaSignal(oktaEvent(t, c.ev))
		if ok != c.ok || typ != c.typ || person != c.person || (c.field != "" && fields[c.field] != c.value) {
			t.Errorf("%s\n  read as %q %q %v %v", c.ev, typ, person, fields, ok)
		}
	}
	if OktaSeverity("risk-level-change", map[string]string{"current_level": "high"}) != "high" ||
		OktaSeverity("reported", nil) != "high" || OktaSeverity("account-enabled", nil) != "low" {
		t.Error("Okta signals are weighed wrongly")
	}
}
