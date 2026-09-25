// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package notify

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/webhook"
)

type posted struct {
	url     string
	body    []byte
	headers map[string]string
}

type poster struct {
	got    []posted
	status int
}

func (p *poster) Post(url string, body []byte, headers map[string]string) (
	int, error) {

	p.got = append(p.got, posted{url: url, body: body, headers: headers})
	if p.status == 0 {
		return 200, nil
	}
	return p.status, nil
}

func hookSender(p *poster) HookSender {
	return HookSender{Post: p, Secret: "shhh",
		At: func() time.Time { return now }}
}

func TestANoticeIsNotPostedInTheClear(t *testing.T) {
	p := &poster{}
	err := hookSender(p).Send(breach(), Delivery{Channel: Webhook,
		Address: "http://customer.test/hook", To: who(1), Key: "k"})
	if err == nil {
		t.Fatal("a breach notice was posted over plaintext HTTP")
	}
	if !strings.Contains(err.Error(), "second disclosure") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	if len(p.got) != 0 {
		t.Fatal("it was posted anyway")
	}
}

func TestAnUnsignedNoticeIsRefused(t *testing.T) {
	p := &poster{}
	s := hookSender(p)
	s.Secret = ""
	err := s.Send(breach(), Delivery{Channel: Webhook,
		Address: "https://customer.test/hook", To: who(1), Key: "k"})
	if err == nil {
		t.Fatal("an unsigned breach notice was posted")
	}
	if !strings.Contains(err.Error(), "phishing") {
		t.Errorf("the refusal does not say what an attacker does with "+
			"this: %v", err)
	}
}

func TestThePayloadIsSignedAndVerifiesWithTheSharedScheme(t *testing.T) {
	p := &poster{}
	d := Delivery{Channel: Webhook, Address: "https://customer.test/hook",
		To: who(1), Key: "delivery-key"}
	if err := hookSender(p).Send(breach(), d); err != nil {
		t.Fatal(err)
	}
	if len(p.got) != 1 {
		t.Fatalf("%d posts", len(p.got))
	}
	got := p.got[0]
	// The receiver verifies it exactly as they verify a publication webhook.
	if err := webhook.Verify("shhh", got.headers["Quilzo-Signature"], now,
		got.body, now); err != nil {
		t.Fatalf("the signature does not verify under the shared scheme: %v",
			err)
	}
	if got.headers["Quilzo-Delivery"] != "delivery-key" {
		t.Error("the receiver cannot deduplicate a retry")
	}
}

func TestThePayloadCarriesOnePersonAndWhatTheyNeedToAct(t *testing.T) {
	p := &poster{}
	n := breach()
	d := Delivery{Channel: Webhook, Address: "https://customer.test/hook",
		To: who(1), Key: "k"}
	if err := hookSender(p).Send(n, d); err != nil {
		t.Fatal(err)
	}
	var h Hook
	if err := json.Unmarshal(p.got[0].body, &h); err != nil {
		t.Fatal(err)
	}
	if h.Contact != who(1).String() {
		t.Errorf("the payload names %q", h.Contact)
	}
	// Nobody else. A customer's endpoint must not learn who else was
	// affected, and one delivery per contact is what guarantees it.
	for _, other := range []string{who(2).String(), who(3).String()} {
		if strings.Contains(string(p.got[0].body), other) {
			t.Errorf("the payload mentions %s", other)
		}
	}
	// And the Article 34(2) wording verbatim, so a receiver passing it on to
	// their own users is not paraphrasing a legal notice.
	for name, value := range map[string]string{
		"nature": h.Nature, "contact point": h.ContactPoint,
		"consequences": h.Consequences, "measures": h.Measures,
		"authority deadline": h.AuthorityDue,
	} {
		if value == "" {
			t.Errorf("the payload carries no %s", name)
		}
	}
	if h.Declinable {
		t.Error("the payload tells a receiver a breach notice can be " +
			"turned off")
	}
	if h.Basis != LegalObligation {
		t.Errorf("the payload states the basis as %s", h.Basis)
	}
}

func TestAProductChangeCarriesNoBreachFields(t *testing.T) {
	p := &poster{}
	n := breach()
	n.Kind = Change
	n.Mitigated, n.Public, n.Affected = "", "", nil
	n.ID = Ident(n.Kind, n.Subject, n.Aware)
	d := Delivery{Channel: Webhook, Address: "https://customer.test/hook",
		To: who(1), Key: "k"}
	if err := hookSender(p).Send(n, d); err != nil {
		t.Fatal(err)
	}
	var h Hook
	if err := json.Unmarshal(p.got[0].body, &h); err != nil {
		t.Fatal(err)
	}
	if h.Nature != "" || h.AuthorityDue != "" {
		t.Error("a product change carries Article 33 and 34 fields, which " +
			"tells a receiver's automation this is a breach")
	}
	if !h.Declinable {
		t.Error("a product change is reported as one that cannot be declined")
	}
}

func TestANonSuccessAnswerIsAFailureAndNotASend(t *testing.T) {
	p := &poster{status: 503}
	err := hookSender(p).Send(breach(), Delivery{Channel: Webhook,
		Address: "https://customer.test/hook", To: who(1), Key: "k"})
	if err == nil {
		t.Fatal("a 503 was treated as delivered, so the retry will skip " +
			"somebody who was never told")
	}
}
