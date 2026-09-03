// Package crawl decides whether an automated reader may have a page, and says
// what it would cost if not.
//
// # What this adds to terms that already publish
//
// The site already publishes machine-readable terms: RSL at /license.xml,
// TDMRep, and a robots file pointing at both, with search, training and
// summarisation as separate grants. That is a declaration, and a declaration
// is unenforceable by construction — a crawler reads it or does not.
//
// This is the enforcement point. A crawler that identifies itself and asks for
// a use the terms refuse is answered 402 with a price and where to ask, rather
// than served silently and complained about afterwards.
//
// # Identity is proved, never inferred
//
// A User-Agent header is a string anybody can type. Refusing traffic on one is
// unreliable in the direction that matters — a crawler that wants the content
// changes it — and harmful in the direction that does not: a person whose
// browser or reader happens to match a pattern is turned away from a public
// page, and never finds out why.
//
// So identity here means Web Bot Auth: RFC 9421 HTTP Message Signatures over
// the request, Ed25519, with the public keys published at a well-known
// directory the crawler controls. A signature is either valid or it is not,
// and the answer does not depend on a pattern somebody maintains.
//
// # The weakness in that, stated rather than buried
//
// Only a crawler that identifies itself can be charged. One that stays
// anonymous is indistinguishable from a reader and is served, which reads
// backwards: announce yourself and pay, say nothing and take it.
//
// It is still the right trade, for the same reason robots.txt is worth having.
// This makes the terms actionable for crawlers that participate — which in
// 2026 is the large, well-funded ones with a legal department — and does
// nothing about the ones that do not, which is exactly what a declaration
// already did. What it adds is a price and a refusal instead of a sentence in
// a file.
//
// The alternative, fingerprinting, needs a view of the whole network to work
// and belongs to whoever has one. A single origin guessing at it produces
// false positives on real readers, and a CMS that turns away readers has
// broken the thing it is for.
//
// # And it never holds a payment
//
// A 402 here names a price and where to settle it. It does not take a card,
// hold a balance or confirm a transfer, because the moment this process holds
// a payment credential it needs a threat model it does not have. Terms,
// enforcement and hand-off; the settlement is somebody else's.
package crawl

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// Use is what an automated reader wants the content for.
//
// The same closed vocabulary the licence uses, because two lists of purposes
// would be two things to keep true and the first disagreement would be a
// crawler charged under terms the site never published.
type Use string

const (
	Search    Use = "search"
	Train     Use = "train"
	Summarize Use = "ai-summarize"
	// Unstated is a crawler that identified itself and said nothing about why.
	Unstated Use = ""
)

// Terms are what the site permits, refuses and charges for.
type Terms struct {
	// Permits and Prohibits are the licence's own lists, passed in rather than
	// re-read, so the answer here cannot disagree with /license.xml.
	Permits   []string
	Prohibits []string
	// Price is what a refused use costs, as an ISO 4217 code and an amount —
	// "USD 0.005". Empty means the use is refused outright rather than sold,
	// which is a different answer and is sent as a different one.
	Price string
	// Contact is where to arrange it. A refusal with nowhere to ask is a wall;
	// one with an address is a negotiation.
	Contact string
	// LicenceURL is where the full terms live.
	LicenceURL string
}

// Decision is what to do with a request.
type Decision struct {
	// Serve is true when the request should be answered normally.
	Serve bool
	// Status is what to answer with when Serve is false.
	Status int
	// Headers to set on a refusal.
	Headers map[string]string
	// Reason is for the body and the log, in words somebody can act on.
	Reason string
}

// allow is the decision to serve, and is what every unidentified request gets.
func allow() Decision { return Decision{Serve: true} }

// Decide answers whether this reader may have the page.
//
// `identified` is nil for a request that did not prove who it is, which is the
// overwhelming majority and is always served: an unidentified request is
// indistinguishable from a person, and a public site serves people.
func Decide(identified *Identity, terms Terms) Decision {
	if identified == nil {
		return allow()
	}

	use := identified.Use
	// A crawler that says nothing about why it is here is treated as the most
	// permissive thing it could be doing rather than the least. Guessing
	// "training" from silence would charge a search indexer for a use it never
	// asked for, and the site's own terms are the place to be strict, not the
	// inference.
	if use == Unstated {
		use = Search
	}

	if permitted(terms.Permits, string(use)) {
		return allow()
	}
	if !refused(terms.Prohibits, string(use)) {
		// Neither permitted nor refused: the terms are silent. Silence is not
		// a refusal — the licence says so itself, and answering 402 for a use
		// nobody wrote down would charge for something never offered.
		return allow()
	}

	// Refused. Whether that is for sale is the operator's decision and it is
	// two different answers.
	if strings.TrimSpace(terms.Price) == "" {
		return Decision{
			Status:  http.StatusForbidden,
			Headers: linkHeaders(terms, ""),
			Reason: fmt.Sprintf(
				"%s is refused by this site's terms and is not offered for a "+
					"fee. The terms are at %s", use, terms.LicenceURL),
		}
	}
	return Decision{
		Status: http.StatusPaymentRequired,
		// The header AI crawlers already read, because a price nobody can
		// parse is a price nobody pays.
		Headers: linkHeaders(terms, terms.Price),
		Reason: fmt.Sprintf(
			"%s requires a licence for this content. The price is %s per "+
				"request and the terms are at %s", use, terms.Price,
			terms.LicenceURL),
	}
}

func linkHeaders(terms Terms, price string) map[string]string {
	h := map[string]string{}
	if price != "" {
		h["crawler-price"] = price
	}
	if terms.LicenceURL != "" {
		// The relation RSL readers look for, so a crawler finds the terms from
		// the refusal without being told where to look.
		h["Link"] = "<" + terms.LicenceURL + `>; rel="license"`
	}
	if terms.Contact != "" {
		h["X-Licence-Contact"] = terms.Contact
	}
	return h
}

// permitted reports whether a use is on the allow list.
//
// "none" is handled where it means something: a licence permitting "none"
// permits nothing, which is not the same as an empty list meaning the operator
// has said nothing.
func permitted(list []string, use string) bool {
	for _, p := range list {
		if p == "none" {
			return false
		}
		if strings.EqualFold(strings.TrimSpace(p), use) {
			return true
		}
	}
	return false
}

func refused(list []string, use string) bool {
	for _, p := range list {
		p = strings.TrimSpace(p)
		// A licence prohibiting "none" prohibits nothing, and reading it as
		// "prohibits everything" would turn a permissive licence into a wall.
		if strings.EqualFold(p, "none") {
			continue
		}
		if strings.EqualFold(p, use) {
			return true
		}
	}
	return false
}

// MaxPrice reads what a crawler said it is willing to pay.
//
// Cloudflare's crawlers send crawler-max-price or crawler-exact-price, and a
// site that ignores them refuses a crawler that would have paid. Parsed rather
// than trusted: the value arrives from the client and lands in a comparison.
func MaxPrice(h http.Header) (currency string, amount float64, ok bool) {
	for _, name := range []string{"crawler-exact-price", "crawler-max-price"} {
		v := strings.TrimSpace(h.Get(name))
		if v == "" {
			continue
		}
		parts := strings.Fields(v)
		if len(parts) != 2 {
			continue
		}
		n, err := strconv.ParseFloat(parts[1], 64)
		if err != nil || n < 0 {
			continue
		}
		return strings.ToUpper(parts[0]), n, true
	}
	return "", 0, false
}

// Affordable reports whether what the crawler offered covers the asking price.
//
// Same currency only. Converting between currencies here would mean holding a
// rate, and a rate that is wrong by a day is a price that is wrong by a day —
// so a mismatch is a refusal with a reason rather than a guess.
func Affordable(price string, h http.Header) (bool, string) {
	askCur, askAmt, ok := parsePrice(price)
	if !ok {
		return false, "the configured price is not readable"
	}
	offCur, offAmt, offered := MaxPrice(h)
	if !offered {
		return false, "no price was offered"
	}
	if offCur != askCur {
		return false, fmt.Sprintf(
			"the offer is in %s and the price is in %s; this site does not "+
				"convert currencies", offCur, askCur)
	}
	if offAmt < askAmt {
		return false, fmt.Sprintf("the offer of %.6g is below %.6g",
			offAmt, askAmt)
	}
	return true, ""
}

func parsePrice(s string) (currency string, amount float64, ok bool) {
	parts := strings.Fields(strings.TrimSpace(s))
	if len(parts) != 2 {
		return "", 0, false
	}
	n, err := strconv.ParseFloat(parts[1], 64)
	if err != nil || n < 0 {
		return "", 0, false
	}
	return strings.ToUpper(parts[0]), n, true
}

// Uses lists the vocabulary, for a settings screen and an error message.
func Uses() []string {
	out := []string{string(Search), string(Train), string(Summarize)}
	sort.Strings(out)
	return out
}
