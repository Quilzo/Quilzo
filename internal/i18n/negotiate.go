package i18n

import (
	"sort"
	"strconv"
	"strings"
)

// Choosing a language from what the browser asked for.
//
// The request was "autonomous edge localization", and it is worth separating
// the two things that phrase can mean, because one of them is a feature and
// the other is a liability.
//
// **Serving the right existing translation, automatically, in a way a CDN can
// cache.** That is this. It is real, it is standards-bound, and getting it
// wrong is the difference between a working multilingual site and one that
// serves German to everybody because the first request happened to be German.
//
// **Producing translations automatically.** That would need a model, and it
// would mean publishing text in a language nobody on the team can read, on
// pages that carry legal and safety consequences, with no reviewer. Machine
// translation is good enough that the mistakes are fluent, which is worse than
// obviously broken output: nobody notices. It is declined, and the decline is
// written down here rather than left as an omission somebody assumes was an
// oversight.
//
// The part that is easy to get wrong and expensive to discover is the caching.
// A response that varies by Accept-Language and does not say so is a response a
// shared cache will hand to the next visitor in the wrong language — and the
// bug is invisible from the origin, which serves everybody correctly.

// Offer is a language the site actually has.
type Offer struct {
	Tag string
	// Default marks the fallback, used when nothing matches.
	Default bool
}

// Match is the outcome of negotiation, with enough detail to explain itself.
type Match struct {
	// Tag is what to serve.
	Tag string
	// Quality is the client's stated preference for it, 0 to 1.
	Quality float64
	// Exact is true when the client asked for this tag specifically rather
	// than for its language.
	Exact bool
	// Fallback is true when nothing matched and the default was used, so a
	// caller can tell "you asked for this" from "we had nothing you wanted".
	Fallback bool
}

// Negotiate picks a language from an Accept-Language header.
//
// RFC 9110 semantics, including the parts people skip:
//
//   - q=0 means *refused*, not "least preferred". A client sending
//     `de, en;q=0` is saying it will take German and will not take English,
//     and treating that as a weak preference serves exactly what was refused.
//   - `*` matches anything not otherwise named, at its own quality.
//   - Ties go to the order the site lists its languages, not the order the
//     client sent them, so the outcome is stable and an operator can control it.
//   - A tag matches a more specific offer: a request for `en` is satisfied by
//     `en-GB`. The reverse is not automatic — asking for `en-GB` and being
//     given `en-US` is a different dialect, and for prices and legal text it is
//     a different answer — but it is better than falling back to another
//     language entirely, so it is used at a lower priority.
func Negotiate(header string, offers []Offer) Match {
	fallback := ""
	for _, o := range offers {
		if o.Default {
			fallback = o.Tag
			break
		}
	}
	if fallback == "" && len(offers) > 0 {
		fallback = offers[0].Tag
	}
	if len(offers) == 0 {
		return Match{Fallback: true}
	}

	prefs := parseAccept(header)
	if len(prefs) == 0 {
		return Match{Tag: fallback, Fallback: true}
	}

	// Refusals first: anything at q=0 is out, whatever else matches it.
	refused := map[string]bool{}
	star := -1.0
	for _, p := range prefs {
		if p.q == 0 {
			refused[strings.ToLower(p.tag)] = true
		}
		if p.tag == "*" && p.q > 0 {
			star = p.q
		}
	}

	type candidate struct {
		tag   string
		q     float64
		exact bool
		rank  int // lower is better: exact, then prefix, then star
		order int // the site's own ordering, for stable ties
	}
	var best *candidate

	for i, o := range offers {
		lower := strings.ToLower(o.Tag)
		base, _, _ := strings.Cut(lower, "-")
		if refused[lower] || refused[base] {
			continue
		}
		var c *candidate
		for _, p := range prefs {
			if p.q <= 0 {
				continue
			}
			pl := strings.ToLower(p.tag)
			switch {
			case pl == lower:
				c = &candidate{o.Tag, p.q, true, 0, i}
			case pl == base && c == nil:
				// Asked for the language, offered a region of it.
				c = &candidate{o.Tag, p.q, false, 1, i}
			case strings.HasPrefix(pl, base+"-") && c == nil:
				// Asked for a region, offered a different one.
				c = &candidate{o.Tag, p.q, false, 2, i}
			}
			if c != nil && c.rank == 0 {
				break
			}
		}
		if c == nil && star > 0 {
			c = &candidate{o.Tag, star, false, 3, i}
		}
		if c == nil {
			continue
		}
		if best == nil || better(*c, *best) {
			cc := *c
			best = &cc
		}
	}

	if best == nil {
		// Nothing the client wants. Prefer a language it has not explicitly
		// refused over the default, because serving what somebody said they
		// will not take is worse than serving something they did not ask for
		// — `en;q=0` from a reader who cannot read English is a statement,
		// and answering it in English answers nobody.
		//
		// If every offer is refused there is nothing left to do but serve the
		// default. A 406 is technically available and is hostile: a person who
		// sent an over-specific header would get no page at all.
		if refused[strings.ToLower(fallback)] {
			for _, o := range offers {
				lower := strings.ToLower(o.Tag)
				base, _, _ := strings.Cut(lower, "-")
				if !refused[lower] && !refused[base] {
					return Match{Tag: o.Tag, Fallback: true}
				}
			}
		}
		return Match{Tag: fallback, Fallback: true}
	}
	return Match{Tag: best.tag, Quality: best.q, Exact: best.exact}
}

func better(a, b struct {
	tag   string
	q     float64
	exact bool
	rank  int
	order int
}) bool {
	if a.q != b.q {
		return a.q > b.q
	}
	if a.rank != b.rank {
		return a.rank < b.rank
	}
	return a.order < b.order
}

type pref struct {
	tag string
	q   float64
}

// parseAccept reads an Accept-Language header.
//
// Bounded at sixteen entries. The header is attacker-controlled and a client
// can send a thousand of them; parsing them all is work somebody else chose
// for this machine to do, and no real client sends more than a handful.
func parseAccept(header string) []pref {
	var out []pref
	for i, part := range strings.Split(header, ",") {
		if i >= 16 {
			break
		}
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tag, rest, hasQ := strings.Cut(part, ";")
		tag = strings.TrimSpace(tag)
		if tag == "" || len(tag) > 35 {
			// RFC 5646 tags are not long. A very long one is not a language.
			continue
		}
		q := 1.0
		if hasQ {
			if _, v, ok := strings.Cut(strings.TrimSpace(rest), "="); ok {
				if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
					q = f
				}
			}
		}
		if q < 0 {
			q = 0
		}
		if q > 1 {
			q = 1
		}
		out = append(out, pref{tag: tag, q: q})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].q > out[j].q })
	return out
}

// VaryHeader is what a response negotiated this way must carry.
//
// Not optional and not cosmetic. A response that varies by Accept-Language and
// does not say so is one a shared cache will hand to the next visitor in the
// wrong language — and the bug is invisible from the origin, which is serving
// everybody correctly. It is found by a customer in another country, weeks
// later, and is very hard to believe.
const VaryHeader = "Accept-Language"

// CacheKey is the value a CDN should add to its cache key: the negotiated tag
// rather than the raw header.
//
// Keying on the header itself would shatter the cache — browsers send dozens
// of distinct Accept-Language strings that all resolve to the same language,
// so every variant would be a separate entry and the hit rate would collapse
// on exactly the sites that need it most.
func (m Match) CacheKey() string {
	if m.Tag == "" {
		return "none"
	}
	return strings.ToLower(m.Tag)
}
