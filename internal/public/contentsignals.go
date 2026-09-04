package public

import (
	"fmt"
	"io"
	"strings"

	"github.com/quilzo/quilzo/internal/crawl"
)

// Saying in robots.txt what this site already says everywhere else.
//
// # Why another channel
//
// This site publishes its crawl terms three times already: RSL at
// /license.xml, a summary in llms.txt, and a 402 with the terms attached when
// a crawler takes content it has not licensed. All three are read by software
// that went looking. Cloudflare's Content Signals Policy is read by software
// that did not: it lives in robots.txt, which every crawler fetches whether or
// not it has heard of licensing, and it was rolled out across several million
// domains with defaults set for them.
//
// So this is the channel with the widest reach and the least meaning -- a
// preference, not a licence, and honoured by whoever chooses to. That is worth
// having anyway, because the alternative is a site whose terms are perfectly
// expressed in three formats a crawler can decline to learn.
//
// # Derived, never configured separately
//
// The three signals map onto the purposes this program already enforces:
// search is search, ai-train is train, ai-input is ai-summarize. So they are
// derived from the licence rather than set on their own.
//
// That matters more than it looks. A second place to write the same policy is
// a second place for it to be wrong, and the failure is silent in the worst
// direction: robots.txt saying ai-train=yes while the licence prohibits
// training is a site that invites the thing it then refuses, and the crawler
// followed the file it was told to follow.

// contentSignals renders the Content Signals Policy comment and directives.
//
// The policy text is required to be present as a comment for the directives to
// carry their defined meaning -- the signals are defined by that text, and a
// bare "ai-train=no" without it is three words with no agreed reading.
func contentSignals(w io.Writer, terms *crawl.Terms) {
	if terms == nil {
		return
	}
	signals := signalsFor(terms)
	if len(signals) == 0 {
		return
	}

	fmt.Fprint(w, "\n# Content-Signal directives say how this site's content "+
		"may be used, not\n# whether it may be fetched. They are derived from "+
		"the licence at\n# /license.xml, which is the binding statement; these "+
		"are the same terms in\n# the file every crawler already reads.\n")
	fmt.Fprint(w, "#\n# yes = permitted, no = not permitted, absent = no "+
		"preference stated.\n#\n")
	fmt.Fprint(w, "#   search:   building a search index and showing links "+
		"and snippets\n")
	fmt.Fprint(w, "#   ai-input: using this content as input to an "+
		"AI-generated answer\n")
	fmt.Fprint(w, "#   ai-train: using this content to train a model\n")
	fmt.Fprintf(w, "\nContent-Signal: %s\n", strings.Join(signals, ", "))
}

// signalsFor turns the licence's purposes into signals.
//
// Only what the licence actually says. A purpose that is neither permitted nor
// prohibited produces no signal at all, because "no preference stated" and
// "not permitted" are different answers and a site that has not decided should
// not be made to look as though it has.
func signalsFor(terms *crawl.Terms) []string {
	// Ordered as the policy documents them, so two sites with the same terms
	// produce the same line and a diff of a deployment is about what changed.
	order := []struct {
		signal string
		use    crawl.Use
	}{
		{"search", crawl.Search},
		{"ai-input", crawl.Summarize},
		{"ai-train", crawl.Train},
	}

	var out []string
	for _, s := range order {
		switch {
		case contains(terms.Permits, string(s.use)):
			out = append(out, s.signal+"=yes")
		case contains(terms.Prohibits, string(s.use)):
			out = append(out, s.signal+"=no")
		}
	}
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(strings.TrimSpace(v), want) {
			return true
		}
	}
	return false
}
