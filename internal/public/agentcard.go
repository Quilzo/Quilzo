package public

import (
	"encoding/json"
	"net/http"
)

// The agent card, at the path A2A discovery looks in.
//
// # Why the public server and not the admin
//
// Discovery is for strangers. A card behind authentication is a card nobody
// can find, which defeats the only thing it is for. That is the same reasoning
// as robots.txt, the RSL licence and the catalogue feed — all published here,
// all statements this deployment makes to whoever asks.
//
// The consequence is stated rather than glossed: publishing a card tells the
// internet which agents this store runs, what they may read, and what they may
// do. That is a decision an operator makes deliberately, so it is off until
// somebody turns it on.
//
// # It is generated, and validated, on the way out
//
// The card is built from the manifests the sessions actually enforce and then
// checked against the shape A2A specifies. A deployment that would publish an
// invalid card serves nothing instead: no card is a site that is not
// discoverable, which is true and harmless. An invalid one is a site that looks
// discoverable and breaks whatever tried to use it, and a July 2026 survey
// found most published cards are in exactly that state.

// agentCard serves /.well-known/agent-card.json.
func (st *Site) agentCard(w http.ResponseWriter, r *http.Request) {
	if st.AgentCard == nil {
		// Nothing declared, nothing served. A card that answered with an empty
		// skills list would be a claim that this store runs no agents, which is
		// a different and stronger statement than "this store does not publish
		// a card".
		http.NotFound(w, r)
		return
	}
	card, err := st.AgentCard()
	if err != nil {
		http.Error(w, "the agent card could not be built",
			http.StatusInternalServerError)
		return
	}
	body, err := json.MarshalIndent(card, "", "  ")
	if err != nil {
		http.Error(w, "the agent card could not be rendered",
			http.StatusInternalServerError)
		return
	}
	// The registered media type for A2A discovery documents is JSON; served as
	// such rather than as a bare application/json blob with no cache policy,
	// because a card is read by software that will fetch it repeatedly.
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(body)
}
