package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/rsh1k/scrivet/internal/assist"
	"github.com/rsh1k/scrivet/internal/auth"
	"github.com/rsh1k/scrivet/internal/provenance"
	"github.com/rsh1k/scrivet/internal/site"
)

// The assistant, in the interface.
//
// The important property is that nothing is written until somebody accepts it,
// and that is not a courtesy — a model's output is untrusted input, and this
// program's whole argument is that untrusted input does not get to execute or
// to be stored without passing the same gates as anything else. So the
// proposal is shown, validated, and only then written; and what is written
// carries a provenance record saying a model produced it, because publishing
// unmarked AI-generated content is what Article 50 is about.

// Assist proposes a site from a description.
type Assist struct {
	// Model is the configured model. Nil means none, which is a complete
	// configuration — the screen says so rather than offering a box that
	// cannot answer.
	Model func() (assist.Model, error)
	// Pages is what exists, so the assistant is told what it is adding to.
	Pages func() (map[string]any, error)
	// Save writes an accepted proposal into the draft. base is the commit the
	// pages were read from, so the write is compare-and-swap.
	Save func(pages map[string]any, message, author, base string) error
	// Record marks the accepted pages as model-generated.
	Record func(pages []string, model, author string) error
	// Timeout bounds one request. Zero means the default below.
	Timeout time.Duration
}

// AssistTimeout is how long a proposal may take.
//
// A bound rather than none, because the model is on the other side of a
// network and a handler that waits forever is a handler somebody's browser
// gives up on while this process still holds the request.
const AssistTimeout = 2 * time.Minute

func (s *Server) handleAssist(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}

	data := map[string]any{
		"Nav": "assist", "Title": "Assistant", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
	}
	if s.Assist == nil || s.Assist.Model == nil {
		data["Unconfigured"] = true
		s.render(w, r, "assist.html", data)
		return
	}
	m, err := s.Assist.Model()
	if err != nil || m == nil {
		data["Unconfigured"] = true
		if err != nil {
			data["Error"] = err.Error()
		}
		s.render(w, r, "assist.html", data)
		return
	}
	data["Model"] = m.Name()

	if r.Method != http.MethodPost {
		s.render(w, r, "assist.html", data)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	instruction := strings.TrimSpace(r.FormValue("instruction"))
	if instruction == "" {
		data["Error"] = "say what you want built"
		s.render(w, r, "assist.html", data)
		return
	}

	current := map[string]any{}
	if s.Assist.Pages != nil {
		if pages, err := s.Assist.Pages(); err == nil {
			current = pages
		}
	}

	timeout := s.Assist.Timeout
	if timeout <= 0 {
		timeout = AssistTimeout
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	prop, err := assist.Ask(ctx, m, instruction, current)
	if err != nil {
		// A rejection is not a failure of the product, and it says which rule
		// the answer broke. Showing that rather than "something went wrong" is
		// what lets somebody rephrase instead of giving up.
		data["Error"] = err.Error()
		data["Instruction"] = instruction
		s.render(w, r, "assist.html", data)
		return
	}

	names := make([]string, 0, len(prop.Pages))
	for name := range prop.Pages {
		names = append(names, name)
	}
	sort.Strings(names)

	// Which of them would replace something. A proposal that quietly overwrites
	// an existing page is the failure mode here, and it is only visible if the
	// collision is named before anybody clicks accept.
	var collides []string
	for _, name := range names {
		if _, exists := current[name]; exists {
			collides = append(collides, name)
		}
	}

	data["Proposal"] = prop
	data["Names"] = names
	data["Collides"] = collides
	data["Instruction"] = instruction
	data["Serialised"] = mustJSON(prop)
	s.render(w, r, "assist.html", data)
}

// handleAssistAccept writes a proposal into the draft.
//
// The proposal comes back through the form rather than being held between
// requests. It is untrusted either way — it came from a model — so it is
// re-validated here by the same function that validated it on the way out, and
// then it goes through the ordinary save path with the ordinary gates. Keeping
// it on the server would make this stateful without making it any more
// trusted.
func (s *Server) handleAssistAccept(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	if s.Assist == nil || s.Assist.Save == nil || s.Assist.Pages == nil {
		s.assistRedirect(w, r, "", "the assistant is not wired up in this build")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	prop, err := assist.ParseProposal(r.FormValue("proposal"))
	if err != nil {
		s.assistRedirect(w, r, "", err.Error())
		return
	}
	if err := assist.Validate(prop); err != nil {
		s.assistRedirect(w, r, "", err.Error())
		return
	}

	base := s.Store.GetRef(site.RefDraft)
	pages, err := s.Assist.Pages()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if pages == nil {
		pages = map[string]any{}
	}
	accepted := make([]string, 0, len(prop.Pages))
	for name, body := range prop.Pages {
		if _, exists := pages[name]; exists && r.FormValue("overwrite") == "" {
			continue
		}
		pages[name] = body
		accepted = append(accepted, name)
	}
	if len(accepted) == 0 {
		s.assistRedirect(w, r, "", "every page in the proposal already exists. "+
			"Tick the box to replace them, or ask for different names.")
		return
	}
	sort.Strings(accepted)

	modelName := r.FormValue("model")
	if err := s.Assist.Save(pages, fmt.Sprintf(
		"accept %d page(s) proposed by %s", len(accepted), modelName),
		p.Name, base); err != nil {
		s.assistRedirect(w, r, "", err.Error())
		return
	}

	// Marked as model-generated, here rather than later. The publish gate
	// already refuses unmarked pages, so writing these without a record would
	// simply move the problem to whoever tries to publish — and "unrecorded" is
	// not the same as "human-written", which is the distinction Article 50
	// turns on.
	if s.Assist.Record != nil {
		if err := s.Assist.Record(accepted, modelName, p.Name); err != nil {
			s.assistRedirect(w, r, "", fmt.Sprintf(
				"the pages were written and their provenance was not recorded: "+
					"%v. Record it on the provenance screen before publishing.",
				err))
			return
		}
	}
	s.auditPub(p, "assist.accept", "/", map[string]string{
		"model": modelName, "pages": strings.Join(accepted, ",")})

	s.assistRedirect(w, r, fmt.Sprintf(
		"wrote %s into the draft, marked as generated by %s.",
		strings.Join(accepted, ", "), modelName), "")
}

// mustJSON serialises a proposal for the round trip through the form.
//
// An error here would mean a proposal that cannot be re-encoded, which cannot
// happen for something that was just decoded from JSON — and returning the
// empty string rather than panicking means the accept form is refused by
// ParseProposal instead of taking the server down.
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// AssistProvenance is the record a proposal's pages carry.
//
// trainedAlgorithmicMedia, which is the IPTC value for something a model
// produced rather than something a person wrote with help. Exported so the
// host can build the same record without this package needing to know where
// provenance is kept.
func AssistProvenance(model, author, contentHash string) provenance.Record {
	return provenance.Record{
		ContentHash: contentHash,
		SourceType:  provenance.TrainedAlgorithmicMedia,
		Model:       model,
		Author:      author,
	}
}

func (s *Server) assistRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/assist"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}
