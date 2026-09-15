// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

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

	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/auth"
	publishgate "github.com/quilzo/quilzo/internal/gate"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
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
	// Gates runs every unwaivable content check against what a proposal would
	// make, without publishing and without moving anything anybody can see.
	//
	// The checks were only ever asked at publication, which is the last
	// possible moment and the wrong one for this: a model writes a claim with
	// nothing behind it, or a reference to a page that does not exist, a
	// person accepts it because it reads well, and the refusal arrives days
	// later against a draft nobody remembers proposing. Asking here turns a
	// publish-time refusal into something the model can be told to fix while
	// the instruction is still on the screen.
	//
	// Nil means the loop is absent and the screen says nothing about gates,
	// rather than saying a proposal is clean when nothing checked it.
	Gates func(pages map[string]any) (*publishgate.Report, []publishgate.Finding, error)
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
	// What the gates said about the last attempt, if this is a second one.
	//
	// Appended to what the model is asked rather than shown to the person and
	// left there: the findings name a page and say what is wrong with it, in
	// the same words the publish refusal uses, and that is already an
	// instruction. What is displayed stays the original ask, because that is
	// what the person wrote and what they will edit if this goes round again.
	asked := instruction
	if fix := strings.TrimSpace(r.FormValue("fix")); fix != "" {
		if len(fix) > maxFixNote {
			fix = fix[:maxFixNote]
		}
		asked = instruction + "\n\n" + fix
		data["Retried"] = true
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

	prop, err := assist.Ask(ctx, m, asked, current)
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
	s.gateProposal(data, prop, current)
	s.render(w, r, "assist.html", data)
}

// maxFixNote bounds what a browser may append to the next instruction.
//
// The findings are built here and put in a hidden field, so the field comes
// back from a browser and is not to be trusted with the length either: it is
// appended to what a model is asked, and an unbounded one is a way to spend
// somebody's token budget from a form post.
const maxFixNote = 4000

// gateProposal asks every unwaivable content check about what this proposal
// would make, and builds the instruction that would fix what it found.
//
// Not a refusal. The draft is where unfinished work belongs, and a proposal
// that would not publish yet is an ordinary thing to accept and finish by
// hand. What it must not be is a surprise at publication — so it is said here,
// where the model that wrote it is still one button away.
func (s *Server) gateProposal(data map[string]any, prop *assist.Proposal,
	current map[string]any) {

	if s.Assist == nil || s.Assist.Gates == nil {
		return
	}
	// What the draft would hold if this were accepted, overwrite and all: the
	// gates are about the set being published, so checking the proposal's
	// pages alone would miss every finding that is about how they sit beside
	// what is already there — a reference to a page that is not in the draft,
	// a menu entry pointing at nothing.
	would := make(map[string]any, len(current)+len(prop.Pages))
	for name, body := range current {
		would[name] = body
	}
	for name, body := range prop.Pages {
		would[name] = body
	}

	refused, advisory, err := s.Assist.Gates(would)
	if err != nil {
		// Said, not swallowed. "The claim check could not run" reaching
		// somebody as silence is the failure mode internal/gate names.
		data["GateError"] = err.Error()
		return
	}
	if len(advisory) > 0 {
		data["GateAdvice"] = findingLines(advisory)
	}
	if refused == nil {
		data["GateClean"] = true
		return
	}
	data["GateRefusal"] = refused.Check.Refusal(len(refused.Findings))
	data["GateFindings"] = findingLines(refused.Findings)
	data["Fix"] = fixNote(refused)
}

// fixNote is what the model is told about its own draft.
//
// The publish refusal's own sentence, then the findings. Not a rewritten
// version of them: the refusal already has to say what to do about it — that
// is the contract every Check.Refusal is written to — so paraphrasing it here
// would be a second, worse copy that drifts from the one a person sees.
func fixNote(r *publishgate.Report) string {
	var b strings.Builder
	b.WriteString("Your last answer would not publish. ")
	b.WriteString(r.Check.Refusal(len(r.Findings)))
	b.WriteString("\n")
	for _, f := range r.Findings {
		b.WriteString("\n- ")
		b.WriteString(f.String())
	}
	b.WriteString("\n\nWrite the pages again with those fixed. " +
		"Keep everything else the same.")
	if b.Len() > maxFixNote {
		return b.String()[:maxFixNote]
	}
	return b.String()
}

// findingLines is the findings as text, for a screen.
func findingLines(fs []publishgate.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.String())
	}
	return out
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
	// Whether they may write anything. Which pages is asked below, once the
	// proposal has been read — this handler writes whatever names the proposal
	// carries, and the proposal comes out of the form, so the site-wide
	// question was the one thing standing between a scoped author and every
	// page in the store.
	if !s.canAnywhere(w, r, p, auth.ActEditDraft) {
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
	// Every page the proposal names, before any of them is written. All or
	// nothing on purpose: accepting the permitted half of a proposal and
	// dropping the rest would leave a half-applied change nobody asked for,
	// and the person would be told it worked.
	for name := range prop.Pages {
		if !s.canPage(w, r, p, auth.ActEditDraft, name) {
			return
		}
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
