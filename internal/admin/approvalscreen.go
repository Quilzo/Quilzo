// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/approval"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/seckit"
	"github.com/quilzo/quilzo/internal/webauthn"
)

// The approvals of the security record: what waits for its approvers, the
// one page where each is approved, batches of them, the decisions held with
// their approvals, the review a decision made alone owes, and the
// separation policy that says who may approve what.
//
// Everything here works with the page's script off but the passkey
// ceremony itself, which a browser runs only from a script: the lists, each
// decision with the hash of exactly what it shows, opening a batch's items,
// rejecting. Approving without the script says so, and says how an
// administrator at the store's console approves the same hash instead.
//
// The module's screens are registered from this file (internal/register's
// guide), and its templates are assets/record_approval*.html.

func init() {
	registerScreens(screens{
		module: "approval",
		routes: []screenRoute{
			{path: "/register/approvals", handle: (*Server).handleRecordApprovals},
			{path: "/register/approvals/item/", handle: (*Server).handleApprovalItem},
			{path: "/register/approvals/batch", handle: (*Server).handleApprovalBatchStart},
			{path: "/register/approvals/batch/", handle: (*Server).handleApprovalBatch},
			{path: "/register/approvals/held/", handle: (*Server).handleApprovalHeld},
			{path: "/register/approvals/review/", handle: (*Server).handleApprovalReview},
			{path: "/register/approvals/policy", handle: (*Server).handleApprovalPolicy},
		},
		nav: []navEntry{{
			destination: destination{Key: "signoff", Label: "Sign-off", Path: "/register/approvals", Group: "Assurance",
				Doc: "compliance", Needs: auth.ActView},
			icon: "fingerprint", area: register.Area,
			also: []string{"approvals", "approve", "sign-off", "separation of duties", "four eyes", "approved alone",
				"compensating review", "batch approval", "risk acceptance", "exceptions", "separation policy"},
		}},
	})
}

// phishableSignIn is what a person who decides here is told when their
// sign-in can be phished.
const phishableSignIn = "You can approve decisions, accept risks, publish outside the organisation or administer here, " +
	"and your organisation's sign-in did not say it used a method that cannot be phished. Confirm it is you with your passkey."

// decidingAtoms are the permissions whose holders sign in with a method that
// cannot be phished, beside administering the whole site.
var decidingAtoms = []auth.Action{auth.ActAcceptRisk, auth.ActApproveException, auth.ActSignBoardPack,
	auth.ActPublishExternal, auth.ActManageConnectors, auth.ActRecordMinute, auth.ActApprove}

// mustResistPhishing reports whether a person's sign-in has to be one that
// cannot be phished: the separation policy asks it, and they may approve,
// accept a risk, publish outside the organisation or administer.
func (s *Server) mustResistPhishing(name string) bool {
	if s.Store == nil || s.Policy == nil {
		return false
	}
	pol, _, err := approval.LoadPolicy(s.Store.Root())
	if err == nil && !pol.PhishingResistant {
		return false
	}
	// A policy that cannot be read asks the stricter thing.
	if s.Policy.Evaluate(name, auth.ActGrant, "/").Allowed {
		return true
	}
	for _, a := range decidingAtoms {
		if s.Policy.AnywhereUnder(name, a, register.Area) {
			return true
		}
	}
	return false
}

// approvalsFor is this server's approvals module.
func (s *Server) approvalsFor() *approval.Approvals {
	reg := register.Open(s.Store)
	reg.Audit = s.recordRegister
	if s.AuditReady != nil {
		reg.Ready = s.AuditReady
	}
	m := &approval.Approvals{Root: s.Store.Root(), Register: reg, Access: s.Policy, Audit: s.recordRegister}
	if s.Dual != nil && s.Dual.Store != nil {
		m.Settling = s.Dual.Store.Settling
	}
	return m
}

// recordRegister writes an audit record of the register or its approvals:
// through the host's own writer where it has one, which keeps the outcome
// and the kind of actor as they are, and otherwise through Audit.
func (s *Server) recordRegister(rec audit.Record) error {
	if s.AuditRecord != nil {
		return s.AuditRecord(rec)
	}
	d := map[string]string{"by": rec.Principal, "outcome": string(rec.Outcome)}
	for k, v := range rec.Detail {
		d[k] = v
	}
	s.audit(rec.Action, rec.Resource, d)
	return nil
}

// approver is the signed-in person as the approvals module sees them.
func (s *Server) approver(p principal) approval.Person {
	kind := audit.KindService
	if p.Session {
		kind = audit.KindHuman
	}
	return approval.Person{Name: p.Name, Kind: kind, Verified: true, Methods: p.Methods,
		May: func(act auth.Action, resource string) error {
			if s.allows(p, act, resource) {
				return nil
			}
			return fmt.Errorf("%s may not %s on %s", p.Name, act, resource)
		}}
}

// approvalsReady is a signed-in person who may read the register, and its
// approvals.
func (s *Server) approvalsReady(w http.ResponseWriter, r *http.Request) (principal, *approval.Approvals, bool) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return p, nil, false
	}
	if !s.can(w, r, p, auth.ActView, register.Area) {
		return p, nil, false
	}
	return p, s.approvalsFor(), true
}

// approvalRow is one waiting decision as the list shows it.
type approvalRow struct {
	ID, Kind, Label, Rule, Over, Href, NotBatchable string
	Signed, Needed, Of                              int
	Hash                                            seckit.Cell
	Batchable                                       bool
}

func (s *Server) handleRecordApprovals(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/register/approvals" {
		http.NotFound(w, r)
		return
	}
	p, m, ok := s.approvalsReady(w, r)
	if !ok {
		return
	}
	s.renderApprovals(w, r, p, m, nil, r.URL.Query().Get("said"))
}

func (s *Server) renderApprovals(w http.ResponseWriter, r *http.Request, p principal, m *approval.Approvals,
	problems []seckit.Problem, said string) {
	waiting, err := m.Waiting()
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	held, err := m.Held()
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	me, _ := approval.PeopleAt(s.Store.Root()).Known(p.Name)
	var rows []approvalRow
	for _, a := range waiting {
		row := approvalRow{ID: string(a.Proposal.ID), Kind: string(a.Proposal.Kind), Label: labelOf(a.Proposal.Record, a.Proposal.ID),
			Rule: a.Rule.Name, Over: strings.Join(a.Over, "; "), Href: "/register/approvals/item/" + string(a.Proposal.ID),
			Signed: len(a.Signed), Needed: a.Needed, Of: a.Of, Hash: seckit.HashCell(string(a.Hash))}
		switch {
		case a.Raisers(me) && !a.AloneFor(me):
			row.NotBatchable = "You raised it"
		case !s.allows(p, a.Rule.Atom, kindResource(a.Proposal.Kind)):
			row.NotBatchable = "Not yours to approve"
		default:
			row.Batchable = true
		}
		rows = append(rows, row)
	}
	var heldRows []seckit.Row
	for _, h := range held {
		status := seckit.MustBadge(seckit.Good, "Approved")
		switch {
		case h.Lapsed:
			status = seckit.Lapsed
		case h.Overdue:
			status = seckit.MustBadge(seckit.Bad, "Review overdue")
		case h.Approval.Alone && h.Review == nil:
			status = seckit.Alone
		case h.Review != nil && h.Review.Outcome == "challenged":
			status = seckit.MustBadge(seckit.Bad, "Challenged")
		case h.Review != nil:
			status = seckit.MustBadge(seckit.Good, "Reviewed")
		}
		lapses := seckit.TextCell("Does not lapse")
		if h.Approval.Expires != 0 {
			lapses = seckit.TimeCell(h.Approval.Expires.At())
		}
		heldRows = append(heldRows, seckit.Row{Head: seckit.LinkCell("/register/approvals/held/"+string(h.Record), labelOf2(h)),
			Cells: []seckit.Cell{seckit.TextCell(string(h.Kind)), seckit.BadgeCell(status),
				seckit.TextCell(fmt.Sprintf("%d of %d needed", len(h.Approval.Signers), h.Approval.Needed)), lapses,
				seckit.HashCell(string(h.Approval.Surface))}})
	}
	table, err := seckit.NewTable("Decisions the register holds with their approvals",
		[]string{"Decision", "Kind", "Where it stands", "Approvers", "Lapses", "Hash approved"}, heldRows)
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	data := map[string]any{"Title": "Sign-off", "Nav": "signoff", "Principal": p,
		"Header": seckit.Header{Title: "Sign-off", Lead: "Risks accepted, exceptions granted and the other decisions of " +
			"the security record, each approved by the people the separation policy names, with a passkey bound to the " +
			"hash of exactly what they were shown."},
		"Waiting": rows, "Held": len(heldRows) > 0, "HeldTable": table, "Problems": problems, "Said": said,
		"EmptyWaiting": seckit.Empty{Title: "Nothing is waiting for an approval",
			Body: "A decision somebody raises, or a crew proposes, waits here for the people who may approve it."},
		"EmptyHeld": seckit.Empty{Title: "The register holds no approved decisions yet",
			Body: "Once a decision is approved it is listed here with where it stands: reviewed, owing a review, or lapsed."},
	}
	s.render(w, r, "record_approvals.html", data)
}

// kindResource is the resource a kind's records are asked about.
func kindResource(k register.Kind) string {
	spec, _ := register.SpecOf(string(k))
	return spec.Resource()
}

// labelOf names a record by its own reference and title, or its kind and
// identifier.
func labelOf(rec register.Record, id register.ID) string {
	if l := register.Label(rec); l != "" {
		return l
	}
	return string(rec.Kind()) + " " + seckit.Short(string(id))
}

func labelOf2(h approval.Held) string {
	if h.Label != "" {
		return h.Label
	}
	return string(h.Kind) + " " + seckit.Short(string(h.Record))
}

// ceremonies are the passkey challenges issued for approvals, by value:
// each is single use, for one person, one purpose and one hash, and lives
// as long as a sign-in's.
var (
	ceremoniesMu sync.Mutex
	ceremonies   = map[string]ceremony{}
)

type ceremony struct {
	principal string
	purpose   approval.Purpose
	of        register.Digest
	expires   time.Time
}

// issueCeremony is a fresh challenge for a person to sign over a hash.
func issueCeremony(who string, p approval.Purpose, of register.Digest, now time.Time) (string, error) {
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		return "", fmt.Errorf("no entropy for a challenge: %w", err)
	}
	ch, err := approval.Challenge(p, of, n)
	if err != nil {
		return "", err
	}
	ceremoniesMu.Lock()
	defer ceremoniesMu.Unlock()
	for k, c := range ceremonies {
		if now.After(c.expires) {
			delete(ceremonies, k)
		}
	}
	ceremonies[ch] = ceremony{principal: who, purpose: p, of: of, expires: now.Add(webauthn.ChallengeLifetime)}
	return ch, nil
}

// takeCeremony uses a challenge up, if it was issued to this person and has
// not expired.
func takeCeremony(v, who string, now time.Time) (ceremony, bool) {
	ceremoniesMu.Lock()
	defer ceremoniesMu.Unlock()
	c, ok := ceremonies[v]
	delete(ceremonies, v)
	if !ok || now.After(c.expires) || !auth.SamePerson(c.principal, who) {
		return ceremony{}, false
	}
	return c, true
}

// ceremonyBody is what the page's script sends once the passkey has signed.
type ceremonyBody struct {
	webauthn.Assertion
	Challenge string `json:"challenge"`
	// Outcome is a review's: upheld or challenged.
	Outcome string `json:"outcome,omitempty"`
}

// startCeremony answers a page's script asking for a challenge over a hash.
func (s *Server) startCeremony(w http.ResponseWriter, r *http.Request, p principal, purpose approval.Purpose, of register.Digest) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "this is a ceremony endpoint and takes a POST", http.StatusMethodNotAllowed)
		return
	}
	if s.Passkeys == nil {
		writeJSONError(w, http.StatusServiceUnavailable, errNoPasskeyStore)
		return
	}
	party, err := s.partyFor(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	ch, err := issueCeremony(p.Name, purpose, of, time.Now())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, map[string]any{"challenge": ch, "rpId": party.ID, "surface": of})
}

// passkeyProof checks the assertion a page's script sent, live, against the
// person's own registered passkey, and returns it as the proof the
// approvals module keeps. The counter is written back, as at a sign-in.
func (s *Server) passkeyProof(r *http.Request, p principal, purpose approval.Purpose, body ceremonyBody) (*approval.PasskeyProof, int, error) {
	if s.Passkeys == nil {
		return nil, http.StatusServiceUnavailable, errNoPasskeyStore
	}
	c, ok := takeCeremony(body.Challenge, p.Name, time.Now())
	if !ok || c.purpose != purpose {
		return nil, http.StatusBadRequest, fmt.Errorf("this challenge is unknown, has expired or was not issued to you for this. Start again")
	}
	id, err := base64.RawURLEncoding.DecodeString(body.ID)
	if err != nil {
		if id, err = base64.URLEncoding.DecodeString(body.ID); err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("the credential id is not base64url")
		}
	}
	cred, found := s.Passkeys.lookup(id)
	if !found || !auth.SamePerson(cred.Principal, p.Name) {
		return nil, http.StatusForbidden, fmt.Errorf("that passkey is not one of yours: an approval is signed with your own")
	}
	party, err := s.partyFor(r)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	party.ID = cred.RelyingParty
	used, err := party.Verify(cred.Credential, body.Challenge, body.Assertion)
	if err != nil {
		s.audit("approval.passkey-refused", register.Area, map[string]string{"by": p.Name, "why": err.Error()})
		return nil, http.StatusUnauthorized, fmt.Errorf("your passkey's signature did not verify: %w", err)
	}
	if err := s.Passkeys.noteUse(cred.ID, used, time.Now()); err != nil {
		return nil, http.StatusConflict, err
	}
	return &approval.PasskeyProof{RelyingParty: cred.RelyingParty, Origin: party.Origin, Credential: cred.ID,
		PublicKey: cred.PublicKey, Algorithm: cred.Algorithm, Challenge: body.Challenge, Assertion: body.Assertion}, 0, nil
}

// fromScript reports whether a POST came from the page's script, as JSON,
// rather than from the form with the script off.
func fromScript(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
}

// withoutScript is what approving with the page's script off says: the
// passkey has to sign, a browser lets only a script ask it, and the
// console can approve the same hash.
func (s *Server) withoutScript(w http.ResponseWriter, r *http.Request, p principal, line string) {
	s.render(w, r, "message.html", map[string]any{"Status": http.StatusUnprocessableEntity,
		"Title": "Approve with your passkey", "Principal": p, "Heading": "Your passkey has to sign this",
		"Body": "An approval here is your passkey's signature over the hash of what you were shown, and a browser lets " +
			"only the page's script ask a passkey to sign. Turn the script on for this page and approve again, or approve " +
			"at the store's console as an administrator: " + line})
}

// approvalError answers a refusal by the separation policy, or another
// failure, as the script that asked reads it.
func approvalError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, register.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, err)
	case errors.Is(err, approval.ErrRefused), errors.Is(err, register.ErrRefused), errors.Is(err, register.ErrModel):
		writeJSONError(w, http.StatusForbidden, err)
	case errors.Is(err, register.ErrInvalid):
		writeJSONError(w, http.StatusUnprocessableEntity, err)
	default:
		writeJSONError(w, http.StatusInternalServerError, err)
	}
}

func (s *Server) handleApprovalItem(w http.ResponseWriter, r *http.Request) {
	p, m, ok := s.approvalsReady(w, r)
	if !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/register/approvals/item/")
	idPart, action, _ := strings.Cut(rest, "/")
	id := register.ID(idPart)
	switch action {
	case "":
		a, err := m.Ask(id)
		if errors.Is(err, register.ErrNotFound) || errors.Is(err, approval.ErrRefused) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.registerUnreadable(w, r, p, err)
			return
		}
		s.renderAsk(w, r, p, a, "", "")
	case "challenge":
		a, err := m.Ask(id)
		if err != nil {
			approvalError(w, err)
			return
		}
		s.startCeremony(w, r, p, approval.ForApproval, a.Hash)
	case "approve":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "approving takes a POST", http.StatusMethodNotAllowed)
			return
		}
		a, err := m.Ask(id)
		if !fromScript(r) {
			hash := "HASH"
			if err == nil {
				hash = string(a.Hash)
			}
			s.withoutScript(w, r, p, "quilzo approval approve "+string(id)+" --surface "+hash)
			return
		}
		if err != nil {
			approvalError(w, err)
			return
		}
		var body ceremonyBody
		if err := readJSON(r, &body); err != nil {
			writeJSONError(w, http.StatusBadRequest, err)
			return
		}
		proof, code, err := s.passkeyProof(r, p, approval.ForApproval, body)
		if err != nil {
			writeJSONError(w, code, err)
			return
		}
		out, err := m.Sign(s.approver(p), id, approval.Proof{Passkey: proof})
		if err != nil && (out == nil || !out.Done) {
			approvalError(w, err)
			return
		}
		said := fmt.Sprintf("Approved: %d of %d approvals given. Your passkey signed %s.", out.Signed, out.Needed, out.Surface)
		next := "/register/approvals/item/" + string(id)
		if out.Done {
			said = "Approved and written to the register. The receipt carries the hash " + string(out.Surface) + "."
			next = "/register/approvals/held/" + string(id)
		}
		writeJSON(w, map[string]any{"done": out.Done, "signed": out.Signed, "needed": out.Needed, "surface": out.Surface,
			"evidence": out.Evidence, "receipt": out.Receipt, "said": said, "next": next})
	case "reject":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "rejecting takes a POST", http.StatusMethodNotAllowed)
			return
		}
		if err := m.Reject(s.approver(p), id); err != nil {
			s.render(w, r, "message.html", map[string]any{"Status": http.StatusForbidden, "Title": "Sign-off",
				"Principal": p, "Heading": "It was not rejected", "Body": err.Error()})
			return
		}
		http.Redirect(w, r, "/register/approvals?said="+url.QueryEscape("Rejected: nothing was written to the register."),
			http.StatusSeeOther)
	default:
		http.NotFound(w, r)
	}
}

// renderAsk draws one waiting decision: what it is, what it cites, what it
// changes, who may approve it, and the hash of all of it beside the button.
func (s *Server) renderAsk(w http.ResponseWriter, r *http.Request, p principal, a *approval.Ask, batch, notice string) {
	spec, _ := register.SpecOf(string(a.Proposal.Kind))
	fields, err := seckit.NewTable("Its fields, as it would be written", []string{"Field", "Value", "What it is for"},
		fieldRows(spec.Fields, register.WithApproval(a.Proposal.Record, nil)))
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	var diffRows []seckit.Row
	for _, c := range a.Surface.Diff {
		before := "Not there"
		if len(c.Before) > 0 {
			before = string(c.Before)
		}
		after := "Removed"
		if len(c.After) > 0 {
			after = string(c.After)
		}
		diffRows = append(diffRows, seckit.Row{Head: seckit.TextCell(c.Field), Cells: []seckit.Cell{seckit.TextCell(before), seckit.TextCell(after)}})
	}
	diff, err := seckit.NewTable("What changes, field by field, from the record as the register holds it",
		[]string{"Field", "Now", "Once approved"}, diffRows)
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	me, _ := approval.PeopleAt(s.Store.Root()).Known(p.Name)
	label := labelOf(a.Proposal.Record, a.Proposal.ID)
	base := "/register/approvals/item/" + string(a.Proposal.ID)
	if batch != "" {
		base = "/register/approvals/batch/" + batch
	}
	ap := seckit.Approval{What: "Approve " + label, Hash: a.Hash, Who: a.Rule.Describe(), Needed: a.Needed, Of: a.Of,
		Alone: a.AloneFor(me), Button: "Approve with my passkey"}
	if batch == "" {
		ap.Action = base + "/approve"
	}
	var signed []seckit.Event
	for _, sg := range a.Signed {
		signed = append(signed, seckit.Event{At: sg.At.At(), What: "Approved, by " + string(sg.Method), By: seckit.Short(string(sg.Subject)),
			Hash: string(sg.Evidence)})
	}
	proposer, byAgent := string(a.Proposal.Subject), a.Proposal.Agent != ""
	if byAgent {
		proposer = a.Proposal.Agent
	}
	n, _ := nonce()
	data := map[string]any{"Title": label, "Nav": "signoff", "Principal": p, "Nonce": n,
		"Header": seckit.Header{Title: label, Lead: string(a.Proposal.Kind) + ", waiting for approval under the rule " + a.Rule.Name + "."},
		"ID":     string(a.Proposal.ID), "Hash": string(a.Hash), "Fields": fields, "Diff": diff, "Evidence": a.Surface.Evidence,
		"Signed": signed, "Approval": ap, "Notice": notice, "Why": a.Proposal.Why, "Proposer": proposer, "ByAgent": byAgent,
		"Over": a.Over}
	if batch == "" {
		data["Ceremony"] = map[string]any{"Nonce": n, "Challenge": base + "/challenge", "Approve": base + "/approve"}
		data["Reject"] = base + "/reject"
	} else {
		data["Back"] = map[string]string{"Href": "/register/approvals/batch/" + batch, "Text": "Back to the batch"}
	}
	s.passkeyPolicy(w, n)
	s.render(w, r, "record_approval.html", data)
}

// rootOf is a batch's root from its address, which carries the hash
// without its "sha256:".
func rootOf(hex string) register.Digest { return register.Digest("sha256:" + hex) }

func (s *Server) handleApprovalBatchStart(w http.ResponseWriter, r *http.Request) {
	p, m, ok := s.approvalsReady(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "a batch is started with a POST", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	var ids []register.ID
	for _, v := range r.PostForm["id"] {
		ids = append(ids, register.ID(v))
	}
	b, err := m.StartBatch(s.approver(p), ids)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.renderApprovals(w, r, p, m, []seckit.Problem{{Field: "batch", Label: "Batch", Message: err.Error()}}, "")
		return
	}
	http.Redirect(w, r, "/register/approvals/batch/"+strings.TrimPrefix(string(b.Root), "sha256:"), http.StatusSeeOther)
}

// batchRow is one item of a batch as its page lists it.
type batchRow struct {
	N                         int
	ID, Kind, Label, Href     string
	Hash                      seckit.Cell
	Status                    seckit.Badge
	Seconds                   int64
	Sampled, Opened, Changing bool
}

func (s *Server) handleApprovalBatch(w http.ResponseWriter, r *http.Request) {
	p, m, ok := s.approvalsReady(w, r)
	if !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/register/approvals/batch/")
	hex, action, _ := strings.Cut(rest, "/")
	root := rootOf(hex)
	switch {
	case action == "":
		b, err := m.BatchOf(s.approver(p), root)
		if errors.Is(err, approval.ErrNoBatch) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.registerUnreadable(w, r, p, err)
			return
		}
		s.renderBatch(w, r, p, m, b)
	case strings.HasPrefix(action, "item/"):
		b, a, err := m.OpenInBatch(s.approver(p), root, register.ID(strings.TrimPrefix(action, "item/")))
		if errors.Is(err, approval.ErrNoBatch) || errors.Is(err, register.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		if err != nil {
			s.render(w, r, "message.html", map[string]any{"Status": http.StatusForbidden, "Title": "Sign-off",
				"Principal": p, "Heading": "This is not your batch to open", "Body": err.Error()})
			return
		}
		notice := ""
		for _, it := range b.Items {
			if it.Record == a.Proposal.ID && it.Surface != a.Hash {
				notice = "This decision has changed since the batch was shown, so the batch cannot approve it; show the batch again."
			}
		}
		s.renderAsk(w, r, p, a, hex, notice)
	case action == "challenge":
		b, err := m.BatchOf(s.approver(p), root)
		if err != nil {
			approvalError(w, err)
			return
		}
		s.startCeremony(w, r, p, approval.ForBatch, b.Root)
	case action == "approve":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "approving takes a POST", http.StatusMethodNotAllowed)
			return
		}
		if !fromScript(r) {
			s.withoutScript(w, r, p, "the console approves one decision at a time: quilzo approval approve ID --surface HASH")
			return
		}
		var body ceremonyBody
		if err := readJSON(r, &body); err != nil {
			writeJSONError(w, http.StatusBadRequest, err)
			return
		}
		proof, code, err := s.passkeyProof(r, p, approval.ForBatch, body)
		if err != nil {
			writeJSONError(w, code, err)
			return
		}
		out, err := m.SignBatch(s.approver(p), root, approval.Proof{Passkey: proof})
		if err != nil {
			approvalError(w, err)
			return
		}
		done := 0
		for _, o := range out.Items {
			if o != nil && o.Done {
				done++
			}
		}
		writeJSON(w, map[string]any{"root": out.Root, "evidence": out.Evidence, "receipt": out.Receipt, "items": out.Items,
			"said": fmt.Sprintf("Approved %d decisions by one signature over the root %s; %d of them are written to the "+
				"register, and the rest wait for their other approvers.", len(out.Items), out.Root, done),
			"next": "/register/approvals?said=" + url.QueryEscape(fmt.Sprintf("A batch of %d approved.", len(out.Items)))})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) renderBatch(w http.ResponseWriter, r *http.Request, p principal, m *approval.Approvals, b *approval.Batch) {
	hex := strings.TrimPrefix(string(b.Root), "sha256:")
	var rows []batchRow
	for i, it := range b.Items {
		row := batchRow{N: i + 1, ID: string(it.Record), Kind: string(it.Kind), Label: string(it.Kind) + " " + seckit.Short(string(it.Record)),
			Href: "/register/approvals/batch/" + hex + "/item/" + string(it.Record), Hash: seckit.HashCell(string(it.Surface)),
			Seconds: it.Seconds, Sampled: it.Sampled, Opened: it.Opened != 0}
		if a, err := m.Ask(it.Record); err == nil {
			row.Label = labelOf(a.Proposal.Record, a.Proposal.ID)
			row.Changing = a.Hash != it.Surface
		}
		switch {
		case it.Sampled && it.Opened == 0:
			row.Status = seckit.MustBadge(seckit.Warn, "Open this first")
		case it.Sampled:
			row.Status = seckit.MustBadge(seckit.Good, "Opened, as asked")
		case it.Opened != 0:
			row.Status = seckit.MustBadge(seckit.Info, "Opened")
		default:
			row.Status = seckit.MustBadge(seckit.Neutral, "Not opened")
		}
		rows = append(rows, row)
	}
	n, _ := nonce()
	data := map[string]any{"Title": "A batch of decisions", "Nav": "signoff", "Principal": p, "Nonce": n,
		"Header": seckit.Header{Title: "A batch of decisions", Lead: fmt.Sprintf("%d decisions, approved together by one passkey "+
			"signature over the Merkle root of what each shows, in this order.", len(b.Items))},
		"Rows": rows, "Root": string(b.Root), "Short": seckit.Short(string(b.Root)), "Unopened": b.Unopened(),
		"Until": b.Until.At(), "Action": "/register/approvals/batch/" + hex + "/approve",
		"Ceremony": map[string]any{"Nonce": n, "Challenge": "/register/approvals/batch/" + hex + "/challenge",
			"Approve": "/register/approvals/batch/" + hex + "/approve"}}
	s.passkeyPolicy(w, n)
	s.render(w, r, "record_approval_batch.html", data)
}

func (s *Server) handleApprovalHeld(w http.ResponseWriter, r *http.Request) {
	p, m, ok := s.approvalsReady(w, r)
	if !ok {
		return
	}
	id := register.ID(strings.TrimPrefix(r.URL.Path, "/register/approvals/held/"))
	h, err := s.heldOne(m, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.renderHeld(w, r, p, m, h)
}

// heldOne is one decision the register holds with its approval.
func (s *Server) heldOne(m *approval.Approvals, id register.ID) (approval.Held, error) {
	all, err := m.Held()
	if err != nil {
		return approval.Held{}, err
	}
	for _, h := range all {
		if h.Record == id {
			return h, nil
		}
	}
	return approval.Held{}, register.ErrNotFound
}

// signerRow is one approver of a held decision, with whether their
// evidence checks.
type signerRow struct {
	Subject, Method, Evidence, Batch, Checks string
	At                                       time.Time
	Holds                                    bool
}

func (s *Server) renderHeld(w http.ResponseWriter, r *http.Request, p principal, m *approval.Approvals, h approval.Held) {
	a := h.Approval
	var signers []signerRow
	for _, sg := range a.Signers {
		row := signerRow{Subject: string(sg.Subject), Method: string(sg.Method), Evidence: string(sg.Assertion),
			Batch: string(sg.Batch), At: sg.At.At()}
		if row.Method == "" {
			row.Method = "passkey"
		}
		ev, err := approval.LoadEvidence(s.Store.Root(), sg.Assertion)
		switch {
		case err != nil:
			row.Checks = "Not checked: " + err.Error()
		case ev.Check() != nil:
			row.Checks = "Does not hold: " + ev.Check().Error()
		default:
			row.Holds = true
			row.Checks = "The signature holds, over " + string(ev.For)
		}
		signers = append(signers, row)
	}
	status := []seckit.Badge{seckit.MustBadge(seckit.Good, "Approved")}
	if a.Alone {
		status = append(status, seckit.Alone)
	}
	if h.Overdue {
		status = append(status, seckit.MustBadge(seckit.Bad, "Review overdue"))
	}
	if h.Lapsed {
		status = append(status, seckit.Lapsed)
	}
	label := labelOf2(h)
	data := map[string]any{"Title": label, "Nav": "signoff", "Principal": p,
		"Header": seckit.Header{Title: label, Lead: string(h.Kind) + ", approved under the rule " + a.Rule + "."},
		"Held":   h, "Status": status, "Signers": signers, "Hash": string(a.Surface), "ID": string(h.Record)}
	if a.Expires != 0 {
		data["Expires"] = a.Expires.At()
	}
	if a.ReviewDue != 0 {
		data["ReviewDue"] = a.ReviewDue.At()
	}
	if a.Alone && h.Review == nil {
		data["ReviewHref"] = "/register/approvals/review/" + string(h.Record)
	}
	s.render(w, r, "record_approval_held.html", data)
}

func (s *Server) handleApprovalReview(w http.ResponseWriter, r *http.Request) {
	p, m, ok := s.approvalsReady(w, r)
	if !ok {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/register/approvals/review/")
	idPart, action, _ := strings.Cut(rest, "/")
	id := register.ID(idPart)
	h, err := s.heldOne(m, id)
	if err != nil || !h.Approval.Alone {
		http.NotFound(w, r)
		return
	}
	switch action {
	case "":
		n, _ := nonce()
		base := "/register/approvals/review/" + string(id)
		label := labelOf2(h)
		data := map[string]any{"Title": "Review " + label, "Nav": "signoff", "Principal": p, "Nonce": n,
			"Header": seckit.Header{Title: "Review " + label, Lead: "This decision was made alone, by the only person " +
				"eligible. Its review is yours to make if you are somebody else: look at exactly what was approved, and " +
				"say whether it stands."},
			"Held": h, "ID": string(id), "Hash": string(h.Approval.Surface), "Short": seckit.Short(string(h.Approval.Surface)),
			"Action": base + "/approve", "Record": "/register/record/" + string(id),
			"Ceremony": map[string]any{"Nonce": n, "Challenge": base + "/challenge", "Approve": base + "/approve"}}
		if h.Review != nil {
			data["Reviewed"] = h.Review
			delete(data, "Ceremony")
		}
		s.passkeyPolicy(w, n)
		s.render(w, r, "record_approval_review.html", data)
	case "challenge":
		s.startCeremony(w, r, p, approval.ForReview, h.Approval.Surface)
	case "approve":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "reviewing takes a POST", http.StatusMethodNotAllowed)
			return
		}
		if !fromScript(r) {
			s.withoutScript(w, r, p, "quilzo approval review "+string(id)+" upheld --surface "+string(h.Approval.Surface))
			return
		}
		var body ceremonyBody
		if err := readJSON(r, &body); err != nil {
			writeJSONError(w, http.StatusBadRequest, err)
			return
		}
		proof, code, err := s.passkeyProof(r, p, approval.ForReview, body)
		if err != nil {
			writeJSONError(w, code, err)
			return
		}
		rc, err := m.Review(s.approver(p), id, register.ReviewOutcome(body.Outcome), approval.Proof{Passkey: proof})
		if err != nil && !errors.Is(err, register.ErrUnrecorded) {
			approvalError(w, err)
			return
		}
		writeJSON(w, map[string]any{"receipt": rc, "said": "Reviewed: " + body.Outcome + ". The record of your review carries the hash " +
			string(h.Approval.Surface) + ".", "next": "/register/approvals/held/" + string(id)})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleApprovalPolicy(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.approvalsReady(w, r)
	if !ok {
		return
	}
	pol, declared, err := approval.LoadPolicy(s.Store.Root())
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	var rows []seckit.Row
	for _, rule := range pol.Rules {
		when := "Every record of the kind"
		if rule.When != nil {
			when = "When " + rule.When.Field + " is " + rule.When.Equals
		}
		term := "Does not lapse"
		if rule.TermDays > 0 {
			term = fmt.Sprintf("%d days", rule.TermDays)
		}
		rows = append(rows, seckit.Row{Head: seckit.TextCell(rule.Name), Cells: []seckit.Cell{
			seckit.TextCell(string(rule.Kind)), seckit.TextCell(when), seckit.TextCell(string(rule.Atom)),
			seckit.TextCell(fmt.Sprintf("Level %d", rule.Level)), seckit.TextCell(rule.Describe()), seckit.TextCell(term)}})
	}
	table, err := seckit.NewTable("Who may approve each kind of decision, the first rule that applies deciding",
		[]string{"Rule", "Kind", "Applies", "Makes eligible", "Autonomy", "Who, and how many", "Approval counts for"}, rows)
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	lead := "The organisation's separation policy, as declared in separation.json beside the store."
	if !declared {
		lead = "The default separation policy: this store has not declared its own."
	}
	s.render(w, r, "record_approval_policy.html", map[string]any{"Title": "Separation policy", "Nav": "signoff",
		"Principal": p, "Header": seckit.Header{Title: "Separation policy", Lead: lead}, "Table": table, "Policy": pol})
}
