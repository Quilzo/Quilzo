// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/seckit"
)

// The register's export, its data inventory and the erasure of a person,
// as the admin shows them: the same three as `quilzo register export`,
// `inventory` and `erase`, registered from registerscreen.go with the
// register's other screens and built from the security kit.

// erasureResource is what the policy is asked about for an erasure: the
// approval of the register's Erasure records.
func erasureResource() string {
	spec, _ := register.SpecOf(string(register.KindErasure))
	return spec.Resource()
}

// handleRegisterExport is /register/export/KIND.csv: a kind as CSV, a
// column per field and every cell safe for a spreadsheet, filtered as the
// kind's screen is, or the top risks by rating with ?top=N.
func (s *Server) handleRegisterExport(w http.ResponseWriter, r *http.Request) {
	p, reg, ok := s.registerReady(w, r)
	if !ok {
		return
	}
	name, isCSV := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/register/export/"), ".csv")
	spec, found := register.SpecOf(name)
	if !found || !isCSV || strings.Contains(name, "/") {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	filters, problem := filtersOf(q)
	top := 0
	if raw := q.Get("top"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			problem = "top is a whole number of records, 1 or more"
		}
		top = n
	}
	var entries []register.Entry
	if problem == "" {
		var err error
		entries, _, err = reg.Find(spec.Kind, filters, 0, 0)
		if err == nil && top > 0 {
			if _, rated := register.Rating(spec.New().(register.Record)); !rated {
				err = fmt.Errorf("%w: a %s has no rating to put the highest first by", register.ErrInvalid,
					strings.ToLower(string(spec.Kind)))
			} else {
				entries, err = register.Top(entries, top)
			}
		}
		switch {
		case errors.Is(err, register.ErrInvalid):
			problem = err.Error()
		case err != nil:
			s.registerUnreadable(w, r, p, err)
			return
		}
	}
	if problem != "" {
		s.render(w, r, "message.html", map[string]any{"Status": http.StatusBadRequest, "Title": "Export",
			"Principal": p, "Heading": "That export cannot be made", "Body": problem})
		return
	}
	var b bytes.Buffer
	if err := register.WriteCSV(&b, spec, entries); err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	file := "register-" + strings.TrimPrefix(spec.Collection, register.Prefix)
	if top > 0 {
		file += "-top-" + strconv.Itoa(top)
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+file+`.csv"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(b.Bytes())
}

// handleRegisterInventory is /register/inventory: the data inventory, a
// table a kind, generated from the schemas and the policy's roles.
func (s *Server) handleRegisterInventory(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.registerReady(w, r)
	if !ok {
		return
	}
	inv := register.Inventory()
	names := func(fs []register.InventoryField) seckit.Cell {
		if len(fs) == 0 {
			return seckit.TextCell("None")
		}
		var out []string
		for _, f := range fs {
			out = append(out, f.Field)
		}
		return seckit.TextCell(strings.Join(out, ", "))
	}
	type kindTable struct {
		ID    string
		Table seckit.Table
	}
	var tables []kindTable
	for _, k := range inv.Kinds {
		keep := "Until a person erases them"
		if k.RetainDays > 0 {
			keep = fmt.Sprintf("%d days after they were last kept for a record of the kind", k.RetainDays)
		}
		t, err := seckit.NewTable(fmt.Sprintf("%s (%s): %s", k.Kind, k.Class, k.Summary), []string{"What", "Fields or rule"},
			[]seckit.Row{
				{Head: seckit.TextCell("People, by pseudonym"), Cells: []seckit.Cell{names(k.People)}},
				{Head: seckit.TextCell("Free text, in the side store"), Cells: []seckit.Cell{names(k.Text)}},
				{Head: seckit.TextCell("Raw files, in the side store"), Cells: []seckit.Cell{names(k.Files)}},
				{Head: seckit.TextCell("Text and files kept"), Cells: []seckit.Cell{seckit.TextCell(keep)}},
				{Head: seckit.TextCell("Who may read it"), Cells: []seckit.Cell{seckit.TextCell(strings.Join(k.Readers, "; "))}},
			})
		if err != nil {
			s.registerUnreadable(w, r, p, err)
			return
		}
		tables = append(tables, kindTable{ID: "kind-" + strings.TrimPrefix(k.Collection, register.Prefix), Table: t})
	}
	s.render(w, r, "register_inventory.html", map[string]any{"Title": "Data inventory", "Nav": "register",
		"Principal": p, "Inventory": inv, "Tables": tables, "MayErase": s.allows(p, auth.ActApprove, erasureResource()),
		"Header": seckit.Header{Title: "Data inventory", Lead: "What the register holds about people, kind by kind, " +
			"generated from the kinds' schemas and the access policy's roles for a record of processing. A field " +
			"added to a kind is here the next time this page is drawn."}})
}

// erasureForm is what the erasure screen was sent, and what is wrong with
// it.
type erasureForm struct {
	Subject, Basis, Requested string
	Confirm                   bool
	Problems                  []seckit.Problem
	ByField                   map[string]seckit.Problem
}

func (f *erasureForm) problem(field, label, message string) {
	pr := seckit.Problem{Field: field, Label: label, Message: message}
	f.Problems = append(f.Problems, pr)
	if f.ByField == nil {
		f.ByField = map[string]seckit.Problem{}
	}
	f.ByField[field] = pr
}

// basisWords is each basis of an erasure in the words the form offers.
var basisWords = map[register.ErasureBasis]string{
	"request":           "The person asked to be erased (GDPR Article 17)",
	"objection":         "The person objected to the processing (Article 21)",
	"consent-withdrawn": "The person withdrew their consent",
	"no-longer-needed":  "The data is no longer needed for its purpose",
	"unlawful":          "The data was processed unlawfully",
	"legal-obligation":  "A law requires it erased",
}

// handleRegisterErase is /register/erase: the form, and the erasure.
func (s *Server) handleRegisterErase(w http.ResponseWriter, r *http.Request) {
	p, reg, ok := s.registerReady(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActApprove, erasureResource()) {
		return
	}
	var bases []map[string]string
	for _, b := range register.ErasureBasis("").Values() {
		bases = append(bases, map[string]string{"Value": b, "Words": basisWords[register.ErasureBasis(b)]})
	}
	data := map[string]any{"Title": "Erase a person", "Nav": "register", "Principal": p, "Bases": bases,
		"Header": seckit.Header{Title: "Erase a person", Lead: "Deletes who a pseudonym stands for, and the free text " +
			"and files about them, from beside the register, and writes the signed record that says so. The register " +
			"itself is not changed, so every record and every chain still checks. It cannot be undone."}}
	form := &erasureForm{Requested: "subject"}
	data["Form"] = form
	if r.Method != http.MethodPost {
		s.render(w, r, "register_erase.html", data)
		return
	}
	form.Subject, form.Basis = strings.TrimSpace(r.FormValue("subject")), r.FormValue("basis")
	form.Requested, form.Confirm = r.FormValue("requested"), r.FormValue("confirm") == "yes"
	if form.Subject == "" {
		form.problem("erase-subject", "Person", "Enter the person's pseudonym, or the name the subject map holds for them")
	}
	if !slices.Contains(register.ErasureBasis("").Values(), form.Basis) {
		form.problem("erase-basis", "Basis", "Choose the ground the person is erased on")
	}
	if !form.Confirm {
		form.problem("erase-confirm", "Confirmation", "Confirm that you understand an erasure cannot be undone")
	}
	id := register.ID(form.Subject)
	if form.Subject != "" && !id.Valid() {
		found, held, err := reg.Side().Lookup(form.Subject)
		if err != nil {
			s.registerUnreadable(w, r, p, err)
			return
		}
		if !held {
			form.problem("erase-subject", "Person", "The subject map names nobody by that; a person erased already is "+
				"found by their pseudonym, in the Erasure records")
		}
		id = register.ID(found)
	}
	if len(form.Problems) > 0 {
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "register_erase.html", data)
		return
	}
	writer, by, err := s.registerWriter(p)
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	var asked register.ID
	if form.Requested == "subject" {
		asked = id
	}
	if id == by.Subject {
		form.problem("erase-subject", "Person", "You do not decide your own erasure: somebody else who may decide one does")
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "register_erase.html", data)
		return
	}
	about, err := writer.Side().About(string(id))
	if err != nil {
		s.registerUnreadable(w, r, p, err)
		return
	}
	rc, err := writer.Erase(by, register.ErasureRequest{Subject: id, Basis: register.ErasureBasis(form.Basis),
		RequestedBy: asked, Eligible: max(register.Eligible(s.Policy, auth.ActApprove, erasureResource()), 1),
		Evidence: sessionEvidence(p)})
	switch {
	case errors.Is(err, register.ErrErased):
		s.render(w, r, "message.html", map[string]any{"Status": http.StatusConflict, "Title": "Erase a person",
			"Principal": p, "Heading": "That person was erased already", "Body": err.Error()})
		return
	case errors.Is(err, register.ErrNotFound):
		form.problem("erase-subject", "Person", "Nothing is kept about that pseudonym, and the subject map names nobody by it")
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "register_erase.html", data)
		return
	case errors.Is(err, register.ErrRefused), errors.Is(err, register.ErrModel):
		s.render(w, r, "message.html", map[string]any{"Status": http.StatusForbidden, "Title": "Not permitted",
			"Principal": p, "Heading": "You cannot erase that person here", "Body": err.Error()})
		return
	case errors.Is(err, register.ErrInvalid):
		// Every field was checked above, so what is left is the approval:
		// with anybody else eligible, the person who raises a decision is
		// not the one who makes it. It is the question of who asked, and
		// is said there, with nothing erased.
		form.problem("erase-requested", "Who asked for it", "Somebody else may decide an erasure too, and the "+
			"person who raises a decision does not make it: choose who asked for it, or ask somebody else who "+
			"may decide it to erase them")
		w.WriteHeader(http.StatusUnprocessableEntity)
		s.render(w, r, "register_erase.html", data)
		return
	case err != nil && !errors.Is(err, register.ErrUnrecorded):
		s.registerUnreadable(w, r, p, err)
		return
	}
	data["Done"] = map[string]any{"Record": string(register.ErasureID(id)), "Commit": rc.Commit, "Subject": string(id),
		"Entries": len(about)}
	data["Said"] = fmt.Sprintf("Erased the person behind %s: the subject map's entry and %d entries of text and files "+
		"about them. The register still checks.", id, len(about))
	data["Form"] = &erasureForm{Requested: "subject"}
	s.render(w, r, "register_erase.html", data)
}

// registerWriter is the register of this server's store, wired to write
// as a person signed in here: the policy asked through this session, with
// its credential's limits; the audit entry written as every act here is;
// and the person named in the record by their pseudonym from the subject
// map. With no audit log there is no writer, and the register refuses to
// write.
func (s *Server) registerWriter(p principal) (*register.Register, register.Actor, error) {
	reg := register.Open(s.Store)
	if s.Audit != nil {
		reg.Audit = func(rec audit.Record) error {
			detail := map[string]string{}
			for k, v := range rec.Detail {
				detail[k] = v
			}
			detail["by"] = rec.Principal
			action := rec.Action
			if rec.Outcome == audit.Denied {
				action += ".denied"
			}
			s.audit(action, rec.Resource, detail)
			return nil
		}
	}
	by := register.Actor{Name: p.Name, Kind: audit.KindHuman, Verified: true,
		May: func(act auth.Action, resource string) error {
			if !s.allows(p, act, resource) {
				return fmt.Errorf("%s may not %s on %s through this session", p.Name, act, resource)
			}
			return nil
		}}
	id, err := reg.SubjectFor(p.Name, "person")
	if err != nil {
		return nil, register.Actor{}, err
	}
	by.Subject = id
	return reg, by, nil
}

// sessionEvidence is the authentication evidence a decision made here is
// bound to: the session's credential and how it was signed in. A passkey's
// assertion over the record's own hash is the approvals module's, and
// stronger; the approval's rule says which this was.
//
// It names the decider by nothing else, as the command line's does
// (consoleEvidence in cmd/quilzo): the assertion binds it to their
// pseudonym, and is in the register for good, where the name in it was a
// thing to guess at.
func sessionEvidence(p principal) []byte {
	return []byte("admin session\x00" + p.TokenID + "\x00" + strings.Join(p.Methods, ","))
}
