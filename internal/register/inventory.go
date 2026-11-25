// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package register

import (
	"fmt"
	"strings"

	"github.com/quilzo/quilzo/internal/auth"
)

// The data inventory: what the register holds about people, kind by kind,
// for a privacy officer's record of processing (GDPR Article 30) and the
// information a works council is owed about a system that records what
// employees do.
//
// It is generated from the kinds' schemas and the access policy's own
// roles, and never written by hand, so it cannot say less than the
// register holds: a field added to a kind is in it the next time it is
// read. What it says of each kind is which fields name a person (by
// pseudonym), which hold free text and which name raw files (both kept in
// the side store, as digests in the record), how long the side store keeps
// those, and which jobs and roles may read the records.

// DataInventory is the sheet, as every surface shows it.
type DataInventory struct {
	Kinds []InventoryKind `json:"kinds"`
	// SubjectMap and SideStore say where the map from a pseudonym to the
	// person and the free text and files are kept, and how each is erased.
	SubjectMap string `json:"subject_map"`
	SideStore  string `json:"side_store"`
	// Erasure says what an erasure deletes and what it leaves.
	Erasure string `json:"erasure"`
	// AuditLog says how the audit log names the people who wrote the
	// register, which an erasure does not reach. A sheet that said only
	// the subject map names a person would say less than is kept.
	AuditLog string `json:"audit_log"`
}

// InventoryKind is one kind's lines of the sheet.
type InventoryKind struct {
	Kind       Kind   `json:"kind"`
	Collection string `json:"collection"`
	Summary    string `json:"summary"`
	Class      Class  `json:"class"`
	// People are the fields that name a person or an account, each by its
	// pseudonym; Text the fields of free text and Files the raw files,
	// each held in the record as a digest and kept in the side store.
	People []InventoryField `json:"people"`
	Text   []InventoryField `json:"text"`
	Files  []InventoryField `json:"files"`
	// RetainDays is how long the side store keeps the text and files the
	// kind's records name; zero keeps them until a person erases them.
	RetainDays int `json:"retain_days"`
	// Readers are the jobs and roles the access policy lets read the
	// kind's records, in words.
	Readers []string `json:"readers"`
}

// InventoryField is one field of the sheet: where it is in the record, as
// a dotted path, and what it is for.
type InventoryField struct {
	Field    string `json:"field"`
	About    string `json:"about,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// rawField is what a field naming a raw file is called in every kind that
// keeps one: the file a fact was read from, by its digest.
const rawField = "raw"

// Inventory is the data inventory of every kind, in the alphabet's order.
func Inventory() DataInventory {
	inv := DataInventory{
		SubjectMap: "side/subjects under the store's directory: one file a person, holding their pseudonym, the name " +
			"the systems that name them use (an account, a user principal name or an address) and what sort of " +
			"account it is, and an index of those names to find a person by; sealed with the store's keyring on " +
			"an encrypted store. Nothing in the register itself names a person.",
		SideStore: "side/entries under the store's directory: the free text people wrote and the raw files facts " +
			"were read from, each named by its SHA-256 and checked against it when read, with the kinds that hold " +
			"it and the pseudonyms of the people it is about; sealed with the store's keyring on an encrypted store.",
		Erasure: "An erasure deletes the subject map's entry for the person and every side entry about them, and " +
			"writes a signed Erasure record saying whose pseudonym now names nobody, on what basis and on whose " +
			"decision; nothing more is kept about that pseudonym after it. The register itself is not changed, so " +
			"every record and chain still checks. A backup is a copy of the store and its side store as they were, " +
			"so one made before the erasure still holds the person until it is deleted, after backup.keep newer " +
			"ones, and a backup from before an erasure that is restored brings the person back, to be erased again.",
		AuditLog: "The audit log, beside the register, records every write, every entry kept in the side store and " +
			"every erasure with who did it and what was done: the kinds, the counts, the digests and the " +
			"pseudonyms, never the words or the files. Who did it, and every person an entry names, is written as " +
			"a pseudonym of the name the access policy knows them by, made with the log's own key (audit.key, " +
			"beside the log), so whoever holds that key can tell who it was and a copy without it cannot. It is a " +
			"hash chain, which a SIEM may hold a copy of, so an erasure does not reach it: it keeps who answered " +
			"for the security record, not what the record says about the person erased.",
	}
	for _, k := range Kinds() {
		ik := InventoryKind{Kind: k.Kind, Collection: k.Collection, Summary: k.Summary, Class: k.Class,
			People: []InventoryField{}, Text: []InventoryField{}, Files: []InventoryField{},
			RetainDays: k.RetainDays, Readers: readersOf(k)}
		walkFields(k.Fields, "", func(path string, f Field) {
			line := InventoryField{Field: path, About: f.About, Required: f.Required}
			base := strings.TrimPrefix(f.Type, "list of ")
			switch {
			case base == "id" && (f.Ref == KindSubject || (k.Kind == KindSubject && path == "pseudonym")):
				ik.People = append(ik.People, line)
			case base == "text":
				ik.Text = append(ik.Text, line)
			case base == "digest" && f.Name == rawField:
				ik.Files = append(ik.Files, line)
			}
		})
		inv.Kinds = append(inv.Kinds, ik)
	}
	return inv
}

// walkFields calls fn for every field, an object's fields under its own
// name and a dot.
func walkFields(fields []Field, prefix string, fn func(path string, f Field)) {
	for _, f := range fields {
		path := prefix + f.Name
		if len(f.Fields) > 0 {
			walkFields(f.Fields, path+".", fn)
			continue
		}
		fn(path, f)
	}
}

// readersOf is who the access policy lets read a kind's records, worked
// out by asking it: each job granted alone, and each role granted over the
// whole site. A role granted on the register's area, or on the kind's own
// resource, reads it too, and is said last.
func readersOf(k Spec) []string {
	var out []string
	for _, j := range auth.Jobs {
		p := &auth.Policy{}
		for _, b := range j.Bindings {
			b.Principal = "someone"
			p.Bindings = append(p.Bindings, b)
		}
		if p.Evaluate("someone", auth.ActView, k.Resource()).Allowed {
			line := fmt.Sprintf("the %s job (%s)", j.Name, j.Summary)
			if j.Ends {
				line += ", granted for a set time"
			}
			out = append(out, line)
		}
	}
	for _, role := range auth.Roles {
		p := &auth.Policy{Bindings: []auth.Binding{{Principal: "someone", Role: role, Resource: "/"}}}
		if p.Evaluate("someone", auth.ActView, k.Resource()).Allowed {
			out = append(out, roleWords(role)+" of the whole site")
		}
	}
	return append(out, "anybody granted a role on "+Area+" or on "+k.Resource())
}

// roleWords is a role as a sentence says it.
func roleWords(r auth.Role) string {
	if r == auth.RoleAdmin {
		return "an administrator"
	}
	return "a " + string(r)
}
