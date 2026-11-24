// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/register"
)

// PLAN theme 7: registerWriter names the caller in the record by their
// pseudonym from the subject map, the same pseudonym every time and a
// different one for somebody else, so a person's proposal is decided by
// somebody the register can tell apart from them. Their name is in the
// subject map and in no object of the store.
func TestRegisterWriterNamesTheCallerByPseudonym(t *testing.T) {
	root, token := accessStore(t)
	// Two people with the compliance job, which is the register's.
	for _, who := range []string{"ada.lovelace@example.com", "lee"} {
		if _, e, code := cliRun(t, root, token, "auth", "grant", who, "compliance"); code != 0 {
			t.Fatalf("auth grant: %s", e)
		}
	}
	ada := &Caller{Name: "ada.lovelace@example.com", Role: auth.RoleAdmin, Scope: auth.AreaCompliance, Kind: audit.KindHuman, Verified: true}
	lee := &Caller{Name: "lee", Role: auth.RoleAdmin, Scope: auth.AreaCompliance, Kind: audit.KindHuman, Verified: true}
	r, byAda, err := registerWriter(root, ada)
	if err != nil {
		t.Fatal(err)
	}
	if !byAda.Subject.Valid() {
		t.Fatalf("the writer names ada by %q", byAda.Subject)
	}
	_, again, _ := registerWriter(root, ada)
	_, byLee, _ := registerWriter(root, lee)
	if again.Subject != byAda.Subject || byLee.Subject == byAda.Subject || !byLee.Subject.Valid() {
		t.Fatalf("ada is %s then %s, and lee %s", byAda.Subject, again.Subject, byLee.Subject)
	}
	if p, err := r.Person(byAda.Subject); err != nil || p.Name != ada.Name || p.Type != "person" {
		t.Errorf("the subject map has ada as %+v (%v)", p, err)
	}

	rc, err := r.Propose(byAda, "a control ada proposes",
		register.Control{Ref: "AC-21", Title: "Access reviewed every quarter", Domain: "identity", Owner: byAda.Subject})
	if err != nil || len(rc.Written) != 1 {
		t.Fatalf("propose: %v", err)
	}
	id := rc.Written[0].ID
	if _, err := r.Accept(again, id, nil); !errors.Is(err, register.ErrRefused) {
		t.Errorf("ada accepted her own proposal: %v", err)
	}
	if _, err := r.Accept(byLee, id, nil); err != nil {
		t.Errorf("lee could not accept ada's proposal: %v", err)
	}
	c, err := r.Store.GetCommit(r.Head())
	if err != nil || c.Author != string(byLee.Subject) {
		t.Errorf("the commit is authored %q (%v)", c.Author, err)
	}
	if hit := scanFor(t, filepath.Join(root, "objects"), ada.Name); hit != "" {
		t.Errorf("ada's address is in the store at %s", hit)
	}
}

// scanFor is the first file under dir whose bytes hold s, or "".
func scanFor(t *testing.T, dir, s string) string {
	t.Helper()
	var hit string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || hit != "" {
			return nil
		}
		if b, _ := os.ReadFile(path); strings.Contains(string(b), s) {
			hit = path
		}
		return nil
	})
	return hit
}

// PLAN theme 7: `quilzo register erase` erases a person from beside the
// register and writes the signed Erasure record; the record that named
// them still reads and says the subject and the text are erased; somebody
// who may not decide an erasure is refused, exit 3, and erases nothing;
// and a person erased already is not erased twice.
func TestRegisterEraseCommand(t *testing.T) {
	root, token := accessStore(t)
	owner := &Caller{Name: "owner", Role: auth.RoleAdmin, Scope: "/", Kind: audit.KindHuman, Verified: true}
	r, by, err := registerWriter(root, owner)
	if err != nil {
		t.Fatal(err)
	}
	ada, err := r.SubjectFor("ada.lovelace@example.com", "person")
	if err != nil {
		t.Fatal(err)
	}
	words, err := r.PutText(by, register.KindRisk, "Ada Lovelace raised this after the breach", ada)
	if err != nil {
		t.Fatal(err)
	}
	risk := register.Risk{Ref: "R-1", Title: "Shared administrator accounts", Description: words, Owner: ada,
		Raised: ada, Likelihood: 3, Impact: 4, Status: "open"}
	if _, err := r.Put(by, "a risk", risk); err != nil {
		t.Fatal(err)
	}
	riskID, _ := register.IDOf(risk)

	// A reader of the whole site may not decide an erasure.
	if _, e, code := cliRun(t, root, token, "auth", "grant", "rita", "reader"); code != 0 {
		t.Fatalf("auth grant: %s", e)
	}
	o, e, code := cliRun(t, root, token, "token", "issue", "rita", "--principal", "rita", "--role", "reader", "--json")
	if code != 0 {
		t.Fatalf("token issue: %s", e)
	}
	var rita struct{ Token string }
	_ = json.Unmarshal([]byte(o), &rita)
	if _, e, code := cliRun(t, root, rita.Token, "register", "erase", "--subject", string(ada), "--basis", "request",
		"--yes"); code != 3 {
		t.Errorf("a reader's erasure exited %d: %s", code, firstLines(e, 3))
	}
	if r.SubjectState(ada).State != register.SubjectHeld {
		t.Fatal("a refused erasure erased the person")
	}

	if _, e, code := cliRun(t, root, token, "register", "erase", "--subject", string(ada), "--basis", "whim", "--yes"); code != 2 {
		t.Errorf("a basis that is none exited %d: %s", code, firstLines(e, 3))
	}
	o, e, code = cliRun(t, root, token, "register", "erase", "--name", "ada.lovelace@example.com", "--basis", "request",
		"--requested-by", "subject", "--yes", "--json")
	if code != 0 {
		t.Fatalf("register erase: %d %s", code, e)
	}
	var erased struct {
		Erasure register.ID
		Receipt register.Receipt
	}
	if err := json.Unmarshal([]byte(o), &erased); err != nil || erased.Erasure != register.ErasureID(ada) || erased.Receipt.Commit == "" {
		t.Fatalf("register erase answered %s (%v)", firstLines(o, 4), err)
	}
	if st := r.SubjectState(ada); st.State != register.SubjectErased {
		t.Errorf("after the erasure the subject is %+v", st)
	}
	if held := r.TextOf(words); held.State != register.TextErased {
		t.Errorf("after the erasure the words are %+v", held)
	}
	show, e, code := cliRun(t, root, token, "register", "show", string(riskID))
	if code != 0 || !strings.Contains(show, "subject erased") || !strings.Contains(show, "text erased") ||
		strings.Contains(show, "Ada Lovelace") {
		t.Errorf("the risk after the erasure shows %d %s %s", code, show, e)
	}
	js, _, _ := cliRun(t, root, token, "register", "show", string(riskID), "--json")
	if !strings.Contains(js, `"subject erased"`) {
		t.Errorf("the risk's JSON does not say the subject is erased: %s", firstLines(js, 6))
	}
	// The Erasure record is in the register, signed, under the pseudonym.
	e2, err := r.Get(erased.Erasure)
	if err != nil || e2.Kind != register.KindErasure {
		t.Fatalf("the erasure record: %v", err)
	}
	if rec := e2.Record.(register.Erasure); rec.Approval == nil || rec.Approval.Raised != ada || rec.Basis != "request" {
		t.Errorf("the erasure is %+v", rec)
	}
	if _, e, code := cliRun(t, root, token, "register", "erase", "--subject", string(ada), "--basis", "request", "--yes"); code == 0 {
		t.Errorf("a person erased twice: %s", e)
	}
	if _, e, code := cliRun(t, root, token, "register", "erase", "--name", "nobody@example.com", "--basis", "request", "--yes"); code != 4 {
		t.Errorf("an erasure of somebody nobody named exited %d: %s", code, firstLines(e, 3))
	}
	// What the audit log holds of it names the pseudonym, pseudonymised
	// again as every subject in the log is, and never the person.
	events, _ := audit.Read(auditPath(root))
	found := false
	for _, ev := range events {
		if ev.Action == register.EraseAction && ev.Outcome == audit.Success && ev.Detail["basis"] == "request" &&
			ev.Detail["subject"] != "" {
			found = true
		}
		for _, v := range ev.Detail {
			if strings.Contains(v, "ada.lovelace") || strings.Contains(v, "Ada Lovelace") {
				t.Errorf("an audit entry names the person: %+v", ev)
			}
		}
	}
	if !found {
		t.Error("the erasure is not in the audit log")
	}
}

// PLAN theme 28: `quilzo register history` is a record's commits, newest
// first; `quilzo register list --filter` filters a kind by a field's value;
// and `quilzo register export` writes the kind as CSV with every cell safe
// for a spreadsheet, filtered as the list is, or the top risks by rating.
func TestRegisterHistoryFiltersAndExport(t *testing.T) {
	root, token := accessStore(t)
	owner := &Caller{Name: "owner", Role: auth.RoleAdmin, Scope: "/", Kind: audit.KindHuman, Verified: true}
	r, by, err := registerWriter(root, owner)
	if err != nil {
		t.Fatal(err)
	}
	first := register.Control{Ref: "AC-01", Title: "=HYPERLINK(\"https://attacker.example\",\"x\")", Domain: "identity", Owner: by.Subject}
	if _, err := r.Put(by, "the first control", first,
		register.Control{Ref: "AC-02", Title: "Encrypted disks", Domain: "endpoints", Owner: by.Subject}); err != nil {
		t.Fatal(err)
	}
	renamed := first
	renamed.Title = "Second factor on every account"
	if _, err := r.Put(by, "renamed", renamed); err != nil {
		t.Fatal(err)
	}
	for i, li := range []int64{1, 5, 3} {
		if _, err := r.Put(by, "a risk", register.Risk{Ref: "R-" + string(rune('1'+i)), Title: "A risk", Owner: by.Subject,
			Raised: by.Subject, Likelihood: li, Impact: 4, Status: "open"}); err != nil {
			t.Fatal(err)
		}
	}
	id, _ := register.IDOf(first)

	o, e, code := cliRun(t, root, token, "register", "history", string(id), "--json")
	if code != 0 {
		t.Fatalf("register history: %s", e)
	}
	var h struct {
		ID      register.ID
		Changes []register.Change
	}
	if err := json.Unmarshal([]byte(o), &h); err != nil || len(h.Changes) != 2 || h.Changes[0].Why != "renamed" ||
		!h.Changes[1].New || h.Changes[0].By != by.Subject {
		t.Fatalf("the history is %s (%v)", firstLines(o, 8), err)
	}
	if _, e, code := cliRun(t, root, token, "register", "history", "ffffffffffffffffffffffffffffffff"); code != 4 {
		t.Errorf("the history of nothing exited %d: %s", code, firstLines(e, 2))
	}

	o, e, code = cliRun(t, root, token, "register", "list", "Control", "--filter", "domain=endpoints", "--json")
	if code != 0 {
		t.Fatalf("register list --filter: %s", e)
	}
	var list struct {
		Total   int
		Filters []register.Filter
	}
	if err := json.Unmarshal([]byte(o), &list); err != nil || list.Total != 1 || len(list.Filters) != 1 {
		t.Errorf("the filtered list is %s", firstLines(o, 4))
	}
	if _, e, code := cliRun(t, root, token, "register", "list", "Control", "--filter", "colour=red"); code != 2 {
		t.Errorf("a filter on a field the kind lacks exited %d: %s", code, firstLines(e, 2))
	}

	o, e, code = cliRun(t, root, token, "register", "export", "Control")
	if code != 0 {
		t.Fatalf("register export: %s", e)
	}
	rows, err := csv.NewReader(strings.NewReader(o)).ReadAll()
	if err != nil || len(rows) != 3 || rows[0][0] != "id" {
		t.Fatalf("the export is %v (%v):\n%s", rows, err, o)
	}
	for _, row := range rows[1:] {
		for _, cell := range row {
			if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
				t.Errorf("the cell %q would run as a formula", cell)
			}
		}
	}
	o, _, _ = cliRun(t, root, token, "register", "export", "Control", "--filter", "domain=identity")
	if rows, _ := csv.NewReader(strings.NewReader(o)).ReadAll(); len(rows) != 2 {
		t.Errorf("the filtered export is %d rows", len(rows))
	}
	out := filepath.Join(t.TempDir(), "risks.csv")
	if _, e, code := cliRun(t, root, token, "register", "export", "Risk", "--top", "2", "--out", out); code != 0 {
		t.Fatalf("register export --top: %s", e)
	}
	b, _ := os.ReadFile(out)
	rows, _ = csv.NewReader(strings.NewReader(string(b))).ReadAll()
	if len(rows) != 3 || rows[0][len(rows[0])-1] != "rating" || rows[1][len(rows[1])-1] != "20" || rows[2][len(rows[2])-1] != "12" {
		t.Errorf("the top two risks are %v", rows)
	}
	if _, e, code := cliRun(t, root, token, "register", "export", "Control", "--top", "2"); code != 2 {
		t.Errorf("the top of controls exited %d: %s", code, firstLines(e, 2))
	}
	o, _, code = cliRun(t, root, token, "register", "export", "Control", "--json")
	var js struct {
		Columns []string
		Rows    [][]string
	}
	if code != 0 || json.Unmarshal([]byte(o), &js) != nil || len(js.Rows) != 2 || js.Columns[0] != "id" {
		t.Errorf("the export as JSON is %s", firstLines(o, 4))
	}
}

// PLAN theme 7: `quilzo register inventory` is the data inventory made
// from the schemas, for a privacy officer's record of processing.
func TestRegisterInventoryCommand(t *testing.T) {
	root, token := accessStore(t)
	o, e, code := cliRun(t, root, token, "register", "inventory", "--json")
	if code != 0 {
		t.Fatalf("register inventory: %s", e)
	}
	var inv register.DataInventory
	if err := json.Unmarshal([]byte(o), &inv); err != nil || len(inv.Kinds) != len(register.Kinds()) || inv.SubjectMap == "" {
		t.Fatalf("the inventory is %s (%v)", firstLines(o, 4), err)
	}
	human, _, code := cliRun(t, root, token, "register", "inventory")
	if code != 0 || !strings.Contains(human, "Risk") || !strings.Contains(human, "raised_by") ||
		!strings.Contains(human, "subject map") {
		t.Errorf("the inventory reads:\n%s", firstLines(human, 20))
	}
}

// PLAN theme 28 and STRATEGY 7.4: the register's operations on the agent
// interface are off for an app connected through OAuth until a recorded
// setting switches them on, and read for a person's own client as before.
func TestRegisterOperationsAreOffForOutsideApps(t *testing.T) {
	root, token := accessStore(t)
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	app := remoteCaller(appToken("owner", auth.RoleAdmin))
	for _, op := range []string{"register_kinds", "register_inventory"} {
		if _, rerr := callTool(t, buildMCP(root, s, app, "templates"), "quilzo_read", op, nil); rerr == nil ||
			!strings.Contains(rerr.Message, "register.mcp_for_apps") {
			t.Errorf("an app's %s was answered %v", op, rerr)
		}
	}
	person := &Caller{Name: "owner", Role: auth.RoleAdmin, Scope: "/", Kind: audit.KindAI, Model: "mcp-client", Verified: true, Remote: true}
	if _, rerr := callTool(t, buildMCP(root, s, person, "templates"), "quilzo_read", "register_kinds", nil); rerr != nil {
		t.Errorf("a person's own client was refused the register: %s", rerr.Message)
	}
	if _, e, code := cliRun(t, root, token, "config", "set", "register.mcp_for_apps", "true", "--accept-risk",
		"the organisation's assistant reads the register"); code != 0 {
		t.Fatalf("config set: %s", e)
	}
	if _, rerr := callTool(t, buildMCP(root, s, app, "templates"), "quilzo_read", "register_kinds", nil); rerr != nil {
		t.Errorf("with the setting on, the app was refused: %s", rerr.Message)
	}
}
