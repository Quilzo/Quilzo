// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/evidence"
	"github.com/quilzo/quilzo/internal/listen"
	"github.com/quilzo/quilzo/internal/register"
	"github.com/quilzo/quilzo/internal/seckit"
)

// The evidence screens: the files brought in as evidence, one of them with
// what was read from it and whether it still checks, and the import, which
// shows what a file would write before anything is written.
//
// An import is two steps on purpose. The file is sealed in the raw evidence
// store the moment it arrives, before anything parses it, and read; the
// person is shown every record it would write, with the place in the file
// each was read from and what was hidden there; and only when they confirm
// is anything written to the register, through register.Put, as them. The
// confirmation carries the digest of what they were shown, and writes
// nothing if the file reads otherwise by then: a column map somebody else
// changed in between would otherwise have them write facts they never saw. A
// table needs a column map, and a person confirms one here once, having
// seen the rows it reads. A key that signed files are verified against is
// pinned here by a person too.
//
// The same as `quilzo ingest` and `quilzo evidence`, registered from this
// file (modules.go).

// evidenceImportPath carries a file, and is named to the listener and to
// limitBody for it (FileBody).
const evidenceImportPath = "/evidence/import"

func init() {
	registerScreens(screens{
		module: "evidence",
		routes: []screenRoute{
			{path: "/evidence", handle: (*Server).handleEvidence},
			{path: evidenceImportPath, handle: (*Server).handleEvidenceImport},
			{path: "/evidence/import/confirm", handle: (*Server).handleEvidenceConfirm},
			{path: "/evidence/map", handle: (*Server).handleEvidenceMap},
			{path: "/evidence/keys", handle: (*Server).handleEvidenceKeys},
			{path: "/evidence/expire", handle: (*Server).handleEvidenceExpire},
			{path: "/evidence/file/", handle: (*Server).handleEvidenceFile},
		},
		nav: []navEntry{{
			destination: destination{Key: "evidence", Label: "Evidence", Path: "/evidence", Group: "Assurance",
				Doc: "compliance", Needs: auth.ActView},
			icon: "inventory_2", area: register.Area,
			also: []string{"import", "ingest", "upload evidence", "raw evidence", "ocsf", "prowler", "sbom", "cyclonedx",
				"spdx", "sarif", "csaf", "vex", "dsse", "osquery", "fleet", "column map", "pinned keys"},
		}},
	})
}

// evidenceReady is a signed-in person who may act on the register as act
// asks, and the ingester of this server's store.
func (s *Server) evidenceReady(w http.ResponseWriter, r *http.Request, act auth.Action) (principal, *evidence.Ingester, bool) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return p, nil, false
	}
	if !s.can(w, r, p, act, register.Area) {
		return p, nil, false
	}
	return p, evidence.New(register.Open(s.Store)), true
}

// evidenceWriter is the ingester wired to write as the person signed in:
// its audit entries go where the command line's go, and it writes nothing
// while that log cannot take one. A server started without that wiring
// writes nothing, and says so.
func (s *Server) evidenceWriter(p principal) (*evidence.Ingester, register.Actor, error) {
	if evidence.Recorder == nil {
		return nil, register.Actor{}, errors.New("this server was started without its audit log wired to the register, " +
			"so it writes nothing to it: use quilzo ingest")
	}
	reg := register.Open(s.Store)
	evidence.Recorder(reg)
	by := register.Actor{Name: p.Name, Kind: audit.KindHuman, Verified: true,
		May: func(act auth.Action, resource string) error {
			d := s.Policy.Evaluate(p.Name, act, resource)
			if err := auth.CheckGranted(d, p.Role, p.Scope, p.Limits, act, resource); err != nil {
				return err
			}
			if !d.Allowed {
				return errors.New(d.Reason)
			}
			return nil
		}}
	return evidence.New(reg), by, nil
}

func (s *Server) evidenceUnreadable(w http.ResponseWriter, r *http.Request, p principal, err error) {
	s.render(w, r, "message.html", map[string]any{"Status": http.StatusServiceUnavailable,
		"Title": "Evidence", "Principal": p, "Heading": "The evidence could not be read",
		"Body": "Nothing on this screen would be true until it can: " + err.Error()})
}

// gradeBadge is a grade as a status: its word, and a tone that says how far
// it can be trusted, never the colour alone.
func gradeBadge(g register.Grade) seckit.Badge {
	tone := seckit.Neutral
	switch g {
	case register.GradeConnector, register.GradeCI, register.GradeSigned:
		tone = seckit.Good
	case register.GradeScreenshot:
		tone = seckit.Warn
	}
	b, err := seckit.NewBadge(tone, seckit.GradeWord(g))
	if err != nil {
		return seckit.MustBadge(seckit.Neutral, "Ungraded")
	}
	return b
}

var (
	heldBadge    = seckit.MustBadge(seckit.Good, "Kept")
	erasedBadge  = seckit.MustBadge(seckit.Info, "Erased when its time was up")
	checksBadge  = seckit.MustBadge(seckit.Good, "Checks")
	brokenBadge  = seckit.MustBadge(seckit.Bad, "Does not check")
	hiddenBadge  = seckit.MustBadge(seckit.Warn, "Hidden in the file")
	missingBadge = seckit.MustBadge(seckit.Bad, "Not in the raw store")
)

func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/evidence" {
		http.NotFound(w, r)
		return
	}
	p, g, ok := s.evidenceReady(w, r, auth.ActView)
	if !ok {
		return
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	offset = max(offset, 0)
	const limit = 50
	files, total, err := g.Files(offset, limit)
	if err != nil {
		s.evidenceUnreadable(w, r, p, err)
		return
	}
	var rows []seckit.Row
	for _, f := range files {
		kept := heldBadge
		switch {
		case f.Sealed == nil:
			kept = missingBadge
		case !f.Held:
			kept = erasedBadge
		}
		rows = append(rows, seckit.Row{Head: seckit.LinkCell("/evidence/file/"+string(f.ID), string(f.Record.Format)+" file "+seckit.Short(string(f.Record.Digest))),
			Cells: []seckit.Cell{seckit.BadgeCell(gradeBadge(f.Record.Grade)), seckit.TextCell(fmt.Sprintf("%d, %d of them hidden in the file", f.Record.Facts, f.Record.Tainted)),
				seckit.TimeCell(f.Record.Received.At()), seckit.BadgeCell(kept), seckit.HashCell(string(f.Record.Digest))}})
	}
	table, err := seckit.NewTable(fmt.Sprintf("Files brought in as evidence, %d to %d of %d", min(offset+1, total), offset+len(files), total),
		[]string{"File", "Grade", "Records read", "First received", "Raw file", "Sealed as"}, rows)
	if err != nil {
		s.evidenceUnreadable(w, r, p, err)
		return
	}
	data := map[string]any{"Title": "Evidence", "Nav": "evidence", "Principal": p,
		"Header": seckit.Header{Title: "Evidence", Lead: "Files brought in as evidence. Each was sealed by its hash before " +
			"anything read it, and every fact it yielded names the file, the place it was read from and how it came in."},
		"Table": table, "Total": total, "CanImport": s.allows(p, auth.ActEditDraft, register.Area), "Said": ""}
	if n := r.URL.Query().Get("erased"); n != "" {
		data["Said"] = "Erased the raw bytes of " + n + " files whose time to be kept was up. Their seals, and the lists of what was read from them, are kept."
		if n == "0" {
			data["Said"] = "No raw file's time to be kept is up, so nothing was erased."
		}
	}
	if total == 0 {
		data["Empty"] = seckit.Empty{Title: "No file has been brought in yet",
			Body: "Findings from a cloud scanner, a bill of materials, a code scan, an advisory, a signed attestation, " +
				"query results from a fleet of devices, or a table through a column map.",
			Href: evidenceImportPath, Action: "Bring a file in"}
	}
	if next := offset + len(files); next < total {
		data["Next"] = fmt.Sprintf("/evidence?offset=%d", next)
	}
	s.render(w, r, "evidence.html", data)
}

// importForm is what the import form was sent, kept to show again.
type importForm struct {
	Format, Source, Map, Kind, Sheet string
}

func (s *Server) importData(p principal, g *evidence.Ingester, f importForm, problems []seckit.Problem) map[string]any {
	maps, _, _ := g.Reg.List(register.KindColumnMap, 0, 200)
	var names []string
	for _, e := range maps {
		names = append(names, e.Record.(register.ColumnMap).Name)
	}
	var kinds []string
	for _, k := range register.Kinds() {
		if !k.Signed && !k.Unconfirmed && !k.Immutable && k.Kind != register.KindRawFile && k.Kind != register.KindColumnMap &&
			k.Kind != register.KindPinnedKey && k.Kind != register.KindSubject {
			kinds = append(kinds, string(k.Kind))
		}
	}
	byField := map[string]seckit.Problem{}
	for _, pr := range problems {
		byField[pr.Field] = pr
	}
	status := http.StatusOK
	if len(problems) > 0 {
		status = http.StatusUnprocessableEntity
	}
	return map[string]any{"Status": status, "Title": "Bring a file in", "Nav": "evidence", "Principal": p,
		"Header": seckit.Header{Title: "Bring a file in", Lead: "The file is sealed by its hash as it arrives, and read. " +
			"You see every record it would write before anything is written."},
		"Formats": evidence.Formats(), "Form": f, "Maps": names, "Kinds": kinds, "Problems": problems, "ByField": byField,
		"Limit": evidence.MaxFile >> 20}
}

func (s *Server) handleEvidenceImport(w http.ResponseWriter, r *http.Request) {
	p, g, ok := s.evidenceReady(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		f := importForm{Format: q.Get("format"), Map: q.Get("map"), Source: q.Get("source")}
		if file := q.Get("file"); file != "" {
			// A file sealed already, coming back with the map a person has
			// just confirmed for it.
			body, err := g.Raw.Open(register.Digest(file))
			if err != nil {
				s.render(w, r, "evidence_import.html", s.importData(p, g, f, []seckit.Problem{{Field: "import-file",
					Label: "The file", Message: "the file sealed earlier cannot be read: " + err.Error()}}))
				return
			}
			s.evidencePreview(w, r, p, g, f, body)
			return
		}
		s.render(w, r, "evidence_import.html", s.importData(p, g, f, nil))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "GET or POST", http.StatusMethodNotAllowed)
		return
	}
	listen.Receive(r)
	r.Body = http.MaxBytesReader(w, r.Body, evidence.MaxFile+1<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		s.render(w, r, "evidence_import.html", s.importData(p, g, importForm{}, []seckit.Problem{{Field: "import-file",
			Label: "The file", Message: fmt.Sprintf("the upload could not be read (%v); the most read is %d MB", err, evidence.MaxFile>>20)}}))
		return
	}
	f := importForm{Format: r.FormValue("format"), Source: strings.TrimSpace(r.FormValue("source")),
		Map: r.FormValue("map"), Kind: r.FormValue("kind"), Sheet: strings.TrimSpace(r.FormValue("sheet"))}
	var problems []seckit.Problem
	format, known := evidence.FormatNamed(f.Format)
	if !known {
		problems = append(problems, seckit.Problem{Field: "import-format", Label: "Its format", Message: "choose the format the file is in"})
	}
	var body []byte
	if file, _, err := r.FormFile("file"); err == nil {
		body, err = io.ReadAll(io.LimitReader(file, evidence.MaxFile+1))
		file.Close()
		if err != nil || len(body) == 0 {
			problems = append(problems, seckit.Problem{Field: "import-file", Label: "The file", Message: "the file could not be read, or is empty"})
		}
	} else {
		problems = append(problems, seckit.Problem{Field: "import-file", Label: "The file", Message: "choose the file to bring in"})
	}
	if len(body) > evidence.MaxFile {
		problems = append(problems, seckit.Problem{Field: "import-file", Label: "The file",
			Message: fmt.Sprintf("the file is larger than %d MB, the most read", evidence.MaxFile>>20)})
	}
	if len(problems) > 0 {
		s.render(w, r, "evidence_import.html", s.importData(p, g, f, problems))
		return
	}
	if format == evidence.FormatCSV || format == evidence.FormatXLSX || format == evidence.FormatJSON {
		if f.Map == "" && f.Kind == "" {
			s.render(w, r, "evidence_import.html", s.importData(p, g, f, []seckit.Problem{{Field: "import-map", Label: "Its column map",
				Message: "a table is read through a column map: choose one you confirmed, or choose what it is read into to draft one"}}))
			return
		}
	}
	// Sealed before anything reads it, as every import is, as the person
	// who sent it and recorded in the audit log: a file previewed and never
	// confirmed is kept all the same.
	wr, by, err := s.evidenceWriter(p)
	if err != nil {
		s.render(w, r, "evidence_import.html", s.importData(p, g, f, []seckit.Problem{{Field: "import-file", Label: "The file", Message: err.Error()}}))
		return
	}
	if wr.Reg.Ready != nil {
		if err := wr.Reg.Ready(); err != nil {
			s.render(w, r, "evidence_import.html", s.importData(p, g, f, []seckit.Problem{{Field: "import-file", Label: "The file", Message: err.Error()}}))
			return
		}
	}
	if _, err := wr.Seal(by, body); err != nil {
		s.render(w, r, "evidence_import.html", s.importData(p, g, f, []seckit.Problem{{Field: "import-file", Label: "The file",
			Message: "the file could not be sealed, so it was not read: " + err.Error()}}))
		return
	}
	if f.Map == "" && f.Kind != "" {
		s.evidenceDraft(w, r, p, g, f, body)
		return
	}
	s.evidencePreview(w, r, p, g, f, body)
}

// evidencePreview reads a sealed file and shows what it would write.
func (s *Server) evidencePreview(w http.ResponseWriter, r *http.Request, p principal, g *evidence.Ingester, f importForm, body []byte) {
	format, _ := evidence.FormatNamed(f.Format)
	in := evidence.Input{Format: format, Body: body, Source: f.Source, By: audit.KindHuman}
	fail := func(field, label, msg string) {
		s.render(w, r, "evidence_import.html", s.importData(p, g, f, []seckit.Problem{{Field: field, Label: label, Message: msg}}))
	}
	if err := g.Prepare(&in, f.Map); err != nil {
		fail("import-map", "Its column map", err.Error())
		return
	}
	b, err := evidence.Read(in)
	if err != nil {
		fail("import-file", "The file", err.Error())
		return
	}
	var rows []seckit.Row
	const shown = 200
	for i, fact := range b.Facts {
		if i == shown {
			break
		}
		taint := seckit.Cell{}
		if fact.Taint != "" {
			taint = seckit.BadgeCell(hiddenBadge)
		}
		what := string(fact.Taint)
		name := fact.Name
		if name == "" {
			name = string(fact.Kind) + " " + seckit.Short(string(fact.ID))
		}
		rows = append(rows, seckit.Row{Head: seckit.TextCell(name), Cells: []seckit.Cell{seckit.TextCell(string(fact.Kind)),
			seckit.TextCell(fact.Value), seckit.TextCell(fact.Place), taint, seckit.TextCell(what)}})
	}
	table, err := seckit.NewTable(fmt.Sprintf("What the file would write: %d records, the first %d shown", len(b.Facts), min(len(b.Facts), shown)),
		[]string{"Record", "Kind", "Value read", "Where in the file", "Seen", "What was hidden"}, rows)
	if err != nil {
		fail("import-file", "The file", err.Error())
		return
	}
	s.render(w, r, "evidence_preview.html", map[string]any{"Title": "Check what the file would write", "Nav": "evidence", "Principal": p,
		"Header": seckit.Header{Title: "Check what the file would write", Lead: "Nothing has been written yet. " +
			"The file is sealed, and this is everything it yields."},
		"Batch": b, "Table": table, "Grade": gradeBadge(b.Grade), "Form": f, "Hidden": b.Tainted(),
		"Said": fmt.Sprintf("Read %d records from the file. Nothing has been written yet.", len(b.Facts))})
}

// evidenceDraft drafts a column map for a sealed table, for a person to
// look at and confirm.
func (s *Server) evidenceDraft(w http.ResponseWriter, r *http.Request, p principal, g *evidence.Ingester, f importForm, body []byte) {
	format, _ := evidence.FormatNamed(f.Format)
	d, err := evidence.DraftMap(format, body, f.Kind, "", f.Sheet)
	if err != nil {
		s.render(w, r, "evidence_import.html", s.importData(p, g, f, []seckit.Problem{{Field: "import-kind", Label: "Read it into", Message: err.Error()}}))
		return
	}
	s.renderDraft(w, r, p, f, d, string(evidence.DigestOf(body)), nil, "")
}

func (s *Server) renderDraft(w http.ResponseWriter, r *http.Request, p principal, f importForm, d *evidence.Draft, digest string,
	problems []seckit.Problem, text string) {
	var rows []seckit.Row
	for _, c := range d.Map.Columns {
		from := c.Column
		if from == "" {
			from = "the value " + c.Value
		}
		rows = append(rows, seckit.Row{Head: seckit.TextCell(from), Cells: []seckit.Cell{seckit.TextCell(c.Field)}})
	}
	for _, fact := range d.Map.Facts {
		rows = append(rows, seckit.Row{Head: seckit.TextCell(fact.Column), Cells: []seckit.Cell{seckit.TextCell("the fact " + fact.Fact)}})
	}
	table, _ := seckit.NewTable("How the draft reads each column", []string{"Column", "Read into"}, rows)
	var sample []seckit.Row
	for _, line := range d.Sample {
		if len(line) == 0 {
			continue
		}
		var cells []seckit.Cell
		for _, v := range line[1:] {
			cells = append(cells, seckit.TextCell(v))
		}
		head := line[0]
		if head == "" {
			head = "(blank)"
		}
		sample = append(sample, seckit.Row{Head: seckit.TextCell(head), Cells: cells})
	}
	sampleTable, err := seckit.NewTable("The first rows it would read", d.Headings, sample)
	hasSample := err == nil
	if text == "" {
		b, _ := json.MarshalIndent(d.Map, "", "  ")
		text = string(b)
	}
	s.render(w, r, "evidence_map.html", map[string]any{"Title": "Confirm a column map", "Nav": "evidence", "Principal": p,
		"Header": seckit.Header{Title: "Confirm a column map", Lead: "A draft, from the table's headings. It reads nothing " +
			"until you confirm it, and every import of this table reads through it after."},
		"Draft": d, "Table": table, "Sample": sampleTable, "HasSample": hasSample, "Text": text,
		"Digest": digest, "Form": f, "Problems": problems, "Status": statusOf(problems)})
}

func (s *Server) handleEvidenceMap(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.evidenceReady(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	f := importForm{Format: r.FormValue("format"), Source: r.FormValue("source"), Kind: r.FormValue("kind")}
	digest, text := r.FormValue("file"), r.FormValue("map")
	again := func(msg string) {
		d := &evidence.Draft{}
		_ = json.Unmarshal([]byte(text), &d.Map)
		s.renderDraft(w, r, p, f, d, digest, []seckit.Problem{{Field: "map-text", Label: "The map", Message: msg}}, text)
	}
	var m register.ColumnMap
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		again("it is not a column map as JSON: " + err.Error())
		return
	}
	wr, by, err := s.evidenceWriter(p)
	if err != nil {
		again(err.Error())
		return
	}
	if _, err := wr.Reg.Put(by, "column map "+m.Name+", confirmed", m); err != nil {
		again(err.Error())
		return
	}
	q := url.Values{"format": {string(m.Format)}, "map": {m.Name}, "source": {f.Source}}
	if digest != "" {
		q.Set("file", digest)
	}
	http.Redirect(w, r, evidenceImportPath+"?"+q.Encode(), http.StatusSeeOther)
}

func (s *Server) handleEvidenceConfirm(w http.ResponseWriter, r *http.Request) {
	p, g, ok := s.evidenceReady(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	f := importForm{Format: r.FormValue("format"), Source: r.FormValue("source"), Map: r.FormValue("map")}
	fail := func(msg string) {
		s.render(w, r, "evidence_import.html", s.importData(p, g, f, []seckit.Problem{{Field: "import-file", Label: "The file", Message: msg}}))
	}
	format, known := evidence.FormatNamed(f.Format)
	if !known {
		fail("the format was not said; bring the file in again")
		return
	}
	body, err := g.Raw.Open(register.Digest(r.FormValue("file")))
	if err != nil {
		fail("the sealed file cannot be read: " + err.Error())
		return
	}
	wr, by, err := s.evidenceWriter(p)
	if err != nil {
		fail(err.Error())
		return
	}
	in := evidence.Input{Format: format, Body: body, Source: f.Source, By: audit.KindHuman,
		Shown: register.Digest(r.FormValue("shown"))}
	if err := wr.Prepare(&in, f.Map); err != nil {
		fail(err.Error())
		return
	}
	res, err := wr.Ingest(by, "", in)
	if err != nil {
		fail(err.Error())
		return
	}
	q := url.Values{"written": {strconv.Itoa(len(res.Receipt.Written))}, "unchanged": {strconv.Itoa(res.Receipt.Unchanged)}}
	if res.Proposed != nil {
		q.Set("proposed", strconv.Itoa(len(res.Proposed.Written)))
	}
	http.Redirect(w, r, "/evidence/file/"+string(res.Batch.RawID)+"?"+q.Encode(), http.StatusSeeOther)
}

func (s *Server) handleEvidenceFile(w http.ResponseWriter, r *http.Request) {
	p, g, ok := s.evidenceReady(w, r, auth.ActView)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/evidence/file/")
	f, err := g.FileNamed(id)
	if errors.Is(err, register.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.evidenceUnreadable(w, r, p, err)
		return
	}
	checks, err := g.Verify(string(f.ID))
	if err != nil || len(checks) != 1 {
		s.evidenceUnreadable(w, r, p, fmt.Errorf("it could not be checked: %v", err))
		return
	}
	c := checks[0]
	verdict := checksBadge
	if !c.OK() {
		verdict = brokenBadge
	}
	var rows []seckit.Row
	if list, err := g.Raw.Yield(f.Record.Yield); err == nil {
		for i, line := range strings.Split(strings.TrimRight(string(list), "\n"), "\n") {
			if i == 200 {
				break
			}
			parts := strings.Fields(line)
			if len(parts) != 3 {
				continue
			}
			rows = append(rows, seckit.Row{Head: seckit.LinkCell("/register/record/"+parts[1], parts[1]),
				Cells: []seckit.Cell{seckit.TextCell(parts[0]), seckit.HashCell("sha256:" + parts[2])}})
		}
	}
	table, _ := seckit.NewTable(fmt.Sprintf("What was read from it: %d records, the first %d shown", c.Facts, len(rows)),
		[]string{"Record", "Kind", "Its fields as read"}, rows)
	kept := heldBadge
	if !f.Held {
		kept = erasedBadge
	}
	data := map[string]any{"Title": string(f.Record.Format) + " file " + seckit.Short(string(f.Record.Digest)), "Nav": "evidence",
		"Principal": p, "Header": seckit.Header{Title: string(f.Record.Format) + " file " + seckit.Short(string(f.Record.Digest)),
			Lead: "A file brought in as evidence, sealed by its hash before anything read it."},
		"File": f, "Check": c, "Verdict": verdict, "Grade": gradeBadge(f.Record.Grade), "Kept": kept, "Table": table,
		"Received": seckit.TimeCell(f.Record.Received.At()), "Said": ""}
	if f.Sealed != nil {
		data["Until"] = seckit.TimeCell(f.Sealed.Until)
		if !f.Held {
			data["Erased"] = seckit.TimeCell(f.Sealed.Erased)
		}
	}
	q := r.URL.Query()
	if n := q.Get("written"); n != "" {
		said := "Written: " + n + " records, " + q.Get("unchanged") + " already in the register unchanged."
		if n == "0" {
			said = "The register already held every record this file yields, so nothing was written."
		}
		if pr := q.Get("proposed"); pr != "" {
			said += " " + pr + " proposals wait for a person."
		}
		data["Said"] = said
	}
	s.render(w, r, "evidence_file.html", data)
}

func (s *Server) handleEvidenceKeys(w http.ResponseWriter, r *http.Request) {
	act := auth.ActView
	if r.Method == http.MethodPost {
		act = auth.ActEditDraft
	}
	p, g, ok := s.evidenceReady(w, r, act)
	if !ok {
		return
	}
	var problems []seckit.Problem
	said := ""
	form := map[string]string{}
	if r.Method == http.MethodPost {
		name, title, keyid, key := strings.TrimSpace(r.FormValue("name")), r.FormValue("title"), r.FormValue("keyid"), r.FormValue("key")
		form = map[string]string{"name": name, "title": title, "keyid": keyid, "key": key}
		k, err := evidence.PinKey(name, title, keyid, []byte(key), time.Now())
		if err != nil {
			field, label := "key-key", "The public key"
			if strings.Contains(err.Error(), "name") {
				field, label = "key-name", "Its name"
			}
			problems = append(problems, seckit.Problem{Field: field, Label: label, Message: err.Error()})
		} else {
			wr, by, err := s.evidenceWriter(p)
			if err == nil {
				_, err = wr.Reg.Put(by, "key "+k.Name+", pinned", k)
			}
			if err != nil {
				problems = append(problems, seckit.Problem{Field: "key-key", Label: "The public key", Message: err.Error()})
			} else {
				said = "Pinned " + k.Name + ", with the fingerprint " + string(k.Fingerprint) + "."
				form = map[string]string{}
			}
		}
	}
	var mapRows, keyRows []seckit.Row
	maps, _, err := g.Reg.List(register.KindColumnMap, 0, 200)
	if err != nil {
		s.evidenceUnreadable(w, r, p, err)
		return
	}
	for _, e := range maps {
		m := e.Record.(register.ColumnMap)
		tool := m.Tool
		if tool == "" {
			tool = "a person's own table"
		}
		mapRows = append(mapRows, seckit.Row{Head: seckit.LinkCell("/register/record/"+string(e.ID), m.Name),
			Cells: []seckit.Cell{seckit.TextCell(string(m.Format)), seckit.TextCell(m.Makes), seckit.TextCell(tool), seckit.TimeCell(e.Updated.At())}})
	}
	keys, err := g.PinnedKeys()
	if err != nil {
		s.evidenceUnreadable(w, r, p, err)
		return
	}
	for _, k := range keys {
		keyRows = append(keyRows, seckit.Row{Head: seckit.TextCell(k.Name), Cells: []seckit.Cell{seckit.TextCell(k.Title),
			seckit.TextCell(string(k.Algorithm)), seckit.HashCell(string(k.Fingerprint)), seckit.TimeCell(k.Pinned.At())}})
	}
	mapTable, _ := seckit.NewTable("Column maps a person confirmed", []string{"Map", "Reads", "Into", "Whose export", "Confirmed"}, mapRows)
	keyTable, _ := seckit.NewTable("Keys a person pinned", []string{"Key", "Whose", "Algorithm", "Fingerprint", "Pinned"}, keyRows)
	byField := map[string]seckit.Problem{}
	for _, pr := range problems {
		byField[pr.Field] = pr
	}
	s.render(w, r, "evidence_keys.html", map[string]any{"Status": statusOf(problems), "Title": "Column maps and pinned keys", "Nav": "evidence",
		"Principal": p, "Header": seckit.Header{Title: "Column maps and pinned keys", Lead: "How tables are read, and whose " +
			"signatures count. A person decides both, once."},
		"Maps": mapTable, "Keys": keyTable, "HasMaps": len(mapRows) > 0, "HasKeys": len(keyRows) > 0,
		"Problems": problems, "ByField": byField, "Form": form, "Said": said,
		"CanPin": s.allows(p, auth.ActEditDraft, register.Area)})
}

// statusOf is the status a form's page is answered with: unprocessable
// while it has problems, so a client that reads only the status is told.
func statusOf(problems []seckit.Problem) int {
	if len(problems) > 0 {
		return http.StatusUnprocessableEntity
	}
	return http.StatusOK
}

// handleEvidenceExpire erases the raw files whose time to be kept is up, as
// the person who asked, recorded in the audit log. Nothing is erased before
// its time; the seals and the lists of what was read are kept.
func (s *Server) handleEvidenceExpire(w http.ResponseWriter, r *http.Request) {
	p, _, ok := s.evidenceReady(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	wr, by, err := s.evidenceWriter(p)
	if err != nil {
		s.evidenceUnreadable(w, r, p, err)
		return
	}
	gone, err := wr.Expire(by)
	if err != nil {
		s.evidenceUnreadable(w, r, p, err)
		return
	}
	http.Redirect(w, r, "/evidence?erased="+strconv.Itoa(len(gone)), http.StatusSeeOther)
}
