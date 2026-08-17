package admin

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/form"
)

// Reading the postbag, which the public server deliberately cannot.
//
// Everything that reads, exports or removes a submission lives here, behind
// authentication, in the process that is not exposed to the internet. The
// public half can append and nothing else — see internal/public/forms.go.
//
// The erasure tools are first-class rather than an afterthought. A store
// holding what members of the public typed needs a way to answer "delete
// everything about me", and it needs it to start from an email address rather
// than a submission identifier, because that is what the person asking has.

// Forms gives the admin the declared forms and the submission store.
type Forms struct {
	Load  func() (*form.Set, error)
	Save  func(*form.Set) error
	Store *form.Store
}

func (s *Server) handleForms(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	// Submissions are what members of the public typed, so reading them needs
	// more than viewing the site. Gated on editing rather than on
	// administration because answering enquiries is an editor's job, and a
	// control only an administrator can use is a control somebody shares an
	// administrator credential to get around.
	if !s.can(w, r, p, auth.ActEditDraft, "/") {
		return
	}
	if s.Forms == nil || s.Forms.Store == nil {
		s.unwired(w, r, p, "Forms", "forms and submissions")
		return
	}
	set, err := s.Forms.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	selected := r.URL.Query().Get("f")
	if selected == "" && len(set.Forms) > 0 {
		selected = set.Names()[0]
	}

	type formRow struct {
		form.Form
		Count     int
		Retention int
		Oldest    int64
	}
	var rows []formRow
	for _, name := range set.Names() {
		f, _ := set.Get(name)
		subs, _ := s.Forms.Store.List(name)
		row := formRow{Form: *f, Count: len(subs),
			Retention: int(f.Retention().Hours() / 24)}
		if len(subs) > 0 {
			row.Oldest = subs[len(subs)-1].At
		}
		rows = append(rows, row)
	}

	var subs []form.Submission
	var fields []form.Field
	// The markup to paste into a template.
	//
	// A form needs two fields nobody declares — the honeypot and the timestamp
	// — and both are refused when missing. Neither appeared anywhere a person
	// could see them, so a form built entirely through this screen could not be
	// made to work: every submission came back with the deliberately
	// uninformative answer a spam script gets, and there was nothing else to
	// read. Printing the markup is the fix, because the rule is about markup.
	embed := ""
	if selected != "" {
		subs, _ = s.Forms.Store.List(selected)
		if f, ok := set.Get(selected); ok {
			fields = f.Fields
			embed = form.Embed(f)
		}
		if len(subs) > 50 {
			subs = subs[:50]
		}
	}

	// A search, for an erasure request. The person asking gives an address.
	var found []form.Submission
	if needle := strings.TrimSpace(r.URL.Query().Get("q")); needle != "" {
		found, _ = s.Forms.Store.Search(set, needle)
	}

	s.render(w, r, "forms.html", map[string]any{
		"Nav": "forms", "Title": "Forms", "Principal": p,
		"Forms": rows, "Selected": selected, "Submissions": subs,
		"Fields": fields, "Found": found, "Query": r.URL.Query().Get("q"),
		"Embed": embed,
		"Kinds": []form.Kind{form.Line, form.Para, form.Email, form.Number,
			form.Choice, form.Agree},
		"MaxRetention": form.MaxRetentionDays,
		"Message":      r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"CanErase": s.Policy.Evaluate(p.Name, auth.ActGrant, "/").Allowed,
	})
}

// handleFormSave declares a form, or adds a field to one.
func (s *Server) handleFormSave(w http.ResponseWriter, r *http.Request) {
	p, ok := s.formWriter(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	set, err := s.Forms.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := strings.TrimSpace(r.FormValue("form"))
	f, exists := set.Get(name)
	if !exists {
		days, _ := strconv.Atoi(r.FormValue("retention"))
		fresh := form.Form{
			Name: name, Label: strings.TrimSpace(r.FormValue("label")),
			Intro:         strings.TrimSpace(r.FormValue("intro")),
			Notice:        strings.TrimSpace(r.FormValue("notice")),
			RetentionDays: days,
			Fields: []form.Field{{
				Name:  strings.TrimSpace(r.FormValue("field")),
				Label: strings.TrimSpace(r.FormValue("field_label")),
				Kind:  form.Kind(r.FormValue("field_kind")),
			}},
		}
		if err := set.Add(fresh); err != nil {
			s.formRedirect(w, r, "", err.Error())
			return
		}
		f, _ = set.Get(name)
	} else if fname := strings.TrimSpace(r.FormValue("field")); fname != "" {
		fl := form.Field{
			Name: fname, Label: strings.TrimSpace(r.FormValue("field_label")),
			Kind:      form.Kind(r.FormValue("field_kind")),
			Required:  r.FormValue("required") != "",
			Sensitive: r.FormValue("sensitive") != "",
			Help:      strings.TrimSpace(r.FormValue("field_help")),
		}
		for _, c := range strings.Split(r.FormValue("choices"), ",") {
			if c = strings.TrimSpace(c); c != "" {
				fl.Choices = append(fl.Choices, c)
			}
		}
		replaced := false
		for i := range f.Fields {
			if f.Fields[i].Name == fname {
				f.Fields[i], replaced = fl, true
				break
			}
		}
		if !replaced {
			f.Fields = append(f.Fields, fl)
		}
	}
	if err := f.Validate(); err != nil {
		s.formRedirect(w, r, "", err.Error())
		return
	}
	if err := s.Forms.Save(set); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "form.save", "/", map[string]string{"form": name})
	s.formRedirect(w, r, "saved "+name, "")
}

// handleFormClose stops a form taking anything more, keeping what it has.
func (s *Server) handleFormClose(w http.ResponseWriter, r *http.Request) {
	p, ok := s.formWriter(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	set, err := s.Forms.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f, exists := set.Get(r.FormValue("form"))
	if !exists {
		s.formRedirect(w, r, "", "there is no such form")
		return
	}
	f.Closed = !f.Closed
	if err := s.Forms.Save(set); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	state := "open"
	if f.Closed {
		state = "closed"
	}
	s.auditPub(p, "form.close", "/", map[string]string{
		"form": f.Name, "state": state})
	s.formRedirect(w, r, f.Name+" is now "+state, "")
}

// handleSubmissionDelete removes one.
//
// The operation the content store cannot offer, and the reason submissions are
// not in it.
func (s *Server) handleSubmissionDelete(w http.ResponseWriter, r *http.Request) {
	p, ok := s.formWriter(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	f, id := r.FormValue("form"), r.FormValue("id")
	if err := s.Forms.Store.Delete(f, id); err != nil {
		s.formRedirect(w, r, "", err.Error())
		return
	}
	// The identifier and the form, never the content. A log outliving the
	// retention period must not be where the deleted data survives.
	s.auditPub(p, "submission.delete", "/"+f,
		map[string]string{"submission": id})
	s.formRedirect(w, r, "deleted", "")
}

// handleFormPurge removes everything a form gathered.
//
// Gated harder than deleting one, because it is irreversible across a whole
// campaign rather than one row.
func (s *Server) handleFormPurge(w http.ResponseWriter, r *http.Request) {
	p, ok := s.formWriter(w, r, auth.ActGrant)
	if !ok {
		return
	}
	name := r.FormValue("form")
	if r.FormValue("confirm") != name {
		s.formRedirect(w, r, "", "type the form's name to confirm; this "+
			"removes every submission it has gathered and cannot be undone")
		return
	}
	n, err := s.Forms.Store.Purge(name)
	if err != nil {
		s.formRedirect(w, r, "", err.Error())
		return
	}
	s.auditPub(p, "form.purge", "/"+name,
		map[string]string{"removed": strconv.Itoa(n)})
	s.formRedirect(w, r, fmt.Sprintf("removed %d submission(s)", n), "")
}

// handleFormExport writes submissions as CSV.
func (s *Server) handleFormExport(w http.ResponseWriter, r *http.Request) {
	p, ok := s.formWriter(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	set, err := s.Forms.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := r.FormValue("form")
	f, exists := set.Get(name)
	if !exists {
		s.formRedirect(w, r, "", "there is no such form")
		return
	}
	subs, err := s.Forms.Store.List(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s.csv"`, name))
	cw := csv.NewWriter(w)
	defer cw.Flush()

	head := []string{"id", "received"}
	for _, fl := range f.Fields {
		head = append(head, fl.Name)
	}
	_ = cw.Write(head)
	for _, sub := range subs {
		row := []string{sub.ID, time.Unix(sub.At, 0).UTC().Format(time.RFC3339)}
		for _, fl := range f.Fields {
			row = append(row, csvSafe(sub.Values[fl.Name]))
		}
		_ = cw.Write(row)
	}
	s.auditPub(p, "form.export", "/"+name,
		map[string]string{"rows": strconv.Itoa(len(subs))})
}

// csvSafe defuses a value a spreadsheet would execute.
//
// CSV injection: a cell beginning =, +, - or @ is a formula in Excel, Numbers
// and Sheets, and =HYPERLINK or =WEBSERVICE will exfiltrate the rest of the
// sheet to whoever typed it. Quoting does not help — the escaping is correct
// CSV and the spreadsheet evaluates it anyway.
//
// Prefixing with an apostrophe is the standard defusal: the cell displays as
// typed and is not evaluated. It changes the stored value, which is why it
// happens here at export rather than at collection — the submission keeps what
// the person actually wrote.
func csvSafe(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}

// handleFormExpire runs retention now.
func (s *Server) handleFormExpire(w http.ResponseWriter, r *http.Request) {
	p, ok := s.formWriter(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	set, err := s.Forms.Load()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n, err := s.Forms.Store.Expire(set, time.Now())
	if err != nil {
		s.formRedirect(w, r, "", err.Error())
		return
	}
	s.auditPub(p, "form.expire", "/", map[string]string{
		"removed": strconv.Itoa(n)})
	s.formRedirect(w, r, fmt.Sprintf(
		"%d submission(s) were past their retention period and are gone", n), "")
}

func (s *Server) formWriter(w http.ResponseWriter, r *http.Request,
	act auth.Action) (principal, bool) {

	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return principal{}, false
	}
	p, ok := s.requireAuth(w, r)
	if !ok {
		return principal{}, false
	}
	if !s.can(w, r, p, act, "/") {
		return principal{}, false
	}
	if s.Forms == nil || s.Forms.Store == nil {
		s.unwired(w, r, p, "Forms", "forms and submissions")
		return principal{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return principal{}, false
	}
	return p, true
}

func (s *Server) formRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/forms"
	if f := r.FormValue("form"); f != "" {
		u += "?f=" + url.QueryEscape(f)
	}
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	switch {
	case errMsg != "":
		u += sep + "e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += sep + "m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

var _ = sort.Strings
