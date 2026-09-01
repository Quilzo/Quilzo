package admin

import (
	"net/http"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/media"
)

// Recording who owns a picture, from the interface people use.
//
// # The dead end this removes
//
// An image licence is a publish window pointed at a file. `quilzo publish`
// refuses a publication carrying an image whose permission has ended, and
// reports the undeclared ones so somebody goes and declares them. All of which
// assumed somebody could declare them — and the only place that could was the
// command line. The admin uploaded files, described them, listed them, deleted
// them, and had no field anywhere for a licence.
//
// So an editor working in a browser could upload a photograph, put it on a page,
// press Publish, and be refused by a gate with nothing in the interface that
// answers it. Their remaining options were a terminal on the server or removing
// the picture. That is the shape this codebase keeps finding: a capability built
// and tested, reachable from one surface out of three.
//
// # Why the fields are the CLI's fields
//
// Licence, holder, until, note — and clearing removes the whole record rather
// than blanking one field, because media.Rights.Validate refuses an expiry with
// no licence and no holder, so a partial clear would leave a store in a state
// its own validator rejects. Same semantics as `quilzo rights set`, same
// validator, same audit action: two ways to record a fact that disagree about
// what a fact is would be worse than one way.

// handleMediaRights records what permits publishing one file.
func (s *Server) handleMediaRights(w http.ResponseWriter, r *http.Request) {
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
	if s.Media == nil {
		s.unwired(w, r, p, "Media", "the media library")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	lib, err := s.Media.Library()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id := r.FormValue("id")
	f, body, err := lib.Get(id)
	if err != nil {
		s.mediaRedirect(w, r, "", err.Error())
		return
	}

	now := time.Now().UTC()
	was := f.Rights

	if r.FormValue("clear") != "" {
		if !was.Declared() && was.Until == 0 {
			s.mediaRedirect(w, r, "nothing was recorded for that file.", "")
			return
		}
		f.Rights = media.Rights{}
		if perr := lib.Put(f, body); perr != nil {
			s.mediaRedirect(w, r, "", perr.Error())
			return
		}
		s.auditPub(p, "rights.set", "/"+shortHash(f.ID), map[string]string{
			"cleared": "the whole record",
			"was":     strings.TrimSpace(was.Licence + " / " + was.Holder),
		})
		s.mediaRedirect(w, r, f.Name+" is undeclared again. It will be listed "+
			"as something to declare.", "")
		return
	}

	next := media.Rights{
		Licence: strings.TrimSpace(r.FormValue("licence")),
		Holder:  strings.TrimSpace(r.FormValue("holder")),
		Note:    strings.TrimSpace(r.FormValue("note")),
	}
	// An empty date means no end, which is the ordinary case for work a
	// business owns outright — and is still a claim somebody makes by leaving
	// the field empty rather than one this fills in for them.
	if until := strings.TrimSpace(r.FormValue("until")); until != "" {
		when, perr := time.Parse("2006-01-02", until)
		if perr != nil {
			s.mediaRedirect(w, r, "",
				"the date has to be YYYY-MM-DD; "+until+" is not")
			return
		}
		next.Until = when.UTC().Unix()
	}
	if verr := next.Validate(now); verr != nil {
		s.mediaRedirect(w, r, "", verr.Error())
		return
	}
	if !next.Declared() && next.Until == 0 {
		s.mediaRedirect(w, r, "",
			"name a licence or a holder — an empty record is the same as no "+
				"record, and clearing is its own button")
		return
	}

	f.Rights = next
	if perr := lib.Put(f, body); perr != nil {
		s.mediaRedirect(w, r, "", perr.Error())
		return
	}
	s.auditPub(p, "rights.set", "/"+shortHash(f.ID), map[string]string{
		"licence": next.Licence, "holder": next.Holder,
		"state": next.State(now, media.LapseWindow),
	})
	s.mediaRedirect(w, r, f.Name+": "+next.State(now, media.LapseWindow)+".", "")
}

// rightsRow is one file's rights, in the shape the template reads.
type rightsRow struct {
	// State is what the publish gate would say about it today.
	State string
	// Until is the expiry as a date field's value, so the form comes back
	// filled in rather than empty with the value shown beside it.
	Until string
	// Ends is the same date for a person to read, empty when there is none.
	Ends string
}

// rightsOf describes a file's rights for the screen.
func rightsOf(f media.File, now time.Time) rightsRow {
	row := rightsRow{State: f.Rights.State(now, media.LapseWindow)}
	if f.Rights.Until != 0 {
		when := time.Unix(f.Rights.Until, 0).UTC()
		row.Until = when.Format("2006-01-02")
		row.Ends = when.Format("2 January 2006")
	}
	return row
}
