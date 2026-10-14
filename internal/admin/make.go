// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/feature"
)

// Make: features as packages (internal/feature). A person drops in a
// package, reads its permission card and what it would change, and installs
// it; one that holds personal data, collects from the public, sends
// anything outside or adds an agent that acts on its own waits here for a
// second person. Installed features can be rolled back or removed.
//
// The package bytes travel from the check to the install in a hidden field
// with their digest beside them, and the install refuses bytes whose digest
// is not the one the person was shown: what is installed is exactly what
// was read.

// FeatureHooks reach the feature store, which the command line owns.
type FeatureHooks struct {
	Installed func() ([]feature.Installed, error)
	Pending   func() ([]feature.Pending, error)
	// Check reads a package: its card and its plan, changing nothing.
	Check func(body []byte) (*feature.Package, feature.Card, feature.Plan, error)
	// Install installs for a person, or leaves it waiting; the id is the
	// waiting request's, empty when it went in at once. rows names records
	// kept from a spreadsheet to import with it. Secrets are new webhooks'
	// signing secrets, shown once on the response and never in a
	// redirect, a log or a later page.
	Install func(body []byte, rows, by string) (string, []string, error)
	// Draft asks a model for a package from a description; invalid says
	// why the draft would not install yet.
	Draft func(description, by string) (body []byte, notes []string, invalid string, err error)
	// FromData makes a package from a spreadsheet or JSON list, keeping
	// its rows under an id until the install.
	FromData func(name string, data []byte, by string) (body []byte, rows string, count int, into string, notes []string, err error)
	Decide   func(id string, approve bool, by string) error
	Remove   func(name, by string) error
	Rollback func(name, by string) (string, error)
}

var (
	reFeatureName = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	reRowsID      = regexp.MustCompile(`^[0-9a-f]{24}$`)
)

func (s *Server) handleMake(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	data := map[string]any{"Title": "Make", "Nav": "make", "Principal": p,
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e")}
	if s.Features == nil {
		data["Unavailable"] = "This build was started without the feature store."
		s.render(w, r, "make.html", data)
		return
	}
	now := time.Now().UTC()
	type waiting struct {
		feature.Pending
		Mine bool
		When string
	}
	if pend, err := s.Features.Pending(); err == nil {
		var list []waiting
		for _, pd := range pend {
			list = append(list, waiting{pd, strings.EqualFold(pd.RequestedBy, p.Name), agoText(now.Sub(pd.At))})
		}
		data["Pending"] = list
	}
	if in, err := s.Features.Installed(); err == nil {
		data["Installed"] = in
	}
	s.render(w, r, "make.html", data)
}

// handleMakeCheck reads an uploaded package and shows its card and plan,
// with the bytes kept for the install button.
func (s *Server) handleMakeCheck(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	if s.Features == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, feature.MaxBytes+64<<10)
	var body []byte
	if err := r.ParseMultipartForm(feature.MaxBytes + 64<<10); err == nil {
		if f, _, ferr := r.FormFile("package"); ferr == nil {
			body, _ = io.ReadAll(io.LimitReader(f, feature.MaxBytes+1))
			f.Close()
		}
	}
	if len(body) == 0 {
		body = []byte(r.FormValue("text"))
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		makeBack(w, r, "", errors.New("choose a package file, or paste one"))
		return
	}
	s.renderCheck(w, r, p, body, nil, "", "", 0, "")
}

// handleMakeDraft asks a model for a package from a description and shows
// it as any other package is shown: its card, its plan, what was left out.
func (s *Server) handleMakeDraft(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	if s.Features == nil || s.Features.Draft == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	body, notes, invalid, err := s.Features.Draft(r.FormValue("description"), p.Name)
	if err != nil {
		makeBack(w, r, "", err)
		return
	}
	s.renderCheck(w, r, p, body, notes, invalid, "", 0, "")
}

// handleMakeFrom makes a package from an uploaded spreadsheet.
func (s *Server) handleMakeFrom(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	if s.Features == nil || s.Features.FromData == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		makeBack(w, r, "", errors.New("choose a CSV or JSON file"))
		return
	}
	f, hdr, err := r.FormFile("data")
	if err != nil {
		makeBack(w, r, "", errors.New("choose a CSV or JSON file"))
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, 64<<20))
	f.Close()
	if err != nil {
		makeBack(w, r, "", err)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = strings.TrimSuffix(hdr.Filename, filepathExt(hdr.Filename))
	}
	body, rows, count, into, notes, err := s.Features.FromData(name, data, p.Name)
	if err != nil {
		makeBack(w, r, "", err)
		return
	}
	s.renderCheck(w, r, p, body, notes, "", rows, count, into)
}

func filepathExt(name string) string {
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		return name[i:]
	}
	return ""
}

// renderCheck shows a package's card and plan, or why it cannot install.
func (s *Server) renderCheck(w http.ResponseWriter, r *http.Request, p principal, body []byte, notes []string,
	invalid, rows string, count int, into string) {
	data := map[string]any{"Title": "Check a feature", "Nav": "make", "Principal": p, "Notes": notes,
		"Body": string(body), "Rows": rows, "RowCount": count, "Into": into}
	if invalid == "" {
		pkg, card, plan, err := s.Features.Check(body)
		if err != nil {
			invalid = err.Error()
		} else {
			digest, _ := pkg.Digest()
			data["Package"], data["Card"], data["Plan"], data["Digest"] = pkg, card, plan, digest
			data["Title"] = "Check " + pkg.Title
		}
	}
	data["Invalid"] = invalid
	s.render(w, r, "make_check.html", data)
}

// handleMakeAct installs a checked package, or decides, removes or rolls
// back one.
func (s *Server) handleMakeAct(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "post", http.StatusMethodNotAllowed)
		return
	}
	if !s.can(w, r, p, auth.ActGrant, "/") {
		return
	}
	if s.Features == nil {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 3*feature.MaxBytes)
	switch do := r.FormValue("do"); do {
	case "install":
		body := []byte(r.FormValue("body"))
		pkg, err := feature.Decode(strings.NewReader(string(body)))
		if err != nil {
			makeBack(w, r, "", err)
			return
		}
		if d, _ := pkg.Digest(); d != r.FormValue("digest") {
			makeBack(w, r, "", errors.New("the package changed after it was checked; check it again"))
			return
		}
		rows := r.FormValue("rows")
		if rows != "" && !reRowsID.MatchString(rows) {
			makeBack(w, r, "", errors.New("those records are not ones this screen kept"))
			return
		}
		id, secrets, err := s.Features.Install(body, rows, p.Name)
		switch {
		case err != nil:
			makeBack(w, r, "", err)
		case id != "":
			makeBack(w, r, fmt.Sprintf("%s waits for a second person to approve it.", pkg.Title), nil)
		case len(secrets) > 0:
			w.Header().Set("Cache-Control", "no-store")
			s.render(w, r, "make.html", map[string]any{"Title": "Make", "Nav": "make", "Principal": p,
				"Message": pkg.Title + " is installed. Copy each webhook's secret now: it is not shown again.",
				"Secrets": secrets, "Done": true})
		default:
			makeBack(w, r, fmt.Sprintf("%s is installed. Its pages are in the draft; publishing them is the usual review.",
				pkg.Title), nil)
		}
	case "approve", "decline":
		id := r.FormValue("id")
		if !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(id) {
			makeBack(w, r, "", errors.New("that is not a request"))
			return
		}
		if err := s.Features.Decide(id, do == "approve", p.Name); err != nil {
			makeBack(w, r, "", err)
			return
		}
		makeBack(w, r, map[bool]string{true: "Approved and installed.", false: "Declined."}[do == "approve"], nil)
	case "remove", "rollback":
		name := r.FormValue("name")
		if !reFeatureName.MatchString(name) {
			makeBack(w, r, "", errors.New("that is not a feature"))
			return
		}
		if do == "remove" {
			if err := s.Features.Remove(name, p.Name); err != nil {
				makeBack(w, r, "", err)
				return
			}
			makeBack(w, r, name+" was removed. Page removals are in the draft, and records people entered are kept.", nil)
			return
		}
		id, err := s.Features.Rollback(name, p.Name)
		switch {
		case err != nil:
			makeBack(w, r, "", err)
		case id != "":
			makeBack(w, r, "Going back to the earlier version waits for a second person.", nil)
		default:
			makeBack(w, r, name+" is back on its earlier version.", nil)
		}
	default:
		makeBack(w, r, "", errors.New("say what to do"))
	}
}

func makeBack(w http.ResponseWriter, r *http.Request, msg string, err error) {
	v := "m=" + url.QueryEscape(msg)
	if err != nil {
		v = "e=" + url.QueryEscape(err.Error())
	}
	http.Redirect(w, r, "/make?"+v, http.StatusSeeOther)
}

// featureApprovals are installs waiting for a second person, for the
// approvals screen.
func (s *Server) featureApprovals(p principal) []approvalItem {
	if s.Features == nil || s.Features.Pending == nil || !s.Policy.Evaluate(p.Name, auth.ActGrant, "/").Allowed {
		return nil
	}
	pend, err := s.Features.Pending()
	if err != nil {
		return nil
	}
	var out []approvalItem
	for _, pd := range pend {
		if strings.EqualFold(pd.RequestedBy, p.Name) {
			continue
		}
		title := "Install " + pd.Card.Title + " " + pd.Version
		if pd.Rollback {
			title = "Roll " + pd.Card.Title + " back to " + pd.Version
		}
		out = append(out, approvalItem{Source: "feature", Agent: "feature " + pd.Name, Title: title,
			Detail:  "risk " + pd.Card.Risk + ": " + strings.Join(pd.Card.Because, "; ") + "; asked by " + pd.RequestedBy,
			Commits: "installs", Href: "/make", Since: pd.At})
	}
	return out
}
