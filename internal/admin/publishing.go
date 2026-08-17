package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/schedule"
	"github.com/quilzo/quilzo/internal/site"
)

// Running a site: where the work is, when it goes out, and who is holding it.
//
// Three capabilities that were only ever on the command line, on one screen
// because they are one question. "Can I publish this now" is answered by all
// three at once — whether staging has it, whether something is already
// scheduled for later, and whether somebody else is mid-edit — and answering
// it used to mean three commands in a terminal the person doing the editing
// does not have open.

// Publishing gives the admin the deployment pipeline.
type Publishing struct {
	// Envs is the configured environment set and how to change it.
	Envs     func() (*site.Envs, error)
	SaveEnvs func(*site.Envs) error
	// Schedule is work queued for later.
	Schedule     func() (*schedule.Schedule, error)
	SaveSchedule func(*schedule.Schedule) error
}

// envView is one environment as the screen shows it.
type envView struct {
	site.Behind
	// Next names where this one promotes to, so the button can say it rather
	// than making somebody work out the order from the list.
	Next string
}

func (s *Server) handlePublishing(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireAuth(w, r)
	if !ok {
		return
	}
	if !s.can(w, r, p, auth.ActView, "/") {
		return
	}
	if s.Publishing == nil {
		s.unwired(w, r, p, "Publishing", "environments and scheduling")
		return
	}

	envs, err := s.Publishing.Envs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	behind, err := site.Status(s.Store, envs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sorted := envs.Sorted()
	views := make([]envView, 0, len(behind))
	for i, b := range behind {
		v := envView{Behind: b}
		if i+1 < len(sorted) {
			v.Next = sorted[i+1].Name
		}
		views = append(views, v)
	}

	draft := s.Store.GetRef(site.RefDraft)

	// What is queued, and whether it still describes the draft anybody has
	// looked at. A stale entry is the failure mode of scheduled publishing and
	// it is invisible unless it is drawn.
	var pending []schedule.Staleness
	if s.Publishing.Schedule != nil {
		if sch, err := s.Publishing.Schedule(); err == nil {
			pending = sch.Check(draft, time.Now())
		}
	}

	var held []collab.Lock
	if s.Locks != nil {
		if locks, err := s.Locks(); err == nil {
			held = locks.Active(time.Now())
			sort.Slice(held, func(i, j int) bool { return held[i].Page < held[j].Page })
		}
	}

	s.render(w, r, "publishing.html", map[string]any{
		"Nav": "publishing", "Title": "Publishing", "Principal": p,
		"Envs": views, "Draft": shortHash(draft), "Pending": pending,
		"Locks": held, "Now": time.Now().Unix(),
		"Message": r.URL.Query().Get("m"), "Error": r.URL.Query().Get("e"),
		"CanPromote": s.Policy.Evaluate(p.Name, auth.ActPublish, "/").Allowed,
		"CanEdit":    s.Policy.Evaluate(p.Name, auth.ActEditDraft, "/").Allowed,
	})
}

// handlePromote moves one environment's ref to what another holds.
//
// Nothing is copied. The environment being promoted to serves the same objects
// the one before it served, which is what makes "it was checked in staging" an
// exact statement rather than a hopeful one.
func (s *Server) handlePromote(w http.ResponseWriter, r *http.Request) {
	p, ok := s.publishWriter(w, r, auth.ActPublish)
	if !ok {
		return
	}
	envs, err := s.Publishing.Envs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	from, to := r.FormValue("from"), r.FormValue("to")
	// Skipping an environment is possible and has to be asked for by name. A
	// pipeline that can silently skip staging is one that eventually does, in
	// a hurry, at the worst moment — so the checkbox exists and its state is
	// recorded.
	skip := r.FormValue("skip") != ""

	prom, err := site.Promote(s.Store, envs, from, to, skip)
	if err != nil {
		s.auditPub(p, "env.promote", "/", map[string]string{
			"from": from, "to": to, "outcome": "denied", "reason": err.Error()})
		s.pubRedirect(w, r, "", err.Error())
		return
	}
	detail := map[string]string{"from": prom.From, "to": prom.To,
		"commit": shortHash(prom.Commit), "was": shortHash(prom.Previous)}
	if skip {
		detail["skipped"] = "an environment was bypassed deliberately"
	}
	s.auditPub(p, "env.promote", "/", detail)

	if prom.Identical {
		s.pubRedirect(w, r, fmt.Sprintf("%s already held %s; nothing moved",
			prom.To, shortHash(prom.Commit)), "")
		return
	}
	s.pubRedirect(w, r, fmt.Sprintf(
		"%s → %s, %d change(s). The same objects, not a copy.",
		prom.From, prom.To, len(prom.Changes)), "")
}

// handleEnvSave adds an environment.
func (s *Server) handleEnvSave(w http.ResponseWriter, r *http.Request) {
	p, ok := s.publishWriter(w, r, auth.ActPublish)
	if !ok {
		return
	}
	envs, err := s.Publishing.Envs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	before := strings.TrimSpace(r.FormValue("before"))

	order := 50
	if before != "" {
		target, found := envs.Lookup(before)
		if !found {
			s.pubRedirect(w, r, "", "there is no environment called "+before)
			return
		}
		low := 0
		if prev, has := envs.Previous(target.Name); has {
			low = prev.Order
		}
		// Midway between, so several can be inserted without renumbering.
		order = (low + target.Order) / 2
		if order == low || order == target.Order {
			s.pubRedirect(w, r, "", fmt.Sprintf(
				"there is no room between %s and %s for another environment; "+
					"the orders have to be renumbered by hand", before, target.Name))
			return
		}
	}
	envs.Environments = append(envs.Environments, site.Env{
		Name: name, Ref: "env-" + name, Order: order,
		Description: strings.TrimSpace(r.FormValue("description")),
	})
	if err := s.Publishing.SaveEnvs(envs); err != nil {
		s.pubRedirect(w, r, "", err.Error())
		return
	}
	s.auditPub(p, "env.add", "/", map[string]string{"environment": name})
	s.pubRedirect(w, r, "added "+name, "")
}

// handleEnvRemove takes an environment out of the sequence.
//
// The ref is deliberately left alone. Removing the environment removes a name
// from a list; deleting the ref would discard the record of what it was
// serving, which is exactly the thing somebody asks about afterwards.
func (s *Server) handleEnvRemove(w http.ResponseWriter, r *http.Request) {
	p, ok := s.publishWriter(w, r, auth.ActPublish)
	if !ok {
		return
	}
	envs, err := s.Publishing.Envs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	name := r.FormValue("name")
	target, found := envs.Lookup(name)
	if !found {
		s.pubRedirect(w, r, "", "there is no environment called "+name)
		return
	}
	if target.Production {
		s.pubRedirect(w, r, "", target.Name+" is production; removing it would "+
			"leave nothing serving the public")
		return
	}
	kept := envs.Environments[:0]
	for _, e := range envs.Environments {
		if e.Name != target.Name {
			kept = append(kept, e)
		}
	}
	envs.Environments = kept
	if err := s.Publishing.SaveEnvs(envs); err != nil {
		s.pubRedirect(w, r, "", err.Error())
		return
	}
	s.auditPub(p, "env.remove", "/", map[string]string{"environment": name})
	s.pubRedirect(w, r, "removed "+name+". Its ref is left in place, so what it "+
		"was serving is still recoverable.", "")
}

// handleScheduleAdd queues the current draft for later.
func (s *Server) handleScheduleAdd(w http.ResponseWriter, r *http.Request) {
	p, ok := s.publishWriter(w, r, auth.ActPublish)
	if !ok {
		return
	}
	if s.Publishing.Schedule == nil {
		s.pubRedirect(w, r, "", "scheduling is not wired up in this build")
		return
	}
	draft := s.Store.GetRef(site.RefDraft)
	if draft == "" {
		s.pubRedirect(w, r, "", "there is no draft to schedule")
		return
	}
	when, err := parseWhen(strings.TrimSpace(r.FormValue("when")), time.Now())
	if err != nil {
		s.pubRedirect(w, r, "", err.Error())
		return
	}
	sch, err := s.Publishing.Schedule()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	note := strings.TrimSpace(r.FormValue("note"))
	if err := sch.Add(draft, when, p.Name, note, time.Now()); err != nil {
		s.pubRedirect(w, r, "", err.Error())
		return
	}
	if err := s.Publishing.SaveSchedule(sch); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "schedule.add", "/", map[string]string{
		"scheduled": draft, "at": when.UTC().Format(time.RFC3339), "note": note})
	s.pubRedirect(w, r, fmt.Sprintf(
		"%s will publish at %s. Every gate runs then, against the content as it "+
			"stands, not now.",
		shortHash(draft), when.UTC().Format("15:04 on 2 Jan 2006")), "")
}

func (s *Server) handleScheduleCancel(w http.ResponseWriter, r *http.Request) {
	p, ok := s.publishWriter(w, r, auth.ActPublish)
	if !ok {
		return
	}
	if s.Publishing.Schedule == nil {
		s.pubRedirect(w, r, "", "scheduling is not wired up in this build")
		return
	}
	sch, err := s.Publishing.Schedule()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	commit := r.FormValue("commit")
	if !sch.Cancel(commit) {
		s.pubRedirect(w, r, "", "nothing pending matches "+shortHash(commit))
		return
	}
	if err := s.Publishing.SaveSchedule(sch); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "schedule.cancel", "/", map[string]string{"cancelled": commit})
	s.pubRedirect(w, r, "cancelled", "")
}

// handleLockRelease takes somebody else's claim off a page.
//
// Allowed, and recorded. A lock here is advisory — it never prevented the write
// — so refusing to release it would only mean the claim outlives the person who
// made it, which is the state locks are supposed to prevent rather than cause.
func (s *Server) handleLockRelease(w http.ResponseWriter, r *http.Request) {
	p, ok := s.publishWriter(w, r, auth.ActEditDraft)
	if !ok {
		return
	}
	if s.Locks == nil || s.SaveLocks == nil {
		s.pubRedirect(w, r, "", "locks are not wired up in this build")
		return
	}
	locks, err := s.Locks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	page, holder := r.FormValue("page"), r.FormValue("holder")
	if !locks.Release(page, holder, time.Now()) {
		s.pubRedirect(w, r, "", "nobody is holding "+page)
		return
	}
	if err := s.SaveLocks(locks); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.auditPub(p, "lock.release", "/"+page,
		map[string]string{"held_by": holder})
	s.pubRedirect(w, r, "released "+page, "")
}

// parseWhen accepts a timestamp or a duration.
//
// Both, because "in 48h" is what somebody types for an embargo and an absolute
// time is what they type for a launch. Forcing one into the other is how a
// scheduled publish goes out at the wrong hour.
func parseWhen(s string, now time.Time) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		if d <= 0 {
			return time.Time{}, fmt.Errorf("%q is not in the future", s)
		}
		return now.Add(d), nil
	}
	return time.Time{}, fmt.Errorf(
		"%q is neither a time (2026-09-01T09:00:00Z) nor a duration (48h)", s)
}

func (s *Server) publishWriter(w http.ResponseWriter, r *http.Request,
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
	if s.Publishing == nil {
		s.unwired(w, r, p, "Publishing", "environments and scheduling")
		return principal{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return principal{}, false
	}
	return p, true
}

func (s *Server) auditPub(p principal, action, resource string,
	detail map[string]string) {

	if s.Audit == nil {
		return
	}
	if detail == nil {
		detail = map[string]string{}
	}
	detail["by"] = p.Name
	s.Audit(action, resource, detail)
}

func (s *Server) pubRedirect(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	u := "/publishing"
	switch {
	case errMsg != "":
		u += "?e=" + url.QueryEscape(errMsg)
	case msg != "":
		u += "?m=" + url.QueryEscape(msg)
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}
