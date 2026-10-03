// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/remind"
)

// Reminders is the reminder programme: what would be sent, what was, and
// the two acts that change anything — allowing it, and sending now.
type Reminders struct {
	Preview func(now time.Time) (remind.Config, []remind.Message,
		[]remind.Held, map[remind.Channel]string, error)
	Ledger func() ([]remind.Sent, error)
	Enable func(on bool, by string) error
	Send   func(now time.Time, by string) (sent, failed int, err error)
}

func (s *Server) handleReminders(w http.ResponseWriter, r *http.Request) {
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	data := map[string]any{"Nav": "workforce", "Title": "Reminders",
		"Principal": p, "Message": r.URL.Query().Get("m"),
		"Error": r.URL.Query().Get("e")}
	if s.Reminders == nil || s.Reminders.Preview == nil {
		data["Unavailable"] = "This build was started without reminders."
		s.render(w, r, "reminders.html", data)
		return
	}
	now := time.Now().UTC()
	c, msgs, held, missing, err := s.Reminders.Preview(now)
	if err != nil {
		data["Unavailable"] = err.Error()
		s.render(w, r, "reminders.html", data)
		return
	}
	sort.Slice(msgs, func(i, j int) bool {
		if msgs[i].Name != msgs[j].Name {
			return msgs[i].Name < msgs[j].Name
		}
		return msgs[i].Channel < msgs[j].Channel
	})
	type preview struct {
		remind.Message
		Lines []string
	}
	var rows []preview
	for _, m := range msgs {
		var lines []string
		for _, l := range strings.Split(m.Body, "\n") {
			if strings.HasPrefix(l, "- ") {
				lines = append(lines, strings.TrimPrefix(l, "- "))
			}
		}
		rows = append(rows, preview{Message: m, Lines: lines})
	}
	var campaigns []string
	for _, k := range remind.Campaigns() {
		if c.Campaigns[k] {
			campaigns = append(campaigns, string(k))
		}
	}
	var channels []string
	for _, ch := range c.Channels {
		channels = append(channels, string(ch))
	}
	unusable := map[string]string{}
	for ch, why := range missing {
		unusable[string(ch)] = why
	}
	data["Config"] = c
	data["Campaigns"] = strings.Join(campaigns, ", ")
	data["Channels"] = strings.Join(channels, ", ")
	data["InHours"] = c.InHours(now)
	data["Window"] = fmt.Sprintf("%02d:00–%02d:00 %s%s", c.FromHour,
		c.ToHour, c.Zone, map[bool]string{true: ", Monday to Friday"}[c.Weekdays])
	data["Rows"], data["Held"], data["Unusable"] = rows, held, unusable

	if s.Reminders.Ledger != nil {
		ledger, lerr := s.Reminders.Ledger()
		if lerr == nil {
			type sentRow struct {
				remind.Sent
				When string
			}
			var recent []sentRow
			for i := len(ledger) - 1; i >= 0 && len(recent) < 50; i-- {
				recent = append(recent, sentRow{Sent: ledger[i],
					When: ledger[i].At.Format("2 Jan 15:04")})
			}
			data["Sent"] = recent
		}
	}
	s.render(w, r, "reminders.html", data)
}

func (s *Server) handleRemindersAct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use the form", http.StatusMethodNotAllowed)
		return
	}
	p, ok := s.securityReader(w, r)
	if !ok {
		return
	}
	if s.Reminders == nil || s.Reminders.Enable == nil ||
		s.Reminders.Send == nil {
		http.Error(w, "this build cannot send reminders",
			http.StatusServiceUnavailable)
		return
	}
	back := func(msg, e string) {
		v := url.Values{}
		if msg != "" {
			v.Set("m", msg)
		}
		if e != "" {
			v.Set("e", e)
		}
		http.Redirect(w, r, "/workforce/reminders?"+v.Encode(),
			http.StatusSeeOther)
	}
	switch r.FormValue("do") {
	case "enable", "disable":
		on := r.FormValue("do") == "enable"
		if on && r.FormValue("read") != "yes" {
			back("", "Tick the box to say you have read the preview. "+
				"Enabling reminders lets them go to everybody listed.")
			return
		}
		if err := s.Reminders.Enable(on, p.Name); err != nil {
			back("", err.Error())
			return
		}
		back(map[bool]string{true: "Reminders are enabled.",
			false: "Reminders are disabled; nothing will be sent."}[on], "")
	case "send":
		if r.FormValue("confirm") != "yes" {
			back("", "Tick the box to confirm. Sending goes to every "+
				"person listed in the preview.")
			return
		}
		sent, failed, err := s.Reminders.Send(time.Now().UTC(), p.Name)
		if err != nil {
			back("", err.Error())
			return
		}
		msg := countOf(sent, "reminder", "reminders") + " sent."
		if failed > 0 {
			msg += fmt.Sprintf(" %d could not be sent; the list below says why.",
				failed)
		}
		back(msg, "")
	default:
		http.Error(w, "nothing to do", http.StatusBadRequest)
	}
}
