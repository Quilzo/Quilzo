// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"sort"
	"strings"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/audit"
)

// Integrations that act with a person's connected account, ready-made: a
// calendar, issues. `quilzo integrations template NAME` declares one,
// switched off and unpinned, for a person to read, pin and turn on, as an
// imported one is. Each goes with the account the person an agent acts for
// connected (quilzo connect), at the provider it names.
//
// Few operations, on purpose: what an agent acting for somebody needs to
// read their calendar and put a meeting in it, and no more. A template is
// where an install starts, not what it may never change.

type integrationTemplate struct {
	Title       string
	Provider    string
	Scopes      string
	Integration agent.Integration
}

func bodySchema(s string) json.RawMessage { return json.RawMessage(s) }

const eventTimeSchema = `{"type":"object","properties":{"dateTime":{"type":"string","description":"RFC 3339, such as 2026-11-05T14:00:00"},"timeZone":{"type":"string","description":"an IANA zone, such as Europe/London"}},"required":["dateTime"]}`

var integrationTemplates = map[string]integrationTemplate{
	"google-calendar": {Title: "Google Calendar", Provider: "google",
		Scopes: "https://www.googleapis.com/auth/calendar.events",
		Integration: agent.Integration{Kind: agent.IntegrationHTTP, Endpoint: "www.googleapis.com", Path: "/calendar/v3",
			Purpose: "read the calendar of the person an agent acts for, and add meetings to it", Writes: true,
			Operations: []agent.Operation{
				{Name: "listEvents", Method: "GET", Path: "/calendars/{calendarId}/events",
					Description: "Events between two times, soonest first. calendarId is primary for the person's own.",
					Params: []agent.OperationParam{{Name: "calendarId", In: "path", Required: true},
						{Name: "timeMin", In: "query", Description: "RFC 3339, with an offset"},
						{Name: "timeMax", In: "query", Description: "RFC 3339, with an offset"},
						{Name: "q", In: "query", Description: "words to find"},
						{Name: "maxResults", In: "query", Type: "integer"},
						{Name: "singleEvents", In: "query", Type: "boolean"},
						{Name: "orderBy", In: "query", Description: "startTime, with singleEvents"}}},
				{Name: "createEvent", Method: "POST", Path: "/calendars/{calendarId}/events",
					Description: "Add an event. sendUpdates=all invites its attendees.",
					Params: []agent.OperationParam{{Name: "calendarId", In: "path", Required: true},
						{Name: "sendUpdates", In: "query", Description: "all, externalOnly or none"}},
					Body: bodySchema(`{"type":"object","properties":{"summary":{"type":"string"},"description":{"type":"string"},` +
						`"location":{"type":"string"},"start":` + eventTimeSchema + `,"end":` + eventTimeSchema + `,` +
						`"attendees":{"type":"array","items":{"type":"object","properties":{"email":{"type":"string"}},"required":["email"]}}},` +
						`"required":["summary","start","end"]}`)},
			}}},
	"microsoft-calendar": {Title: "Microsoft 365 calendar", Provider: "microsoft", Scopes: "Calendars.ReadWrite",
		Integration: agent.Integration{Kind: agent.IntegrationHTTP, Endpoint: "graph.microsoft.com", Path: "/v1.0",
			Purpose: "read the calendar of the person an agent acts for, and add meetings to it", Writes: true,
			Operations: []agent.Operation{
				{Name: "calendarView", Method: "GET", Path: "/me/calendarView",
					Description: "Events between two times.",
					Params: []agent.OperationParam{{Name: "startDateTime", In: "query", Required: true, Description: "ISO 8601"},
						{Name: "endDateTime", In: "query", Required: true, Description: "ISO 8601"}}},
				{Name: "createEvent", Method: "POST", Path: "/me/events",
					Description: "Add an event; its attendees are invited.",
					Body: bodySchema(`{"type":"object","properties":{"subject":{"type":"string"},` +
						`"body":{"type":"object","properties":{"contentType":{"type":"string","enum":["text","html"]},"content":{"type":"string"}}},` +
						`"start":` + eventTimeSchema + `,"end":` + eventTimeSchema + `,` +
						`"location":{"type":"object","properties":{"displayName":{"type":"string"}}},` +
						`"attendees":{"type":"array","items":{"type":"object","properties":{"emailAddress":{"type":"object",` +
						`"properties":{"address":{"type":"string"},"name":{"type":"string"}},"required":["address"]},` +
						`"type":{"type":"string","enum":["required","optional"]}}}}},"required":["subject","start","end"]}`)},
			}}},
	"github-issues": {Title: "GitHub issues", Provider: "github", Scopes: "repo (or public_repo)",
		Integration: agent.Integration{Kind: agent.IntegrationHTTP, Endpoint: "api.github.com", Path: "/",
			Purpose: "read and file issues as the person an agent acts for", Writes: true,
			Operations: []agent.Operation{
				{Name: "listIssues", Method: "GET", Path: "/repos/{owner}/{repo}/issues",
					Params: []agent.OperationParam{{Name: "owner", In: "path", Required: true}, {Name: "repo", In: "path", Required: true},
						{Name: "state", In: "query", Description: "open, closed or all"}, {Name: "labels", In: "query"}}},
				{Name: "createIssue", Method: "POST", Path: "/repos/{owner}/{repo}/issues",
					Params: []agent.OperationParam{{Name: "owner", In: "path", Required: true}, {Name: "repo", In: "path", Required: true}},
					Body: bodySchema(`{"type":"object","properties":{"title":{"type":"string"},"body":{"type":"string"},` +
						`"labels":{"type":"array","items":{"type":"string"}}},"required":["title"]}`)},
				{Name: "commentIssue", Method: "POST", Path: "/repos/{owner}/{repo}/issues/{issue_number}/comments",
					Params: []agent.OperationParam{{Name: "owner", In: "path", Required: true}, {Name: "repo", In: "path", Required: true},
						{Name: "issue_number", In: "path", Required: true, Type: "integer"}},
					Body: bodySchema(`{"type":"object","properties":{"body":{"type":"string"}},"required":["body"]}`)},
			}}},
}

func integrationTemplateNames() []string {
	out := make([]string, 0, len(integrationTemplates))
	for k := range integrationTemplates {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// integrationFromTemplate is a template as a declaration: switched off,
// using only what it is asked to, with the account at provider.
func integrationFromTemplate(tmpl, name, provider string, uses []string) (agent.Integration, error) {
	t, ok := integrationTemplates[tmpl]
	if !ok {
		return agent.Integration{}, fmt.Errorf("no template called %s; there are %s", tmpl, strings.Join(integrationTemplateNames(), ", "))
	}
	in := t.Integration
	in.Operations = append([]agent.Operation(nil), t.Integration.Operations...)
	in.Name = name
	if in.Name == "" {
		in.Name = tmpl
	}
	in.Connection = provider
	if in.Connection == "" {
		in.Connection = t.Provider
	}
	in.Enabled = false
	in.Uses = uses
	if len(in.Uses) == 0 {
		for _, o := range in.Operations {
			in.Uses = append(in.Uses, o.Name)
		}
	}
	in.Writes = false
	for _, u := range in.Uses {
		if o, ok := in.Operation(u); ok && o.Writes() {
			in.Writes = true
		}
	}
	return in, in.Validate()
}

// integrationsTemplate is quilzo integrations template [NAME [--as N]
// [--connection PROVIDER] [--uses A,B]].
func integrationsTemplate(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("integrations template", flag.ContinueOnError)
	as := fs.String("as", "", "what to call it; the template's name by default")
	provider := fs.String("connection", "", "the provider people connect their accounts at; the template's by default")
	uses := fs.String("uses", "", "the operations it may call, comma-separated; all of the template's by default")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) == 0 {
		// The templates as one document under --json. This wrote only for a
		// person, so a script asking which integrations can be declared from
		// one was answered with nothing and exit 0.
		type template struct {
			Name       string   `json:"name"`
			Title      string   `json:"title"`
			Provider   string   `json:"provider"`
			Scopes     string   `json:"scopes"`
			Operations []string `json:"operations"`
		}
		rows := make([]template, 0, len(integrationTemplates))
		for _, n := range integrationTemplateNames() {
			t := integrationTemplates[n]
			row := template{Name: n, Title: t.Title, Provider: t.Provider, Scopes: t.Scopes}
			for _, o := range t.Integration.Operations {
				row.Operations = append(row.Operations, o.Name)
			}
			rows = append(rows, row)
		}
		if w.JSON(map[string]any{"templates": rows}) {
			return nil
		}
		for _, n := range integrationTemplateNames() {
			t := integrationTemplates[n]
			var ops []string
			for _, o := range t.Integration.Operations {
				ops = append(ops, o.Name)
			}
			w.Human("%s%-20s%s %s, with the account people connect at %s (scopes %s)\n    %s%s%s\n", bold, n, reset, t.Title,
				t.Provider, t.Scopes, dim, strings.Join(ops, ", "), reset)
		}
		return nil
	}
	if len(pos) != 1 {
		return errors.New("usage: quilzo integrations template [NAME [--as N] [--connection PROVIDER] [--uses A,B]]")
	}
	var only []string
	for _, u := range strings.Split(*uses, ",") {
		if u = strings.TrimSpace(u); u != "" {
			only = append(only, u)
		}
	}
	in, err := integrationFromTemplate(pos[0], strings.TrimSpace(*as), strings.TrimSpace(*provider), only)
	if err != nil {
		return err
	}
	set, err := loadIntegrations(root)
	if err != nil {
		return err
	}
	for _, d := range set.Declared {
		if d.Name == in.Name {
			return fmt.Errorf("an integration called %s is already declared; use --as to call this one something else", in.Name)
		}
	}
	set.Declared = append(set.Declared, in)
	if err := set.Validate(); err != nil {
		return err
	}
	if err := saveJSON(integrationsPath(root), set); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	record(root, caller.auditRecord("integration.template", "/", audit.Success, map[string]string{
		"integration": in.Name, "template": pos[0], "connection": in.Connection, "uses": strings.Join(in.Uses, ",")}))
	if w.JSON(in) {
		return nil
	}
	w.Human("declared %s%s%s reaching %s with the account each person connects at %s, switched off\n",
		bold, in.Name, reset, in.Where(), in.Connection)
	w.Human("  may call %s\n", strings.Join(in.Uses, ", "))
	w.Human("\nnext: quilzo connect provider add %s --template %s ... (once), quilzo integrations pin %s, "+
		"then turn it on in Administration › Integrations\n", in.Connection, in.Connection, in.Name)
	return nil
}
