// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"regexp"
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
// And one whose service the client chooses: a social media aggregator,
// which holds the platforms' approved apps while the client's own app
// reviews are pending, so the first platform is reachable in week one. It
// is one REST integration with one key, at the host the administrator
// names; which aggregator is the client's decision, on cost, so none is
// written here.
//
// Few operations, on purpose: what an agent acting for somebody needs to
// read their calendar and put a meeting in it, and no more. A template is
// where an install starts, not what it may never change.

type integrationTemplate struct {
	Title       string
	Provider    string
	Scopes      string
	Integration agent.Integration
	// Fill completes a template whose service the client chooses, from
	// what the administrator names in declaring it. Nil for one whose
	// host is fixed, which refuses being pointed anywhere else rather than
	// ignoring the flags that would.
	Fill func(in *agent.Integration, c templateChoice) error
}

// templateChoice is what an administrator names for a template whose
// service the client chooses, and the site's public address its media is
// fetched from.
type templateChoice struct {
	Endpoint, Path, Fields, Secret, Auth string
	// Site is site.base_url, where the media a post names is fetched from.
	Site string
}

func (c templateChoice) named() bool {
	return c.Endpoint != "" || c.Path != "" || c.Fields != "" || c.Secret != "" || c.Auth != ""
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
	// No host, no path and no field names: they are the chosen
	// aggregator's, from its documentation, and fillAggregator refuses a
	// declaration that leaves any of the first two out.
	"social-aggregator": {Title: "A social media aggregator the client chooses",
		Integration: agent.Integration{Kind: agent.IntegrationHTTP,
			Purpose: "post to the social accounts connected at the aggregator, with pictures and videos from this site", Writes: true,
			Operations: []agent.Operation{
				{Name: "publishPost", Method: "POST",
					Description: "Post to the accounts connected at the aggregator: the text, and pictures or videos " +
						"from this site by their /media/ID addresses, which the aggregator fetches."},
			}},
		Fill: fillAggregator},
}

// aggregatorFields are the parts of a post, and their names until the
// administrator gives the aggregator's own (--fields text=post).
var aggregatorFields = []struct{ part, name string }{{"text", "text"}, {"media", "mediaUrls"}, {"platforms", "platforms"}}

// reBodyField is a field name the aggregator's body may be given.
var reBodyField = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// fillAggregator points the aggregator template at the aggregator the
// administrator named: its host, the path it takes a post at, its names
// for the parts of one, and the key it is reached with, from the vault.
//
// A media URL may only be one of this site's own /media/ID addresses,
// checked against the body's schema before anything is sent: an agent
// steered by something it read could otherwise have the client's accounts
// post a picture from anywhere, under the client's name.
func fillAggregator(in *agent.Integration, c templateChoice) error {
	if c.Endpoint == "" || c.Path == "" {
		return fmt.Errorf("%s posts through the aggregator the client chooses, and none is written here: name its "+
			"API's host with --endpoint and where it takes a post with --path, as its documentation gives them", in.Name)
	}
	site, err := url.Parse(c.Site)
	if c.Site == "" || err != nil || (site.Scheme != "https" && site.Scheme != "http") || site.Host == "" ||
		site.RawQuery != "" || site.Fragment != "" {
		return fmt.Errorf("the aggregator fetches each picture and video from this site's /media/ID, so it needs " +
			"the site's public address: quilzo config set site.base_url https://...")
	}
	names := map[string]string{}
	for _, f := range aggregatorFields {
		names[f.part] = f.name
	}
	for _, kv := range strings.Split(c.Fields, ",") {
		if kv = strings.TrimSpace(kv); kv == "" {
			continue
		}
		part, name, _ := strings.Cut(kv, "=")
		if _, ok := names[part]; !ok || !reBodyField.MatchString(name) {
			return fmt.Errorf("--fields takes text=NAME, media=NAME and platforms=NAME, each the aggregator's "+
				"name for that part of a post; %q is not one", kv)
		}
		names[part] = name
	}
	if names["text"] == names["media"] || names["text"] == names["platforms"] || names["media"] == names["platforms"] {
		return fmt.Errorf("--fields gives two parts of a post one name (text %s, media %s, platforms %s); each needs its own",
			names["text"], names["media"], names["platforms"])
	}
	in.Endpoint, in.Auth = c.Endpoint, c.Auth
	in.Secret = c.Secret
	if in.Secret == "" {
		in.Secret = in.Name + "-key"
	}
	if !reSecretName.MatchString(in.Secret) {
		return fmt.Errorf("%s authenticates with the credential %q, which cannot be kept under that name: "+
			"name it with --secret, in lower-case letters, digits, '.', '_' and '-'", in.Name, in.Secret)
	}
	// The path escaped, as the site writes it: Path is decoded, so a site at
	// /caf%C3%A9 was described as having its media at /café/media/, and
	// every address the site gives its own pictures was refused. Without
	// the user and password a base address may carry, which are no business
	// of the aggregator's or of the platforms it posts to.
	at := site.Scheme + "://" + site.Host + strings.TrimSuffix(site.EscapedPath(), "/") + "/media/"
	body, err := json.Marshal(map[string]any{"type": "object", "required": []string{names["text"]},
		"properties": map[string]any{
			names["text"]: map[string]any{"type": "string", "minLength": 1, "description": "what the post says"},
			names["media"]: map[string]any{"type": "array",
				"description": "pictures and videos on this site, each as " + at + "ID, which the aggregator fetches",
				"items":       map[string]any{"type": "string", "pattern": "^" + regexp.QuoteMeta(at) + "[0-9a-f]{64}$"}},
			names["platforms"]: map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "where to post, in the aggregator's names for the platforms"},
		}})
	if err != nil {
		return err
	}
	for i := range in.Operations {
		in.Operations[i].Path, in.Operations[i].Body = c.Path, body
	}
	return nil
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
// using only what it is asked to, with the account at provider, or, for a
// service the client chooses, where and how the administrator named.
func integrationFromTemplate(tmpl, name, provider string, uses []string, c templateChoice) (agent.Integration, error) {
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
	switch {
	case t.Fill == nil && c.named():
		return agent.Integration{}, fmt.Errorf("%s reaches %s, which is not a choice: --endpoint, --path, --fields, "+
			"--secret and --auth are for a service the client chooses (social-aggregator)", tmpl, in.Where())
	case t.Fill != nil && provider != "":
		return agent.Integration{}, fmt.Errorf("%s is reached with the one key the client holds there, from the "+
			"vault (--secret), not with each person's connected account", tmpl)
	case t.Fill != nil:
		if err := t.Fill(&in, c); err != nil {
			return agent.Integration{}, err
		}
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
// [--connection PROVIDER] [--uses A,B]], and for a service the client
// chooses, [--endpoint HOST --path PATH [--fields ...] [--secret NAME]
// [--auth header:NAME]].
func integrationsTemplate(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("integrations template", flag.ContinueOnError)
	as := fs.String("as", "", "what to call it; the template's name by default")
	provider := fs.String("connection", "", "the provider people connect their accounts at; the template's by default")
	uses := fs.String("uses", "", "the operations it may call, comma-separated; all of the template's by default")
	endpoint := fs.String("endpoint", "", "the host of the service the client chose, for social-aggregator")
	path := fs.String("path", "", "where on that host it takes a post, such as /api/post, for social-aggregator")
	fields := fs.String("fields", "", "its names for the parts of a post: text=NAME,media=NAME,platforms=NAME")
	secret := fs.String("secret", "", "the credential it authenticates with, as quilzo secret set keeps it; NAME-key by default")
	authAs := fs.String("auth", "", "how the key is sent: bearer, the default, or header:NAME")
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
			if t.Fill != nil {
				w.Human("%s%-20s%s %s, at the host you name with one key from the vault\n    %s%s; "+
					"--endpoint HOST --path PATH [--fields text=NAME,media=NAME,platforms=NAME] [--secret NAME] [--auth header:NAME]%s\n",
					bold, n, reset, t.Title, dim, strings.Join(ops, ", "), reset)
				continue
			}
			w.Human("%s%-20s%s %s, with the account people connect at %s (scopes %s)\n    %s%s%s\n", bold, n, reset, t.Title,
				t.Provider, t.Scopes, dim, strings.Join(ops, ", "), reset)
		}
		return nil
	}
	if len(pos) != 1 {
		return errors.New("usage: quilzo integrations template [NAME [--as N] [--connection PROVIDER] [--uses A,B]]\n" +
			"       quilzo integrations template social-aggregator --endpoint HOST --path PATH " +
			"[--fields text=NAME,media=NAME,platforms=NAME] [--secret NAME] [--auth header:NAME]")
	}
	var only []string
	for _, u := range strings.Split(*uses, ",") {
		if u = strings.TrimSpace(u); u != "" {
			only = append(only, u)
		}
	}
	in, err := integrationFromTemplate(pos[0], strings.TrimSpace(*as), strings.TrimSpace(*provider), only, templateChoice{
		Endpoint: strings.TrimSpace(*endpoint), Path: strings.TrimSpace(*path), Fields: *fields,
		Secret: strings.TrimSpace(*secret), Auth: strings.TrimSpace(*authAs), Site: siteBaseURL(root)})
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
		"integration": in.Name, "template": pos[0], "connection": in.Connection, "endpoint": in.Where(),
		"uses": strings.Join(in.Uses, ",")}))
	if w.JSON(in) {
		return nil
	}
	if in.Connection == "" {
		w.Human("declared %s%s%s reaching %s with the key kept as %s, switched off\n", bold, in.Name, reset, in.Where(), in.Secret)
		w.Human("  may call %s\n", strings.Join(in.Uses, ", "))
		w.Human("\nnext: quilzo secret set %s < key.txt (the key the aggregator gave the client), quilzo integrations pin %s, "+
			"then turn it on in Administration › Integrations\n", in.Secret, in.Name)
		return nil
	}
	w.Human("declared %s%s%s reaching %s with the account each person connects at %s, switched off\n",
		bold, in.Name, reset, in.Where(), in.Connection)
	w.Human("  may call %s\n", strings.Join(in.Uses, ", "))
	w.Human("\nnext: quilzo connect provider add %s --template %s ... (once), quilzo integrations pin %s, "+
		"then turn it on in Administration › Integrations\n", in.Connection, in.Connection, in.Name)
	return nil
}
