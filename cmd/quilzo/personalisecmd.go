// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/personalise"
)

// Personalisation rules from the command line and for the admin. See
// internal/personalise.

func personalisePath(root string) string { return filepath.Join(root, "personalise.json") }

func cmdPersonalise(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return personaliseList(root)
	case "add":
		return personaliseAdd(root, args[1:])
	case "enable", "disable", "remove":
		return personaliseState(root, args[0], args[1:])
	case "test":
		return personaliseTest(root, args[1:])
	}
	return fmt.Errorf("unknown personalise command %q; try list, add, enable, disable, remove or test", args[0])
}

func personaliseList(root string) error {
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	set, err := personalise.Load(personalisePath(root))
	if err != nil {
		return err
	}
	if w.JSON(set.Rules) {
		return nil
	}
	if len(set.Rules) == 0 {
		w.Human("no rules; add one with quilzo personalise add NAME --page P --variant V --when campaign=newsletter\n")
	}
	for _, r := range set.Rules {
		state := "off"
		if r.Enabled {
			state = "on"
		}
		w.Human("%s%s%s  /%s → %s  %s(%s)%s\n", bold, r.Name, reset, r.Page, r.Variant, dim, state, reset)
	}
	return nil
}

// parseCondition reads field=v1,v2, or param:NAME=v1,v2.
func parseCondition(s string) (personalise.Condition, error) {
	field, values, ok := strings.Cut(s, "=")
	if !ok {
		return personalise.Condition{}, fmt.Errorf("%q is not FIELD=VALUES", s)
	}
	c := personalise.Condition{Field: personalise.Field(field), Values: splitList(values)}
	if f, name, has := strings.Cut(field, ":"); has && f == "param" {
		c.Field, c.Name = personalise.Param, name
	}
	return c, nil
}

func changeRules(root string, caller *Caller, change, name string, edit func(*personalise.Set) error) error {
	set, err := personalise.Load(personalisePath(root))
	if err != nil {
		return err
	}
	if err := edit(set); err != nil {
		return err
	}
	if err := personalise.Save(personalisePath(root), set); err != nil {
		return err
	}
	record(root, audit.Record{Action: "personalise." + change, Resource: "/personalise/" + name,
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Verified, Detail: map[string]string{"rule": name}})
	return nil
}

// authoriseRule is publish on both pages: the rule serves one at the other's
// address. Per page, so a scoped grant covers it and a scoped deny binds.
func authoriseRule(root string, caller *Caller, r personalise.Rule) error {
	for _, p := range []string{r.Page, r.Variant} {
		if err := authorise(root, caller, auth.ActPublish, "/"+p); err != nil {
			return err
		}
	}
	return nil
}

func personaliseAdd(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	page := fs.String("page", "", "the page this applies to")
	variant := fs.String("variant", "", "the published page served there when it matches")
	tz := fs.String("timezone", "", "for day and hour conditions, like Europe/London")
	var when multi
	fs.Var(&when, "when", "a condition: campaign=, referrer=, language=, device=, weekday=, hour=9-17, param:NAME=")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo personalise add NAME --page P --variant V --when FIELD=VALUES")
	}
	r := personalise.Rule{Name: pos[0], Page: *page, Variant: *variant, Timezone: *tz}
	for _, w := range when {
		c, err := parseCondition(w)
		if err != nil {
			return err
		}
		r.When = append(r.When, c)
	}
	caller := resolveCaller(root, flagToken)
	if err := authoriseRule(root, caller, r); err != nil {
		return err
	}
	if err := changeRules(root, caller, "declare", r.Name, func(s *personalise.Set) error {
		return s.Put(r)
	}); err != nil {
		return err
	}
	w.Human("%s%s%s added, off; turn it on with quilzo personalise enable %s\n", bold, r.Name, reset, r.Name)
	return nil
}

func personaliseState(root, verb string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo personalise %s NAME", verb)
	}
	caller := resolveCaller(root, flagToken)
	return changeRules(root, caller, verb, args[0], func(s *personalise.Set) error {
		r, ok := s.Get(args[0])
		if !ok {
			return fmt.Errorf("no rule called %s", args[0])
		}
		if err := authoriseRule(root, caller, r); err != nil {
			return err
		}
		if verb == "remove" {
			s.Remove(r.Name)
			return nil
		}
		r.Enabled = verb == "enable"
		return s.Put(r)
	})
}

// personaliseTest says which rule a described visitor would get.
func personaliseTest(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	campaign := fs.String("campaign", "", "utm_source")
	referrer := fs.String("referrer", "", "the referring address")
	lang := fs.String("language", "", "Accept-Language")
	device := fs.String("device", "desktop", "phone or desktop")
	at := fs.String("at", "", "a time, as 2026-09-29T20:30:00Z (default now)")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo personalise test PAGE [--campaign X --referrer URL --language L --device phone --at TIME]")
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	set, err := personalise.Load(personalisePath(root))
	if err != nil {
		return err
	}
	req, when, err := simulated(*campaign, *referrer, *lang, *device, *at)
	if err != nil {
		return err
	}
	if r, ok := set.For(pos[0], req, when); ok {
		w.Human("%s%s%s applies: /%s is served\n", bold, r.Name, reset, r.Variant)
		return nil
	}
	w.Human("no rule applies: /%s is served as it is\n", pos[0])
	return nil
}

// simulated builds the request a described visitor would send.
func simulated(campaign, referrer, lang, device, at string) (*http.Request, time.Time, error) {
	target := "/"
	if campaign != "" {
		target += "?utm_source=" + url.QueryEscape(campaign)
	}
	req := httptest.NewRequest("GET", target, nil)
	if referrer != "" {
		req.Header.Set("Referer", referrer)
	}
	if lang != "" {
		req.Header.Set("Accept-Language", lang)
	}
	if device == "phone" {
		req.Header.Set("Sec-CH-UA-Mobile", "?1")
	} else {
		req.Header.Set("Sec-CH-UA-Mobile", "?0")
	}
	when := time.Now()
	if at != "" {
		t, err := time.Parse(time.RFC3339, at)
		if err != nil {
			return nil, when, fmt.Errorf("--at is a time like 2026-09-29T20:30:00Z")
		}
		when = t
	}
	return req, when, nil
}

func personaliseCapability(root string) *admin.Personalise {
	return &admin.Personalise{
		Load: func() (*personalise.Set, error) { return personalise.Load(personalisePath(root)) },
		Save: func(s *personalise.Set, by, change, name string) error {
			if err := personalise.Save(personalisePath(root), s); err != nil {
				return err
			}
			record(root, audit.Record{Action: "personalise." + change, Resource: "/personalise/" + name,
				Outcome: audit.Success, Principal: by, Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{"rule": name}})
			return nil
		},
		Simulate: simulated,
	}
}
