// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/geo"
	"github.com/quilzo/quilzo/internal/travel"
)

// What a risky sign-in to the admin has to do.
//
// Every sign-in is placed (internal/geo) and judged against the person's
// own recent ones (internal/travel). A sign-in that looks like somebody
// else — further from the last than a plane could go, through Tor or a
// rented server, a session copied to another device or country, an
// administrator in a country they have never signed in from, or three
// unfamiliar things at once — gets no session until its person confirms it
// with a passkey, and the security contact hears of the worst of them:
// adaptive authentication (NIST SP 800-53 IA-10), on the combinations
// Entra, Okta and Duo step up on.
//
// This was a set of automation rules somebody had to add, which meant a
// new installation stepped nobody up. It is built in and on: turning it
// off (signin.adaptive false) is a weaker setting, so it takes two
// administrators. Rules about other systems' accounts left Quilzo, with
// the rest of a security team's tools, for Vaigil.

// signinBy is who the audit log says decided, for what the policy does.
const signinBy = "signin-policy"

// signInDecision is what the policy decided about one sign-in.
type signInDecision struct {
	StepUp bool
	Tell   bool
	Why    string
}

// decideSignIn is the policy. The signals are the judgement's; the role is
// the person's, since an administrator is worth asking where a reader is
// not.
func decideSignIn(role auth.Role, j travel.Judged) signInDecision {
	var d signInDecision
	for _, sg := range j.Signals {
		switch sg.Kind {
		case "impossible-travel", "session-moved":
			d = signInDecision{StepUp: true, Tell: true, Why: sg.Detail}
		case "anonymous-network", "hosting-network":
			if !d.StepUp {
				d = signInDecision{StepUp: true, Why: sg.Detail}
			}
		case "new-country":
			if role == auth.RoleAdmin && !d.StepUp {
				d = signInDecision{StepUp: true, Why: sg.Detail}
			}
		}
	}
	if j.Risk == "high" && !d.Tell {
		why := d.Why
		if why == "" && len(j.Signals) > 0 {
			why = j.Signals[0].Detail
		}
		d = signInDecision{StepUp: true, Tell: true, Why: why}
	}
	return d
}

// adaptiveSignIn reports whether the policy is on.
func adaptiveSignIn(root string) bool {
	cfg, err := loadConfig(root)
	if err != nil || cfg == nil {
		// Unreadable settings keep the policy on: it is undone by the
		// person proving it is them, and off is the weaker of the two.
		return true
	}
	return cfg.Bool("signin.adaptive")
}

// signInRisk is the admin's sign-in check: place the address, judge it
// against the person's own history, record every signal, and step it up
// when the policy says so.
func signInRisk(root string) func(admin.SignInFacts) admin.SignInVerdict {
	store := &travel.Store{Dir: signinsPath(root)}
	return func(f admin.SignInFacts) admin.SignInVerdict {
		// Whatever cannot be read is said in the audit log and the sign-in
		// goes on: an unreadable history must not lock out the people who
		// would fix it. (A step-up that was decided and cannot be recorded
		// is the admin's to refuse.)
		trouble := func(what string, err error) {
			record(root, audit.Record{Action: "signin.check-degraded", Resource: "/", Outcome: audit.Failure,
				Principal: signinBy, Kind: audit.KindService, Verified: true,
				Detail: map[string]string{"subject": f.Principal, "what": what, "error": err.Error()}})
		}
		loc, _, err := cachedGeo(root)
		if err != nil {
			trouble("geo", err)
			loc = &geo.Locator{}
		}
		place, _ := loc.Locate(f.Addr)
		net := loc.Net(f.Addr)
		in := travel.SignIn{At: time.Now().UTC(), IP: f.Addr, Place: place, Device: travel.DeviceClass(f.Agent),
			How: f.How, ASN: net.ASN, Network: net.Org, Anon: net.Anon}
		judged, err := store.Check(f.Principal, in)
		if err != nil {
			trouble("history", err)
		}
		if f.Verifying || len(judged.Signals) == 0 {
			return admin.SignInVerdict{}
		}
		return judgeSignIn(root, f, in, judged)
	}
}

// judgeSignIn records one judged sign-in's signals and applies the policy.
func judgeSignIn(root string, f admin.SignInFacts, in travel.SignIn, judged travel.Judged) admin.SignInVerdict {
	for _, sg := range judged.Signals {
		detail := map[string]string{"subject": f.Principal, "signal": sg.Kind, "detail": sg.Detail,
			"risk": judged.Risk, "score": strconv.FormatFloat(judged.Score, 'f', 1, 64), "how": f.How,
			"role": string(f.Role), "country": in.Place.Country, "device": in.Device}
		if sg.Kind == "impossible-travel" {
			detail["from"], detail["to"] = sg.From.String(), sg.To.String()
			detail["km"], detail["kmh"] = strconv.Itoa(int(sg.Km)), strconv.Itoa(int(sg.KmH))
		}
		if in.ASN != 0 {
			detail["asn"] = strconv.FormatUint(uint64(in.ASN), 10)
		}
		record(root, audit.Record{Action: "signin.signal", Resource: "/", Outcome: audit.Success,
			Principal: signinBy, Kind: audit.KindService, Verified: true, Detail: detail})
	}
	if !adaptiveSignIn(root) {
		return admin.SignInVerdict{}
	}
	d := decideSignIn(f.Role, judged)
	if d.Tell {
		tellAboutSignIn(root, f.Principal, d.Why)
	}
	if !d.StepUp {
		return admin.SignInVerdict{}
	}
	return admin.SignInVerdict{StepUp: true, Reason: d.Why}
}

// tellAboutSignIn mails the security contact in the background, so no
// sign-in waits on a mail server, and records whether it reached them.
func tellAboutSignIn(root, principal, why string) {
	inBackground(func() {
		did, err := tellSecurity(root, principal+": "+why+". The session must confirm it is them before it can do anything.")
		detail := map[string]string{"subject": principal, "did": did}
		outcome := audit.Success
		if err != nil {
			detail["error"], outcome = err.Error(), audit.Failure
		}
		record(root, audit.Record{Action: "signin.told", Resource: "/", Outcome: outcome,
			Principal: signinBy, Kind: audit.KindService, Verified: true, Detail: detail})
	})
}

// sessionHooks are the admin's other ways into the policy: where a request
// is from, a session seen elsewhere, a person reporting a sign-in that was
// not them, and one more signal about a sign-in.
func sessionHooks(root string) (func(addr, agent string) admin.SessionContext,
	func(admin.SessionMove) admin.SignInVerdict, func(principal, session string),
	func(principal, kind, detail string)) {

	place := func(addr, agent string) admin.SessionContext {
		c := admin.SessionContext{Device: travel.DeviceClass(agent)}
		if loc, _, err := cachedGeo(root); err == nil {
			if p, ok := loc.Locate(addr); ok {
				c.Country = p.Country
			}
		}
		return c
	}
	// A session copied by malware and used elsewhere: the way past every
	// sign-in check, and the one stolen sessions leave a trace of.
	moved := func(m admin.SessionMove) admin.SignInVerdict {
		detail := fmt.Sprintf("a session issued to %s in %s is now used from %s in %s",
			firstNonEmptyStr(m.From.Device, "a device"), firstNonEmptyStr(m.From.Country, "an unknown country"),
			firstNonEmptyStr(m.To.Device, "a device"), firstNonEmptyStr(m.To.Country, "an unknown country"))
		if !adaptiveSignIn(root) {
			return admin.SignInVerdict{}
		}
		tellAboutSignIn(root, m.Principal, detail)
		return admin.SignInVerdict{StepUp: true, Reason: detail}
	}
	// The person themselves is the best detector there is: a sign-in they
	// say was not them ends every session they hold, and the security
	// contact is told.
	reported := func(principal, session string) {
		ended, err := endSessionsOf(root, principal)
		detail := map[string]string{"subject": principal, "session": session, "ended": strconv.Itoa(ended)}
		outcome := audit.Success
		if err != nil {
			detail["error"], outcome = err.Error(), audit.Failure
		}
		record(root, audit.Record{Action: "signin.reported-ended", Resource: "/", Outcome: outcome,
			Principal: signinBy, Kind: audit.KindService, Verified: true, Detail: detail})
		tellAboutSignIn(root, principal, "they said a sign-in was not them, so every session they held was ended")
	}
	// Somebody guessing codes, or an account tried from places it is not
	// used from: the person is not locked out, and the security contact
	// hears of it.
	signal := func(principal, kind, detail string) {
		record(root, audit.Record{Action: "signin.signal", Resource: "/", Outcome: audit.Success,
			Principal: signinBy, Kind: audit.KindService, Verified: true,
			Detail: map[string]string{"subject": principal, "signal": kind, "detail": detail, "risk": travel.Severity(kind)}})
		if kind == "verification-failing" || kind == "account-locked" {
			tellAboutSignIn(root, principal, detail)
		}
	}
	return place, moved, reported, signal
}

// endSessionsOf revokes every session and token a person holds here.
func endSessionsOf(root, principal string) (int, error) {
	ts, err := loadTokens(root)
	if err != nil {
		return 0, err
	}
	ended := 0
	for _, t := range ts.Snapshot() {
		if strings.EqualFold(t.Principal, principal) && !t.Revoked {
			if _, err := ts.Revoke(t.ID); err == nil {
				ended++
			}
		}
	}
	if ended == 0 {
		return 0, nil
	}
	return ended, saveTokens(root, ts)
}

func firstNonEmptyStr(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
