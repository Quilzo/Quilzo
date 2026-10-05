// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/quilzo/quilzo/internal/api"
	"github.com/quilzo/quilzo/internal/clientip"
	"github.com/quilzo/quilzo/internal/config"
	"github.com/quilzo/quilzo/internal/detect"
	"github.com/quilzo/quilzo/internal/estate"
	"github.com/quilzo/quilzo/internal/evals"
	"github.com/quilzo/quilzo/internal/listen"
	"github.com/quilzo/quilzo/internal/logd"
	"github.com/quilzo/quilzo/internal/remind"
	"github.com/quilzo/quilzo/internal/throttle"
	"github.com/quilzo/quilzo/internal/travel"
	"github.com/quilzo/quilzo/internal/webauthn"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/agentwatch"
	"github.com/quilzo/quilzo/internal/assist"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/codescan"
	"github.com/quilzo/quilzo/internal/collab"
	"github.com/quilzo/quilzo/internal/compliance"
	"github.com/quilzo/quilzo/internal/csp"
	"github.com/quilzo/quilzo/internal/ext"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/gate"
	"github.com/quilzo/quilzo/internal/i18n"
	"github.com/quilzo/quilzo/internal/incident"
	"github.com/quilzo/quilzo/internal/indicator"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/media"
	"github.com/quilzo/quilzo/internal/medialib"
	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/oidc"
	"github.com/quilzo/quilzo/internal/posture"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/saml"
	"github.com/quilzo/quilzo/internal/schedule"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/shield"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/taxonomy"
	"github.com/quilzo/quilzo/internal/upkeep"
	"github.com/quilzo/quilzo/internal/vuln"
	"github.com/quilzo/quilzo/internal/webhook"
)

func cmdServe(root string, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	openBrowser := fs.Bool("open", false,
		"open the interface in a browser once the server is listening")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	tplDir := fs.String("templates", "templates", "where page.html lives")
	// Declared so the posture scan can tell interception from exposure. An
	// operator who terminates TLS at a proxy should not be told they serve
	// cleartext — a rule a correct deployment cannot satisfy is a rule people
	// learn to ignore.
	behindProxy := fs.Bool("behind-proxy", false,
		"a reverse proxy terminates TLS in front of this")
	publicAddr := fs.String("public-addr", "",
		"where the public site is served, for the posture scan")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	pol, err := loadPolicy(root)
	if err != nil {
		return err
	}
	toks, err := loadTokens(root)
	if err != nil {
		return err
	}
	// The shield, for this process: the guard every request passes, the
	// engine every signal is told to, and the lockdown on every token store
	// this server loads (internal/shield).
	sh := newShieldHost(root)
	sh.where = shield.Admin
	sh.gate(toks)

	// The whole design, loaded the way the public server loads it. A preview
	// built from a different loader is a preview of a different site, which is
	// the failure internal/render exists to prevent.
	design, derr := loadDesign(*tplDir)
	if derr != nil {
		design = &Design{}
		fmt.Fprintf(os.Stderr, "  %s%s; preview and the accessibility check "+
			"are unavailable%s\n", dim, derr, reset)
	}
	for _, note := range design.Notes {
		fmt.Fprintf(os.Stderr, "  %s%s%s\n", dim, note, reset)
	}

	cfg, err := loadConfig(root)
	if err != nil {
		return err
	}
	srv, err := admin.New(s, pol, toks, design.Layouts)
	if err != nil {
		return err
	}
	// The site's stylesheet, so the framed preview is the page rather than the
	// page's markup. Read from the same directory as the template and, like
	// it, absent rather than fatal — a headless store that renders elsewhere
	// has neither, and refusing to serve the admin over a missing stylesheet
	// would be a poor trade.
	srv.SiteCSS = design.Stylesheet
	// Persistence and auditing for the changes the admin can now make.
	// Without these an access change lives until the process restarts, and the
	// administrator has already been told it worked.
	srv.SavePolicy = func(p *auth.Policy) error {
		return saveJSON(policyPath(root), p)
	}
	// Passkeys, kept beside the tokens they mint a session as. Loaded here
	// rather than lazily so that a store which cannot be read is a startup
	// failure rather than a sign-in that silently offers nobody a key.
	pk := &admin.Passkeys{}
	if err := loadJSON(passkeysPath(root), pk); err != nil {
		return err
	}
	pk.Save = func(p *admin.Passkeys) error {
		return saveJSON(passkeysPath(root), p)
	}
	// Which authenticators may enrol. Empty constrains nothing, which is the
	// default and what most deployments want.
	if cfg, cerr := loadConfig(root); cerr == nil {
		pk.Enrol.RequireIdentified = cfg.Bool("passkey.require_hardware")
		for _, raw := range splitList(cfg.Raw("passkey.authenticators")) {
			id, perr := webauthn.ParseAAGUID(raw)
			if perr != nil {
				return fmt.Errorf("passkey.authenticators: %w", perr)
			}
			pk.Enrol.Allowed = append(pk.Enrol.Allowed, id)
		}
	}
	srv.Passkeys = pk

	srv.SaveTokens = func(t *auth.TokenStore) error {
		return saveJSON(tokensPath(root), t)
	}
	srv.Audit = func(action, resource string, detail map[string]string) {
		by := detail["by"]
		record(root, audit.Record{
			Action: action, Resource: resource, Outcome: audit.Success,
			Principal: by, Kind: audit.KindHuman, Verified: true,
			Detail: detail,
		})
	}

	srv.Settings = &admin.Settings{
		Load: func() (*config.Config, error) { return loadConfig(root) },
		Save: func(c *config.Config) error { return saveConfig(root, c) },
	}
	// Content types, re-read per call for the same reason CheckTypes is: a type
	// added from the CLI while this is running must take effect immediately.
	// The agent declarations, read-only. This process owns the file; the admin
	// shows what is in it and does not write manifests, because declaring one
	// is an administrative act better done where a diff is in front of you.
	signedIn := func(by string) *Caller {
		// Signed in to the admin as an administrator: a person, verified.
		return &Caller{Name: by, Kind: audit.KindHuman, Verified: true,
			Role: auth.RoleAdmin}
	}
	srv.Inbox = inboxHooks(root)
	srv.Members = membersHooks(root)
	srv.Boards = boardsHooks(root)
	srv.SCIM = scimHooks(root)
	// Events other systems push, the moment they happen.
	inb := newInboundServer(root)
	srv.Inbound = inb
	srv.Feeds = feedsHooks(root, inb)
	inboundCtx, stopInbound := context.WithCancel(context.Background())
	defer stopInbound()
	go inb.run(inboundCtx)
	// Sign-ins are judged as they are made, and the rules act on them.
	srv.SignInRisk = signInRisk(root)
	srv.SessionPlace, srv.SessionMovedTo, srv.Reported, srv.SignInSignal = sessionHooks(root)
	srv.Automations = &admin.AutomationsAdmin{
		Engine:  automationEngineAsync(root),
		SignIns: (&travel.Store{Dir: signinsPath(root)}).Since,
		Geo: func() string {
			_, desc, err := cachedGeo(root)
			if err != nil {
				return err.Error()
			}
			return desc
		},
	}
	if m, err := loadMailConfig(root); err == nil && m != nil {
		srv.StepUpMail = func(to, code string) error {
			return m.SendPlain(to, "Your Quilzo sign-in code: "+code,
				"Somebody is signing in to Quilzo as you, and was asked to confirm it.\n\n"+
					"The code is "+code+". It works once, for ten minutes.\n\n"+
					"If this was not you, do not use it, and tell your security team.")
		}
	}
	srv.Agents = &admin.Agents{
		Load: func() (map[string]agent.Manifest, error) {
			set, err := loadAgents(root)
			if err != nil {
				return nil, err
			}
			return set.Agents, nil
		},
		Known: func() []string {
			var out []string
			for c := range knownCapabilities(root) {
				out = append(out, c)
			}
			sort.Strings(out)
			return out
		},
		Save: func(m agent.Manifest, isNew bool, by string) error {
			return declareAgent(root, m, isNew, signedIn(by))
		},
		Remove: func(name, by string) error {
			return withdrawAgent(root, name, signedIn(by))
		},
		Run: func(name, goal string, model bool, by string) (string, error) {
			return runAgentOnce(root, name, goal, model, signedIn(by))
		},
		Runs: func(name string) ([]agent.Record, error) {
			return listAgentRuns(root, name, 0)
		},
		RunGet: func(id string) (agent.Record, error) {
			return loadAgentRun(root, id)
		},
		Answer: func(id string, step int, approve bool, by string) error {
			ctx, cancel := context.WithTimeout(context.Background(), agentRunTime)
			defer cancel()
			_, err := continueAgentRun(ctx, root, id,
				&agent.Verdict{N: step, Approve: approve}, signedIn(by))
			return err
		},
		Resume: func(id, by string) error {
			ctx, cancel := context.WithTimeout(context.Background(), agentRunTime)
			defer cancel()
			_, err := continueAgentRun(ctx, root, id, nil, signedIn(by))
			return err
		},
		Replay: func(id string, step int, by string) (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), agentRunTime)
			defer cancel()
			return replayAgentRun(ctx, root, id, step, signedIn(by))
		},
	}

	srv.Types = &admin.Types{
		Load:  func() (*schema.Store, error) { return schema.Load(root) },
		Save:  func(st *schema.Store) error { return st.Save() },
		Pages: func() (map[string]any, error) { return draftPages(root) },
	}
	srv.Data = &admin.Data{
		Tree: func() (string, error) { return draftTree(s) },
		Commit: func(tree, message, author string) error {
			return commitTreeNoLock(s, tree, message, author)
		},
	}
	// Everything below is the same wiring pattern: the admin package holds no
	// knowledge of where this store keeps its files, so the host hands it
	// functions. Each one may be left nil, and each screen says "this build has
	// no access to X" rather than rendering an empty list — because empty and
	// absent look identical on a page and mean opposite things.
	srv.Publishing = &admin.Publishing{
		Envs:         func() (*site.Envs, error) { return loadEnvs(root) },
		SaveEnvs:     func(e *site.Envs) error { return saveEnvs(root, e) },
		Schedule:     func() (*schedule.Schedule, error) { return loadSchedule(root) },
		SaveSchedule: func(sc *schedule.Schedule) error { return saveJSON(schedulePath(root), sc) },
	}
	srv.Media = &admin.Media{
		Library: func() (*medialib.Library, error) { return openMedia(root) },
		Options: func() media.Options { return mediaOptionsAt(root) },
	}
	srv.Languages = &admin.Languages{
		Load: func() (*i18n.Config, error) { return loadLocales(root) },
		Save: func(c *i18n.Config) error { return saveJSON(localesPath(root), c) },
		Hashes: func() (map[string]string, error) {
			ref := site.RefDraft
			if s.GetRef(ref) == "" {
				ref = site.RefLive
			}
			return pageHashes(s, ref)
		},
	}
	srv.Integrations = &admin.Integrations{
		Declared: func() (agent.Integrations, error) {
			set, err := loadIntegrations(root)
			if err != nil {
				return agent.Integrations{}, err
			}
			return *set, nil
		},
		Webhooks: func() ([]webhook.Endpoint, []webhook.Delivery, error) {
			f, err := loadHooks(root)
			if err != nil {
				return nil, nil, err
			}
			return f.Endpoints, f.Deliveries, nil
		},
		SaveWebhooks: func(e []webhook.Endpoint) error {
			f, err := loadHooks(root)
			if err != nil {
				return err
			}
			f.Endpoints = e
			return saveJSON(hooksPath(root), f)
		},
		Extensions: func() ([]ext.Manifest, error) {
			f, err := loadExts(root)
			if err != nil {
				return nil, err
			}
			return f.Extensions, nil
		},
		SaveExtensions: func(m []ext.Manifest) error {
			return saveExts(root, &extFile{Extensions: m})
		},
		Pin:    ext.Pin,
		Events: func() ([]audit.Event, error) { return audit.Read(auditPath(root)) },
		Provider: func() (string, string, string, string, bool, bool) {
			c, err := loadOIDC(root)
			if err != nil || c == nil {
				return "", "", "", "", false, false
			}
			return c.Issuer, c.ClientID, c.RedirectURI, c.Claim,
				c.RequireVerifiedEmail, true
		},
	}
	srv.Events = &admin.Events{Open: eventsOpener(root)}
	srv.Findings = findingsCapability(root)
	srv.Workforce = &admin.Workforce{
		Load: func(now time.Time) (*estate.Estate, estate.Outcome, error) {
			return buildEstate(root, now)
		},
		History: func() ([]estate.Summary, error) { return loadHistory(root) },
		Status:  func() (admin.SyncStatus, error) { return syncStatus(root) },
		Sync: func(by string) error {
			if syncRunning(root) {
				return fmt.Errorf("the tools are being read already")
			}
			// In the background: a read paced to the tools' limits can take
			// longer than a browser waits. The lock inside estateSync is
			// what keeps two from overlapping; this check is only so the
			// button can say so.
			go func() {
				caller := &Caller{Name: by, Kind: audit.KindHuman, Verified: true}
				if _, err := estateSync(root, time.Now().UTC(), caller,
					false); err != nil {
					fmt.Fprintf(os.Stderr, "  %sestate sync: %v%s\n", dim, err,
						reset)
				}
			}()
			return nil
		},
	}
	srv.Detections = &admin.Detections{
		Load: func(now time.Time) (admin.DetectionView, error) {
			t, err := loadTuning(root, "", now)
			return admin.DetectionView{Rules: t.Rules, Stats: t.Stats,
				Proposals: t.Proposals, Suppressions: t.Suppressions,
				Hits: t.Hits}, err
		},
		Ring: func(rule string, ring detect.Ring, because, by string,
			kind audit.Kind) error {
			return setRing(root, "", rule, ring, because, by, kind)
		},
		Suppress: func(sp detect.Suppression) error {
			_, err := addSuppression(root, "", sp)
			return err
		},
		Unsuppress: func(id, by string, kind audit.Kind) error {
			return removeSuppression(root, id, by, kind)
		},
	}
	srv.Vulns = &admin.Vulns{
		Load: func(now time.Time) (admin.VulnView, error) {
			v, err := loadVulnView(root, now)
			seen := map[string]bool{}
			var assets []string
			for _, c := range v.Inventory {
				if a := c.Where.String(); !seen[a] {
					seen[a] = true
					assets = append(assets, a)
				}
			}
			sort.Strings(assets)
			return admin.VulnView{Advisories: v.Advisories,
				Tree: v.Tree, Tags: v.Tags, Assets: assets,
				Components: len(v.Inventory), Matched: v.Matched,
				Assessments: v.Assessments, History: v.History,
				AdvisoriesAt: v.AdvisoriesAt, InventoryAt: v.InventoryAt}, err
		},
		// From the screen an assessment always names something the screen
		// showed, so it is refused if the store does not know it.
		Assess: func(a vuln.Assessment) error {
			return recordAssessment(root, a, true)
		},
		Tag: func(tag vuln.AssetTag, by string) error {
			return setAssetTag(root, &Caller{Name: by, Kind: audit.KindHuman,
				Verified: true}, tag)
		},
		Untag: func(match, by string) error {
			return removeAssetTag(root, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true}, match)
		},
	}
	srv.Cases = &admin.Cases{
		List: func() ([]*incident.Incident, error) { return listIncidents(root) },
		Get: func(id string) (*incident.Incident, error) {
			return loadIncident(root, id)
		},
		Regimes: func() []string { return loadRegimes(root) },
		Playbooks: func() ([]incident.Playbook, error) {
			return loadPlaybooks(root)
		},
		Actions: func(id string) ([]admin.ActionOffer, error) {
			all, err := loadActions(root)
			if err != nil || len(all) == 0 {
				return nil, err
			}
			i, err := loadIncident(root, id)
			if err != nil {
				return nil, err
			}
			var out []admin.ActionOffer
			for _, a := range all {
				targets, terr := actionTargets(root, i, a, time.Now().UTC())
				if terr != nil {
					return nil, terr
				}
				out = append(out, admin.ActionOffer{Name: a.Name,
					Title: a.Title, Effect: a.Effect, Reverts: a.Reverts,
					Reversible: a.Reversible(), Targets: targets})
			}
			return out, nil
		},
		ActRequest: func(id, by, name, target, why string) error {
			return requestAct(root, id, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true}, name, target, why,
				time.Now().UTC())
		},
		ActApprove: func(id, by string, act int) (int, error) {
			return approveAct(root, id, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true}, act, time.Now().UTC())
		},
		ActUndo: func(id, by string, act int, why string) (int, error) {
			return undoAct(root, id, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true}, act, why,
				time.Now().UTC())
		},
		// Signed in to the admin: a person, verified.
		Declare: func(title string, grade incident.Grade, regimes,
			findings []string, by string) (string, error) {
			i, err := declareIncident(root, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true}, title, grade, regimes,
				findings, time.Now().UTC())
			if err != nil {
				return "", err
			}
			return i.ID, nil
		},
		Act: func(id, by string, a incident.Action) error {
			_, err := actOnIncident(root, id, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true}, a, time.Now().UTC())
			return err
		},
	}
	srv.People = func() map[string]string {
		aliases, err := loadAliases(root)
		if err != nil {
			return nil
		}
		out := make(map[string]string, len(aliases))
		for id, a := range aliases {
			out[id] = a.Person
		}
		return out
	}
	srv.Indicators = &admin.Indicators{
		List: func(now time.Time) ([]indicator.Indicator,
			map[string]admin.IndicatorHits, error) {
			set, err := loadIndicators(root)
			if err != nil {
				return nil, nil, err
			}
			q, err := loadQueue(root, now)
			if err != nil {
				return nil, nil, err
			}
			hits := map[string]admin.IndicatorHits{}
			for id, h := range countIntelHits(q) {
				hits[id] = admin.IndicatorHits{Findings: h.Findings,
					Real: h.Real, False: h.False, Last: h.Last}
			}
			return set.All(), hits, nil
		},
		Add: func(kind, value, source, note, until, by string) (int, int,
			bool, error) {
			now := time.Now().UTC()
			i, err := makeIndicator(kind, value, source, note, until, now)
			if err != nil {
				return 0, 0, false, err
			}
			res, err := takeIndicators(root, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true},
				[]indicator.Indicator{i}, indicator.Report{Read: 1}, now)
			return res.Hits, res.Opened, res.Known > 0, err
		},
		Remove: func(id, by string) error {
			return removeIndicator(root, &Caller{Name: by,
				Kind: audit.KindHuman, Verified: true}, id)
		},
	}
	srv.Reminders = &admin.Reminders{
		Preview: func(now time.Time) (remind.Config, []remind.Message,
			[]remind.Held, map[remind.Channel]string, error) {
			c, msgs, held, err := remindPlan(root, now)
			if err != nil {
				return c, nil, nil, nil, err
			}
			_, missing := remindSenders(root, c)
			return c, msgs, held, missing, nil
		},
		Ledger: func() ([]remind.Sent, error) { return loadLedger(root) },
		Enable: func(on bool, by string) error {
			// Signed in to the admin: a person, verified.
			return setRemindEnabled(root, on, by, audit.KindHuman)
		},
		Send: func(now time.Time, by string) (int, int, error) {
			return remindSendNow(root, now, by, audit.KindHuman)
		},
	}
	srv.Assistants = assistantsCapability(root)
	srv.Models = gatewayCapability(root)
	srv.Deciders = decidersCapability(root)
	srv.Analytics = analyticsCapability(root)
	srv.Experiments = experimentsCapability(root)
	srv.Personalise = personaliseCapability(root)
	srv.Assurance = &admin.Assurance{
		Scan: func() (int, []codescan.Finding, error) {
			inputs, err := collectInputs(root, *tplDir, site.RefDraft)
			if err != nil {
				return 0, nil, err
			}
			return len(inputs), codescan.Scan(inputs), nil
		},
		CSP: func() (string, string, csp.Sources, int, error) {
			c, err := loadConfig(root)
			if err != nil {
				return "", "", csp.Sources{}, 0, err
			}
			commit := s.GetRef(site.RefLive)
			if commit == "" {
				return "", "", csp.Sources{}, 0, fmt.Errorf(
					"nothing is published, so there is no content to derive a " +
						"policy from. One generated from an empty site would " +
						"permit nothing, which is correct and useless")
			}
			pages, err := site.PagesAt(s, commit)
			if err != nil {
				return "", "", csp.Sources{}, 0, err
			}
			pol := buildCSP(c, pages)
			name, _ := pol.Header()
			return name, pol.Build(), pol.Sources, len(pages), nil
		},
		SBOM:   func() (*compliance.SBOM, error) { return compliance.Generate(time.Now()) },
		Verify: func() (int, error) { return s.Verify() },
		Vault: func() (bool, string, []string) {
			kr, err := loadKeyring(root)
			if err != nil || kr == nil {
				return false, "", nil
			}
			return true, kr.Active, kr.IDs()
		},
		Agents: func() ([]agentwatch.Report, error) {
			events, err := audit.Read(auditPath(root))
			if err != nil {
				return nil, err
			}
			return agentwatch.Look(events, time.Now()), nil
		},
		Evidence: func() ([]admin.Evidence, error) { return evidenceRows(root) },
	}
	// Retention. A form declares how long its submissions are kept and, until
	// this, nothing removed them: the ceiling was a sentence in a policy and
	// not a thing the program did. See internal/upkeep for why this sweeps
	// here while scheduled publishing keeps its external timer.
	//
	// And the estate's schedule, which does nothing until an administrator
	// sets one with quilzo estate auto.
	jobs := []upkeep.Job{estateJob(root), collectJob(root),
		// The posture, rescanned on the same schedule, so a check that
		// starts failing is a finding in the queue rather than something
		// waiting for somebody to open the Security screen.
		postureJob(root, *tplDir, posture.ServerFacts{AdminAddr: *addr,
			PublicAddr: *publicAddr, BehindProxy: *behindProxy})}
	if job, ok := retentionJob(root); ok {
		jobs = append(jobs, job)
	}
	upkeepCtx, stopUpkeep := context.WithCancel(context.Background())
	defer stopUpkeep()
	go upkeep.Run(upkeepCtx, upkeep.Every, func(j upkeep.Job, n int, err error) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s%s: %v%s\n", dim, j.Name, err, reset)
			return
		}
		switch j.Name {
		case "retention":
			fmt.Printf("  %sretention: removed %s past the period their form "+
				"declares%s\n", dim, count(n, "submission"), reset)
		case "estate":
			fmt.Printf("  %sestate: synced %s%s\n", dim, count(n, "tool"), reset)
		}
	}, jobs...)

	// Dual authorisation. The same files and the same engine the command line
	// uses — a second implementation of an approval rule would be a second
	// answer to "may this be published".
	if fs, ferr := openSubmissions(root); ferr == nil {
		srv.Forms = &admin.Forms{
			Load:  func() (*form.Set, error) { return loadForms(root) },
			Save:  func(set *form.Set) error { return saveJSON(formsPath(root), set) },
			Store: fs,
		}
	}
	// The remarks people leave on a draft. Opened here rather than per request
	// because it is a directory, and a build that cannot open it should say so
	// once at startup rather than on whichever screen happens to ask first.
	if ns, nerr := openNotes(root); nerr == nil {
		srv.Notes = &admin.Notes{Store: ns}
	}
	// When each page was last confirmed to be right. Every is read per call
	// so changing content.review.every takes effect without a restart, the
	// same as every other setting the interface reads.
	if cs, cerr := openChecked(root); cerr == nil {
		srv.Checked = &admin.Checked{
			Store: cs,
			Every: func() time.Duration { return reviewEvery(root) },
		}
	}
	srv.Approvals = &admin.Approvals{
		Policy: func() (collab.Policy, error) { return loadApprovalPolicy(root) },
		Current: func() (*collab.Proposal, error) {
			prop, _, err := currentProposal(root, s)
			return prop, err
		},
		Save: func(prop *collab.Proposal) error {
			return saveProposal(root, s, prop)
		},
		KindOf: func(principal string) string {
			return principalKind(root, principal)
		},
		Notify: func(prop *collab.Proposal) {
			notifyProposed(root, prop)
		},
	}
	srv.Listings = &admin.Listings{
		Load: func() (*listing.Set, error) { return loadListings(root) },
		Save: func(set *listing.Set) error { return saveJSON(listingPath(root), set) },
	}
	srv.Structure = &admin.Structure{
		Vocabularies: func() (*taxonomy.Set, error) { return loadVocabularies(root) },
		SaveVocabularies: func(set *taxonomy.Set) error {
			return saveJSON(vocabPath(root), set)
		},
		Menus: func() (*menu.Set, error) { return loadMenus(root) },
		SaveMenus: func(set *menu.Set) error {
			return saveJSON(menuPath(root), set)
		},
	}
	// The design screen. The browser could apply a starter's content and not its
	// markup, which meant somebody who never opened a terminal got the fields of
	// a design they were not being served.
	srv.DesignSet = &admin.Design{
		Dir:     *tplDir,
		Tokens:  func() (map[string]string, error) { return loadThemeFile(*tplDir) },
		Save:    func(values map[string]string) error { return writeThemeFile(*tplDir, values) },
		Layouts: func() []string { return design.Layouts.Names() },
		Fonts:   func() []string { return design.Fonts.Names() },
		FontFile: func(name string) ([]byte, bool) {
			if design.Fonts == nil {
				return nil, false
			}
			return design.Fonts.File(name)
		},
		OwnStylesheet: func() bool {
			return fileExists(filepath.Join(*tplDir, "site.css"))
		},
		InstallLayout: func(name string) ([]string, error) {
			return installStarter(*tplDir, name)
		},
	}
	srv.Decentralised = &admin.Decentralised{
		Pages:      func() (map[string]any, error) { return site.PagesAt(s, site.RefLive) },
		Stylesheet: func() string { return design.Stylesheet },
		Media: func() (map[string][]byte, error) {
			lib, err := openMedia(root)
			if err != nil {
				return nil, err
			}
			all, err := lib.List()
			if err != nil {
				return nil, err
			}
			out := map[string][]byte{}
			for _, f := range all {
				_, body, gerr := lib.Get(f.ID)
				if gerr != nil {
					continue
				}
				// The same path the public server uses, so an image reference
				// in a page resolves identically on IPFS.
				out["media/"+f.ID] = body
			}
			return out, nil
		},
	}
	srv.Transfer = &admin.Transfer{
		Pages: func() (map[string]any, error) { return draftPages(root) },
		// Its own Save rather than the shared one, so what it marks is what it
		// brought in. A transfer is content this program converted out of
		// somebody else's export — a thing it knows — where an ordinary edit
		// is a person writing, which it does not. Marking through the shared
		// path would assert the first about the second.
		Save: func(p map[string]any, msg, by, base string) error {
			if err := saveDraft(root, s, p, msg, by, base); err != nil {
				return err
			}
			markGeneratedQuietly(root, s, by, "brought in by transfer import")
			return nil
		},
		SiteName: cfg.Raw("site.name"), BaseURL: cfg.Raw("site.base_url"),
	}
	srv.Assist = &admin.Assist{
		Model: func() (assist.Model, error) {
			m, err := assist.NewHTTPModel()
			if err != nil {
				// No model configured is not an error condition, it is a
				// configuration. The screen says so and offers nothing rather
				// than offering a box that cannot answer.
				return nil, nil
			}
			return m, nil
		},
		Pages: func() (map[string]any, error) { return draftPages(root) },
		Save: func(p map[string]any, msg, by, base string) error {
			return saveDraft(root, s, p, msg, by, base)
		},
		Record: func(pages []string, model, author string) error {
			return recordAssisted(root, s, pages, model, author)
		},
		// The publish gates, asked about a draft that does not exist yet.
		//
		// CommitOnto writes the objects and moves no ref, which is what a
		// content-addressed store makes cheap: the candidate is a real commit
		// the checks can be pointed at, and nothing anybody can reach points
		// at it. The alternative — teaching every check to read a map of
		// pages instead of a commit — would be a second implementation of
		// seven gates, which is the drift internal/gate exists to have
		// stopped.
		//
		// It leaves a commit nothing points at, one per proposal. That is
		// what this store does with every commit — it cannot forget, and a
		// rolled-back publication is still in it — so the cost is the tree
		// objects for the pages that changed, and the page bodies are already
		// stored under their hashes by the time the gates run.
		Gates: func(pages map[string]any) (*gate.Report, []gate.Finding, error) {
			cid, err := site.CommitOnto(s, pages,
				"a proposal, considered and not published", "assistant",
				s.GetRef(site.RefDraft))
			if err != nil {
				return nil, nil, err
			}
			return contentGates(root, s, cid).Run()
		},
	}
	// What people say about themselves. A display name and a way to reach
	// them, and deliberately nothing else — every field here is data this
	// system did not need before and now holds about a person.
	srv.Profile = &admin.Profile{
		Load: func() (map[string]admin.PersonDetails, error) { return loadProfiles(root) },
		Save: func(m map[string]admin.PersonDetails) error {
			return saveJSON(profilesPath(root), m)
		},
	}
	// The interface's own branding. Validated again here rather than trusted
	// from configuration: config validation refuses a bad value at the moment
	// it is set, and this refuses one that reached the file another way.
	brand := admin.Brand{
		Name:   cfg.Raw("admin.brand.name"),
		Colour: cfg.Raw("admin.brand.colour"),
		Mark:   cfg.Raw("admin.brand.mark"),
	}
	if err := brand.Validate(); err != nil {
		return fmt.Errorf("the configured branding is not usable: %w", err)
	}
	srv.Brand = brand

	srv.ReloadTokens = tokenReloader(root, toks)
	srv.OnBadToken = sh.badToken
	srv.OnStrongSignIn = sh.vouch
	srv.Shield = sh.off
	srv.Frozen = sh.frozen
	srv.Reports = public.ReportsHandler(sh.violation)
	srv.ShieldAdmin = &admin.ShieldAdmin{Root: root,
		OnlyAdmin:   func(name string) bool { return onlyAdministrator(root, name) },
		History:     func(days int) ([]shield.Signal, error) { return history(root, days, time.Now()) },
		Changed:     sh.guard.Refresh,
		CanLockdown: func() bool { return canSignInStrongly(root) }}

	// The audit log, read-only. This process cannot write it where the writer
	// has been separated out, so there is no edit path to withhold.
	srv.LoadAudit = func() ([]audit.Event, error) {
		return audit.Read(auditPath(root))
	}
	srv.LogSeparated = func() bool {
		ok, _ := logd.CheckOwnership(auditPath(root), os.Geteuid())
		return ok
	}()
	// Forward matching only. The HMAC cannot be reversed; this computes the
	// pseudonym for each principal the store knows and compares, so somebody
	// the policy has never heard of stays opaque — which is itself worth
	// seeing on the page.
	srv.ResolvePrincipal = func(pseudonym string) string {
		l, err := openAudit(root)
		if err != nil {
			return ""
		}
		for _, name := range pol.Principals() {
			if l.Matches(pseudonym, name) {
				return name
			}
		}
		for _, t := range toks.Snapshot() {
			if l.Matches(pseudonym, t.Principal) {
				return t.Principal
			}
		}
		return ""
	}
	srv.Throttle = throttle.New(throttlePolicy(cfg))

	// The content API, same-origin with the playground. Read-only here: this
	// is the console, and a console that can rewrite production by accident
	// is a different product. `quilzo site --api-writable` is where writes
	// are turned on deliberately.
	apiSrv := &api.Server{
		Store: s, Policy: pol, Tokens: toks,
		// The admin's own limiter and token reloader, not a second set and
		// not nothing.
		//
		// It was nothing. Every throttle call in internal/api is guarded by
		// `if s.Throttle != nil`, so under `quilzo serve` the bearer endpoint
		// had no failed-authentication limit at all — tokens could be spent
		// against it at line rate, uncounted, undelayed, and with no alert,
		// while the same guesses against the admin's own screens were refused
		// after five. `quilzo site` wired all three; this one wired none, and
		// the two are the same API.
		//
		// The *same* limiter rather than another one, because a failure is a
		// failure: an attacker who finds one door throttled should not get a
		// fresh allowance by knocking on the other.
		//
		// ReloadTokens for the same reason it is set on the admin above. With
		// it nil, a token revoked in another process kept authenticating here
		// until an admin request happened to reload the store.
		Throttle:     srv.Throttle,
		ReloadTokens: srv.ReloadTokens,
		OnBadToken:   sh.badToken,
		Shield:       func() (time.Time, bool) { return sh.off("api") },
		// The same cache the admin uses. One process, one decoded copy of a
		// collection — two would be the same memory spent twice and two
		// chances for one of them to be built wrong.
		Index:       srv.Records,
		SessionAuth: true,
		Limits: api.Limits{
			PerMinute: cfg.Int("api.rate.per_minute"),
			Burst:     cfg.Int("api.rate.burst"),
		},
		// The two limits the settings table offered and nothing read. See
		// internal/api/limits.go.
		MaxPage: cfg.Int("api.page.max"),
		MaxBody: cfg.Int("api.body.max_bytes"),
		Types:   func() (*schema.Store, error) { return schema.Load(root) },
		// Every write recorded, which it was not.
		//
		// api.Server documents OnWrite as existing "so the audit trail does
		// not have a hole shaped like the API", and it was set on exactly one
		// of the two servers that has one. This server leaves Writable false
		// deliberately — no page writes — but Records.Writable is true, so
		// POST, PUT and DELETE on /api/v1/records/… succeeded here and wrote
		// nothing to the audit log. The same call under `quilzo site --api`
		// was recorded as api.write.
		//
		// internal/admin/auditcover_test.go asserts "the content API writes
		// through OnWrite", which was true of the contract and false of this
		// wiring: that test drives the admin's HTML handlers and never this
		// server.
		OnWrite: func(principal, page, commit string) {
			record(root, audit.Record{
				Action: "api.write", Resource: "/" + page,
				Outcome: audit.Success, Principal: principal,
				Kind: audit.KindService, Verified: true,
				Detail: map[string]string{
					"commit": commit, "surface": "admin-api",
				},
			})
		},
		Records: &api.Records{
			// Writable from the admin, because the admin is where somebody
			// edits things and a console that can only read is a console
			// people stop opening.
			Writable: true,
			Tree:     func() (string, error) { return draftTree(s) },
			Commit: func(tree, message, author string) error {
				return commitTreeNoLock(s, tree, message, author)
			},
		},
	}
	// And the API reports its failures the same way, rather than reaching the
	// threshold in silence. Set after Handler() is built because the handler
	// closes over the server value, not over this field.
	apiSrv.OnAuthFailure = func(source string, failures int) {
		record(root, audit.Record{
			Action: "auth.failures", Resource: "/api",
			Outcome: audit.Denied, Principal: source, Kind: audit.KindUnknown,
			Detail: map[string]string{
				"failures": fmt.Sprintf("%d", failures),
				"surface":  "api",
			},
		})
	}
	srv.API = apiSrv.Handler()
	srv.OnAuthFailure = func(source string, failures int) {
		// ASVS 5.0 asks for a reaction above five failures an hour. An audit
		// record is the reaction: a SIEM rule can match it, and this program
		// does not send email.
		record(root, audit.Record{
			Action: "auth.failures", Resource: "/admin",
			// Unknown, not service: nobody proved who they were.
			Outcome: audit.Denied, Principal: source,
			Kind: audit.KindUnknown,
			Detail: map[string]string{
				"failures": fmt.Sprintf("%d", failures),
				"surface":  "admin",
			},
		})
	}
	// The admin does not need to know where provenance lives, so the host
	// supplies the two functions and keeps the file layout in one place.
	// The same name the site serves under, so the preview and the publish gate
	// render the page readers get rather than one with a blank site name.
	srv.SiteName = siteName(root)
	srv.LoadProvenance = func() (*provenance.Index, error) { return loadProvenance(root) }
	srv.SaveProvenance = func(i *provenance.Index) error { return saveJSON(provPath(root), i) }
	// Types are re-read per request rather than captured once. A type added
	// from the CLI while the server is running must take effect immediately,
	// for the same reason revoked tokens do: a control that needs a restart is
	// a control that is off for as long as nobody restarts.
	srv.CheckTypes = func(pages map[string]any) []schema.Failure {
		st, err := schema.Load(root)
		if err != nil {
			// Fail closed. An unreadable types file is not the same as a site
			// with no types, and treating it as one would make corrupting the
			// file a way to switch validation off.
			return []schema.Failure{{Page: "(all)", Type: "?", Problems: []schema.Problem{
				{Field: "types.json", Reason: "cannot be read: " + err.Error()}}}}
		}
		return st.Gate(pages)
	}
	// The publish-time half. Wired separately from CheckTypes so it runs at
	// publish and not on every save — see the comment on the field.
	srv.CheckReferences = func(pages map[string]any) []schema.Failure {
		st, err := schema.Load(root)
		if err != nil {
			return []schema.Failure{{Page: "(all)", Type: "?", Problems: []schema.Problem{
				{Field: "types.json", Reason: "cannot be read: " + err.Error()}}}}
		}
		return st.Unresolved(pages)
	}
	srv.TypeFor = func(page string) (schema.Type, bool) {
		st, err := schema.Load(root)
		if err != nil {
			return schema.Type{}, false
		}
		name, bound := st.Bound[page]
		if !bound {
			return schema.Type{}, false
		}
		return st.Registry.Get(name)
	}
	// The scan runs per request rather than on a timer here, because the
	// dashboard is the thing being looked at: a cached posture is a posture
	// from before whatever the person just changed.
	srv.Posture = func() posture.Report {
		state := Observe(root, *tplDir, posture.ServerFacts{
			AdminAddr: *addr, PublicAddr: *publicAddr, BehindProxy: *behindProxy,
		})
		sup, _ := loadSuppressions(root)
		return posture.Scan(state, sup)
	}
	// Locks live on disk so two server processes, or a server and the CLI, see
	// the same claims. Re-read per request rather than held in memory for the
	// same reason tokens are: a claim made in another process has to be visible
	// in this one or the courtesy is only a courtesy to whoever restarted last.
	// An identity provider, if one is configured. Discovery happens at startup
	// rather than on the first sign-in, so a misconfiguration is a failure to
	// start rather than a person who cannot log in and no information about why.
	if cfg, cerr := loadOIDC(root); cerr == nil && cfg != nil {
		secret := os.Getenv(oidcSecretEnv)
		if secret == "" {
			return fmt.Errorf(
				"%s is configured as the identity provider but %s is not set.\n"+
					"  Refusing to start rather than offering a sign-in button "+
					"that cannot work", cfg.Issuer, oidcSecretEnv)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		provider, derr := oidc.Discover(ctx, cfg.Issuer, fetch.New())
		cancel()
		if derr != nil {
			return fmt.Errorf("cannot reach the identity provider: %w", derr)
		}
		if err := provider.Warm(context.Background()); err != nil {
			return fmt.Errorf("cannot read the provider's signing keys: %w", err)
		}
		srv.OIDC = &admin.OIDC{
			Provider: provider, ClientID: cfg.ClientID, Secret: secret,
			RedirectURI: cfg.RedirectURI, Claim: cfg.Claim,
			RequireVerifiedEmail: cfg.RequireVerifiedEmail,
			Label:                cfg.providerLabel(), Tenant: cfg.Tenant,
			Domains: cfg.Domains,
		}
		if cfg.Provider == "google" {
			srv.OIDC.HostedDomains = cfg.Domains
		}
		srv.SaveTokens = func(ts *auth.TokenStore) error {
			return saveJSON(tokensPath(root), ts)
		}
		srv.OnSignIn = func(principal, tokenID string) {
			record(root, audit.Record{
				Action: "signin.oidc", Resource: "/", Outcome: audit.Success,
				// Verified, and this is the one place that word is fully
				// earned: the provider proved the identity cryptographically
				// rather than it being taken from an environment variable.
				Principal: principal, Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{
					"issuer": cfg.Issuer, "session": tokenID,
				},
			})
		}
		fmt.Fprintf(os.Stderr, "  %ssign-in via %s%s\n", dim, cfg.Issuer, reset)
	}

	// Evaluations. An evaluation can take minutes with a model choosing, so
	// the screen starts one and it runs on here; the running marker is what
	// the screen and the command line both read.
	srv.Evals = &admin.Evals{
		Cases: func(name string) ([]evals.Case, error) { return loadEvalCases(root, name) },
		Add: func(name string, c evals.Case, by string) (evals.Case, error) {
			c.By = by
			c, err := addEvalCase(root, name, c)
			if err == nil {
				record(root, signedIn(by).auditRecord("agent.case-added", "/agents/"+name, audit.Success,
					map[string]string{"agent": name, "case": c.ID, "from": c.From}))
			}
			return c, err
		},
		Remove: func(name, id, by string) error {
			if err := removeEvalCase(root, name, id); err != nil {
				return err
			}
			record(root, signedIn(by).auditRecord("agent.case-removed", "/agents/"+name, audit.Success,
				map[string]string{"agent": name, "case": id}))
			return nil
		},
		Start: func(name string, k int, model bool, by string) error {
			if _, running := evalRunning(root, name); running {
				return fmt.Errorf("%s is being evaluated already", name)
			}
			if cases, err := loadEvalCases(root, name); err != nil || len(cases) == 0 {
				return fmt.Errorf("%s has no test cases yet", name)
			}
			go func() {
				if _, err := runEvaluation(root, name, k, model, signedIn(by)); err != nil {
					fmt.Fprintf(os.Stderr, "  evaluation of %s: %v\n", name, err)
				}
			}()
			// Until the marker is written, a reload would say nothing runs.
			for i := 0; i < 20; i++ {
				if _, running := evalRunning(root, name); running {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			return nil
		},
		Running: func(name string) (time.Time, bool) { return evalRunning(root, name) },
		Reports: func(name string, limit int) ([]evals.Report, error) { return evalReports(root, name, limit) },
	}

	// SAML identity providers, read fresh on every use so one added from the
	// command line applies at once. Changes from the screen are recorded
	// here, under the person who made them.
	srv.SAML = &admin.SAMLAdmin{
		Providers: func() ([]saml.Config, error) { return loadSAML(root) },
		Fetch:     samlFetch,
		Save: func(c saml.Config) error {
			if err := saveSAML(root, c); err != nil {
				return err
			}
			record(root, audit.Record{Action: "saml.add", Resource: "/", Outcome: audit.Success,
				Principal: c.AddedBy, Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{"provider": c.Name, "entity": c.EntityID,
					"certs": fmt.Sprint(len(c.Certs)), "domains": strings.Join(c.Domains, ","),
					"required": fmt.Sprint(c.Required), "mfa": fmt.Sprint(c.RequireMFA)}})
			return nil
		},
		Remove: func(name, by string) error {
			if err := removeSAML(root, name); err != nil {
				return err
			}
			record(root, audit.Record{Action: "saml.remove", Resource: "/", Outcome: audit.Success,
				Principal: by, Kind: audit.KindHuman, Verified: true,
				Detail: map[string]string{"provider": name}})
			return nil
		},
	}
	if srv.SaveTokens == nil {
		srv.SaveTokens = func(ts *auth.TokenStore) error { return saveJSON(tokensPath(root), ts) }
	}

	// The same content gates `quilzo publish` runs, built here because this is
	// the package that can reach the media library, the type registry, the
	// claim rules and the menus. See internal/gate for what the browser used
	// to publish that the command line refuses.
	srv.ContentGates = func(ref string) (*gate.Report, []gate.Finding, error) {
		return contentGates(root, s, ref).Run()
	}

	srv.Locks = func() (*collab.Locks, error) { return loadLocks(root) }
	srv.SaveLocks = func(l *collab.Locks) error { return saveJSON(locksPath(root), l) }

	srv.Reload = func() (*auth.Policy, *auth.TokenStore, error) {
		pol, err := loadPolicy(root)
		if err != nil {
			return nil, nil, err
		}
		toks, err := loadTokens(root)
		if err != nil {
			return nil, nil, err
		}
		return pol, sh.gate(toks), nil
	}

	// Loopback by default. An editing interface that binds every interface the
	// moment someone runs it is how a development server ends up on the
	// internet, and the fix has to be a decision rather than a default.
	//
	// Who each request came from is decided once, here, for everything
	// behind: limits, placing a sign-in, the audit log (internal/clientip).
	//
	// Then the shield's guard, before anything else sees the request: a
	// blocked source is refused at the door.
	httpSrv := &http.Server{Addr: *addr,
		Handler: clientip.Middleware(proxies(root, "admin.trusted_proxy"),
			sh.guard.Wrap(shield.Admin, srv.Handler()))}

	fmt.Printf("admin on http://%s\n", *addr)
	// Both commands. A token names the role it may act up to; a binding is
	// what grants one. Naming only the token -- which this line did -- sends
	// somebody to a sign-in that works and then refuses them on every screen,
	// which reads as a broken admin rather than a missing step.
	//
	// Grant first, because then the token is issued to a principal who already
	// holds a role and there is no second step to forget. It works because
	// issuing is permitted while no token exists and the principal is already
	// in the policy, which is the bootstrap in privilege.go.
	fmt.Printf("  %ssign in: quilzo auth grant you admin%s\n", dim, reset)
	fmt.Printf("  %s         quilzo token issue you --principal you --role admin%s\n",
		dim, reset)
	if len(toks.Tokens) == 0 {
		fmt.Printf("  %sno tokens exist yet, so nobody can sign in%s\n", yellow, reset)
	}
	if *openBrowser {
		// After the address is printed and before the listener blocks. A
		// browser that arrives a moment early retries; one that never opens
		// costs nothing, because the address is on the line above.
		//
		// Not an error if it fails. Refusing to serve because a desktop could
		// not be found would break exactly the deployments that matter most —
		// a container, a machine over SSH, CI — none of which has one.
		if !admin.Open("http://" + *addr) {
			fmt.Printf("  %snothing here knows how to open a browser; the "+
				"address is above%s\n", dim, reset)
		}
	}
	// Uploads, because this is the interface a file arrives through: a
	// recording added from the media screen is a request that takes as long
	// as the connection takes, and a deadline on it would refuse the
	// operation on exactly the slow link that needs longest.
	return listen.Uploads().Serve(httpSrv)
}

// retentionJob sweeps submissions past the retention their form declares.
//
// Wired into both long-running servers. Either one alone is enough — Expire is
// idempotent and tolerates a submission another sweep has already taken — and
// running it in both is what makes the ceiling hold for an install that runs
// only the public site, or only the admin, which are both ordinary
// arrangements.
//
// It returns nothing to do rather than an error when this store has no forms,
// so a site without any is not a site printing a warning every quarter hour.
func retentionJob(root string) (upkeep.Job, bool) {
	st, err := openSubmissions(root)
	if err != nil {
		return upkeep.Job{}, false
	}
	return upkeep.Job{
		Name: "retention",
		Do: func(now time.Time) (int, error) {
			// Conversations handed to a person, which carry their own
			// period from the assistant they came through.
			gone, herr := handoffStore(root).Expire(handoffKeep(root), now)
			if herr != nil {
				return gone, herr
			}
			set, lerr := loadForms(root)
			if lerr != nil || set == nil || len(set.Forms) == 0 {
				return gone, nil
			}
			n, err := st.Expire(set, now)
			return n + gone, err
		},
	}, true
}
