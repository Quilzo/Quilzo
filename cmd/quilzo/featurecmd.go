// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/form"
	"github.com/quilzo/quilzo/internal/listing"
	"github.com/quilzo/quilzo/internal/menu"
	"github.com/quilzo/quilzo/internal/out"
	"github.com/quilzo/quilzo/internal/schema"
	"github.com/quilzo/quilzo/internal/webhook"
)

// Features: a set of Quilzo's own blocks declared in one package, installed
// as one decision and taken back as one (see internal/feature).
//
// On disk, under features/:
//
//	installed/NAME.json        what is installed, what it owns, its history
//	packages/NAME/DIGEST.json  every version installed or asked for, exactly
//	pending/ID.json            an install waiting for a second person
//
// Installing never publishes. Pages go to the draft, and a feature that
// would take a block somebody else made is refused rather than merged.

const featureContext = "quilzo/feature-package/v1"

func featuresDir(root string) string { return filepath.Join(root, "features") }

func featureInstalledPath(root, name string) string {
	return filepath.Join(featuresDir(root), "installed", name+".json")
}

func featurePackagePath(root, name, digest string) string {
	return filepath.Join(featuresDir(root), "packages", name, digest+".json")
}

func featurePendingPath(root, id string) string {
	return filepath.Join(featuresDir(root), "pending", id+".json")
}

func cmdFeature(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	rest := args[1:]
	switch args[0] {
	case "example":
		_, err := os.Stdout.Write(feature.Example())
		return err
	case "check":
		return featureCheck(root, rest)
	case "install":
		return featureInstall(root, rest)
	case "approve":
		return featureDecide(root, rest, true)
	case "decline":
		return featureDecide(root, rest, false)
	case "pending":
		return featurePendingList(root)
	case "list":
		return featureList(root)
	case "show":
		return featureShow(root, rest)
	case "remove":
		return featureRemove(root, rest)
	case "rollback":
		return featureRollback(root, rest)
	case "export":
		return featureExport(root, rest)
	case "capture":
		return featureCapture(root, rest)
	case "draft":
		return featureDraftCmd(root, rest)
	case "from":
		return featureFromCmd(root, rest)
	default:
		return fmt.Errorf("unknown feature command %q; try example, draft, from, check, install, approve, decline, "+
			"pending, list, show, remove, rollback, export or capture", args[0])
	}
}

// featureChecks are the validations that need this installation.
func featureChecks(root string) feature.Checks {
	caps, kinds := knownCapabilities(root), customKinds(root)
	return feature.Checks{
		Agent: func(m agent.Manifest) error { return m.ValidateWith(caps, kinds) },
		URL: func(u string) error {
			_, err := fetch.ValidateURL(u)
			return err
		},
		EventType: webhook.KnownType,
	}
}

// readFeature reads and validates a package file, and checks its signature
// against published keys when keys are given.
func readFeature(root, path, keys string) (*feature.Package, []byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return readFeatureBytes(root, body, keys)
}

func readFeatureBytes(root string, body []byte, keys string) (*feature.Package, []byte, error) {
	p, err := feature.Decode(bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	if err := p.Validate(featureChecks(root)); err != nil {
		return nil, nil, err
	}
	if keys != "" {
		if err := verifyFeature(p, keys); err != nil {
			return nil, nil, err
		}
	} else if p.Signature != nil {
		return nil, nil, fmt.Errorf("this package is signed; give the publisher's keys with --keys head.pub.json " +
			"so the signature is checked rather than ignored")
	}
	return p, body, nil
}

func verifyFeature(p *feature.Package, keysPath string) error {
	if p.Signature == nil {
		return errors.New("--keys was given and the package is not signed")
	}
	var k publishedKeys
	body, err := os.ReadFile(keysPath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, &k); err != nil {
		return fmt.Errorf("%s is not a published key file: %w", keysPath, err)
	}
	ed, err1 := base64.StdEncoding.DecodeString(k.Ed25519)
	ml, err2 := base64.StdEncoding.DecodeString(k.MLDSA)
	if err1 != nil || err2 != nil {
		return errors.New("the published keys are not base64")
	}
	v, err := audit.NewHeadVerifier(ed, ml)
	if err != nil {
		return err
	}
	digest, err := p.Digest()
	if err != nil {
		return err
	}
	s := p.Signature
	if err := v.VerifyStatement(featureContext, []byte(digest), audit.Statement{
		KeyID: s.KeyID, Ed25519: s.Ed25519, MLDSA: s.MLDSA, Algorithms: s.Algorithms}); err != nil {
		return fmt.Errorf("the package's signature does not check out: %w", err)
	}
	return nil
}

// featureState reads every existing block's definition and owner.
func featureState(root string) (feature.State, map[string]*feature.Installed, error) {
	st := feature.State{Current: map[feature.Ref]json.RawMessage{}, Owner: map[feature.Ref]string{}}
	put := func(kind, name string, v any) {
		if b, err := json.Marshal(v); err == nil {
			st.Current[feature.Ref{Kind: kind, Name: name}] = b
		}
	}
	types, err := schema.Load(root)
	if err != nil {
		return st, nil, err
	}
	for name, t := range types.Registry.Types {
		put("type", name, t)
	}
	for name, t := range types.Collections {
		put("collection", name, feature.Collection{Name: name, Type: t})
	}
	listings, err := loadListings(root)
	if err != nil {
		return st, nil, err
	}
	for _, l := range listings.Listings {
		put("listing", l.Name, l)
	}
	forms, err := loadForms(root)
	if err != nil {
		return st, nil, err
	}
	for _, f := range forms.Forms {
		put("form", f.Name, f)
	}
	pages, err := draftPages(root)
	if err != nil {
		return st, nil, err
	}
	for name, body := range pages {
		put("page", name, body)
	}
	menus, err := loadMenus(root)
	if err != nil {
		return st, nil, err
	}
	for _, m := range menus.Menus {
		put("menu", m.Name, m)
	}
	bots, err := assistant.Load(assistantsPath(root))
	if err != nil {
		return st, nil, err
	}
	for _, a := range bots.Assistants {
		put("chatbot", a.Name, a)
	}
	agents, err := loadAgents(root)
	if err != nil {
		return st, nil, err
	}
	for name, m := range agents.Agents {
		put("agent", name, m)
	}
	hooks, err := loadHooks(root)
	if err != nil {
		return st, nil, err
	}
	for _, e := range hooks.Endpoints {
		put("webhook", e.URL, feature.Webhook{URL: e.URL, Types: e.Types, Note: e.Note})
	}
	installed, err := loadInstalledFeatures(root)
	if err != nil {
		return st, nil, err
	}
	for name, in := range installed {
		for _, r := range in.Owns {
			st.Owner[r] = name
		}
	}
	// A role lives in the package that declared it, so what it is now is
	// read from the version installed.
	for _, in := range installed {
		if !ownsKind(in, "role") {
			continue
		}
		p, _, err := loadFeaturePackage(root, in.Name, in.Digest)
		if err != nil {
			return st, nil, fmt.Errorf("the roles of %s cannot be read: %w", in.Name, err)
		}
		for _, r := range p.Roles {
			put("role", p.FullName(r), r)
		}
	}
	return st, installed, nil
}

func ownsKind(in *feature.Installed, kind string) bool {
	for _, r := range in.Owns {
		if r.Kind == kind {
			return true
		}
	}
	return false
}

func loadInstalledFeatures(root string) (map[string]*feature.Installed, error) {
	out := map[string]*feature.Installed{}
	dir := filepath.Join(featuresDir(root), "installed")
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var in feature.Installed
		if err := loadJSON(filepath.Join(dir, e.Name()), &in); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out[in.Name] = &in
	}
	return out, nil
}

// featureCheck is `quilzo feature check FILE [--keys F]`: the card and the
// plan, changing nothing.
func featureCheck(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("feature check", flag.ContinueOnError)
	keys := fs.String("keys", "", "the publisher's head.pub.json, to check a signed package")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: quilzo feature check FILE [--keys head.pub.json]")
	}
	p, _, err := readFeature(root, pos[0], *keys)
	if err != nil {
		return err
	}
	st, installed, err := featureState(root)
	if err != nil {
		return err
	}
	var owned []feature.Ref
	if in := installed[p.Name]; in != nil {
		owned = in.Owns
	}
	card, plan := p.MakeCard(), p.MakePlan(st, owned)
	if w.JSON(map[string]any{"card": card, "plan": plan}) {
		return nil
	}
	printFeatureCard(card)
	printFeaturePlan(plan)
	return nil
}

func printFeatureCard(c feature.Card) {
	w.Human("%s%s%s %s  %s\n", bold, c.Title, reset, c.Version, dim+c.Name+reset)
	w.Human("  %s\n", c.Purpose)
	if c.MadeBy != "" {
		w.Human("  %smade by %s%s\n", dim, c.MadeBy, reset)
	}
	section := func(title string, lines []feature.Line) {
		if len(lines) == 0 {
			return
		}
		w.Human("\n  %s%s%s\n", bold, title, reset)
		for _, l := range lines {
			mark := " "
			if l.Flag != "" && l.Flag != "public" {
				mark = yellow + "!" + reset
			}
			w.Human("  %s %s\n", mark, l.Text)
		}
	}
	section("Stores", c.Stores)
	section("Collects", c.Collects)
	section("Shows", c.Shows)
	section("Sends", c.Sends)
	section("Agents", c.Agents)
	section("Chatbots", c.Chatbots)
	section("Roles for the people who work in it", c.Roles)
	if len(c.Roles) > 0 {
		w.Human("    %snobody holds a role until somebody who grants access gives it to them%s\n", dim, reset)
	}
	who := "one person approves it"
	if c.Approvers == 2 {
		who = "two different people approve it"
	}
	w.Human("\n  risk %s%s%s: %s\n", bold, c.Risk, reset, who)
	for _, b := range c.Because {
		w.Human("    because %s\n", b)
	}
}

func printFeaturePlan(p feature.Plan) {
	w.Human("\n  %sWould change%s\n", bold, reset)
	for _, s := range p.Steps {
		w.Human("    %-7s %s\n", s.Action, s.Ref)
	}
	for _, c := range p.Conflicts {
		w.Human("  %s✗ %s%s\n", red, c, reset)
	}
	if len(p.Conflicts) > 0 {
		w.Human("  %sa feature only changes what it made; rename the block in the package, or remove the existing one%s\n",
			dim, reset)
	}
}

// featureInstall is `quilzo feature install FILE [--keys F]`.
func featureInstall(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("feature install", flag.ContinueOnError)
	keys := fs.String("keys", "", "the publisher's head.pub.json, to check a signed package")
	rowsPath := fs.String("rows", "", "records to import into one of its collections, as quilzo feature from writes them")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: quilzo feature install FILE [--keys head.pub.json] [--rows ROWS.json]")
	}
	return installFeatureFile(root, pos[0], *keys, *rowsPath, resolveCaller(root, flagToken))
}

// readRows reads a rows file: {"collection": NAME, "records": [...]}.
func readRows(path string) (*feature.Rows, error) {
	if path == "" {
		return nil, nil
	}
	b, err := readBounded(path, 64<<20)
	if err != nil {
		return nil, err
	}
	var r feature.Rows
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%s is not a rows file: %w", path, err)
	}
	if len(r.Records) == 0 {
		return nil, fmt.Errorf("%s holds no records", path)
	}
	if len(r.Records) > feature.MaxRows {
		return nil, fmt.Errorf("%s holds %d records; at most %d", path, len(r.Records), feature.MaxRows)
	}
	return &r, nil
}

// installFeatureFile installs a package file for a person.
func installFeatureFile(root, path, keys, rowsPath string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActInstall, "/"); err != nil {
		return fmt.Errorf("features are installed and changed by whoever may install them: %w", err)
	}
	if caller.Kind == audit.KindAI {
		return errors.New("a feature is installed by a person. A model may draft a package; it may not install one")
	}
	p, body, err := readFeature(root, path, keys)
	if err != nil {
		return err
	}
	rows, err := readRows(rowsPath)
	if err != nil {
		return err
	}
	o, err := requestFeature(root, p, body, caller, false, rows)
	return printOutcome(p, o, err, caller)
}

// featureOutcome is what asking for an install led to.
type featureOutcome struct {
	// Waiting is the request a second person decides, when there is one.
	Waiting *feature.Pending
	Card    feature.Card
	Plan    feature.Plan
	// Secrets are new webhooks' signing secrets, to show once to the
	// person who installed it and nowhere else.
	Secrets []string
	// Imported is how many records came in with it.
	Imported int
}

// requestFeature installs at once when one approval is enough, and otherwise
// leaves the request for a second person. It prints nothing: the screen
// calls it too, and a secret printed here would land in the server's log.
func requestFeature(root string, p *feature.Package, body []byte, caller *Caller, rollback bool, rows *feature.Rows) (featureOutcome, error) {
	var out featureOutcome
	if err := featureNeeds(root, caller, p); err != nil {
		return out, err
	}
	if rows != nil {
		if err := p.CheckRows(rows.Collection, rows.Records); err != nil {
			return out, err
		}
	}
	st, installed, err := featureState(root)
	if err != nil {
		return out, err
	}
	var owned []feature.Ref
	if in := installed[p.Name]; in != nil {
		owned = in.Owns
	}
	out.Plan = p.MakePlan(st, owned)
	out.Card = p.MakeCard()
	if len(out.Plan.Conflicts) > 0 {
		return out, fmt.Errorf("%s was not installed: %s", p.Name, strings.Join(out.Plan.Conflicts, "; "))
	}
	digest, err := p.Digest()
	if err != nil {
		return out, err
	}
	if err := keepFeaturePackage(root, p.Name, digest, body); err != nil {
		return out, err
	}
	if out.Card.Approvers < 2 {
		out.Secrets, err = applyFeature(root, p, digest, out.Plan, caller, []string{caller.Name})
		if err == nil && rows != nil {
			out.Imported, err = putCheckedRecords(root, rows.Collection, rows.Records, caller)
		}
		return out, err
	}
	id := make([]byte, 6)
	if _, err := rand.Read(id); err != nil {
		return out, err
	}
	pend := feature.Pending{ID: hex.EncodeToString(id), Name: p.Name, Version: p.Version, Digest: digest,
		RequestedBy: caller.Name, At: time.Now().UTC(), Card: out.Card, Plan: out.Plan, Rollback: rollback}
	if err := os.MkdirAll(filepath.Dir(featurePendingPath(root, pend.ID)), 0o700); err != nil {
		return out, err
	}
	if rows != nil {
		pend.Rows, pend.RowsCollection = len(rows.Records), rows.Collection
		if err := saveJSON(featurePendingPath(root, pend.ID)+".rows", rows); err != nil {
			return out, err
		}
	}
	if err := saveJSON(featurePendingPath(root, pend.ID), pend); err != nil {
		return out, err
	}
	record(root, caller.auditRecord("feature.requested", "/", audit.Success, map[string]string{
		"feature": out.Card.Name, "version": p.Version, "digest": digest[:16], "risk": out.Card.Risk, "request": pend.ID}))
	out.Waiting = &pend
	return out, nil
}

// printOutcome is the command line's account of an install request.
func printOutcome(p *feature.Package, o featureOutcome, err error, caller *Caller) error {
	if err != nil {
		if len(o.Plan.Conflicts) > 0 {
			printFeaturePlan(o.Plan)
		}
		return err
	}
	if o.Waiting != nil {
		if w.JSON(o.Waiting) {
			return nil
		}
		printFeatureCard(o.Card)
		w.Human("\n%s needs a second person: quilzo feature approve %s, by somebody other than %s\n",
			p.Name, o.Waiting.ID, caller.Name)
		return nil
	}
	w.Human("installed %s %s; its pages are in the draft, and publishing them is the usual review\n", p.Name, p.Version)
	if o.Imported > 0 {
		w.Human("imported %d record(s)\n", o.Imported)
	}
	for _, sec := range o.Secrets {
		w.Human("webhook secret, shown once: %s\n", sec)
	}
	return nil
}

func keepFeaturePackage(root, name, digest string, body []byte) error {
	path := featurePackagePath(root, name, digest)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, body, 0o600)
}

func loadFeaturePackage(root, name, digest string) (*feature.Package, []byte, error) {
	body, err := os.ReadFile(featurePackagePath(root, name, digest))
	if err != nil {
		return nil, nil, err
	}
	p, err := feature.Decode(bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	if got, err := p.Digest(); err != nil || got != digest {
		return nil, nil, fmt.Errorf("the stored copy of %s %s no longer has the digest it was kept under", name, digest[:12])
	}
	return p, body, nil
}

// featureDecide is `quilzo feature approve|decline ID`.
func featureDecide(root string, args []string, approve bool) error {
	verb := "approve"
	if !approve {
		verb = "decline"
	}
	if len(args) != 1 {
		return fmt.Errorf("usage: quilzo feature %s ID", verb)
	}
	return decideFeature(root, args[0], approve, resolveCaller(root, flagToken))
}

// decideFeature approves or declines a waiting install.
func decideFeature(root, id string, approve bool, caller *Caller) error {
	if err := authorise(root, caller, auth.ActInstall, "/"); err != nil {
		return fmt.Errorf("features are installed and changed by whoever may install them: %w", err)
	}
	verb := "approve"
	if !approve {
		verb = "decline"
	}
	if caller.Kind == audit.KindAI {
		return fmt.Errorf("a feature is %sd by a person", verb)
	}
	if !reFeatureID.MatchString(id) {
		return fmt.Errorf("%q is not a request id", id)
	}
	var pend feature.Pending
	body, err := os.ReadFile(featurePendingPath(root, id))
	if err != nil {
		return fmt.Errorf("no request %s is waiting", id)
	}
	if err := json.Unmarshal(body, &pend); err != nil {
		return err
	}
	if time.Since(pend.At) > feature.PendingTTL {
		_ = os.Remove(featurePendingPath(root, id))
		return fmt.Errorf("request %s lapsed after %s; ask again", id, feature.PendingTTL)
	}
	if !approve {
		if err := os.Remove(featurePendingPath(root, id)); err != nil {
			return err
		}
		_ = os.Remove(featurePendingPath(root, id) + ".rows")
		record(root, caller.auditRecord("feature.declined", "/", audit.Success, map[string]string{
			"feature": pend.Name, "version": pend.Version, "request": id, "by": caller.Name}))
		w.Human("declined %s %s\n", pend.Name, pend.Version)
		return nil
	}
	if strings.EqualFold(caller.Name, pend.RequestedBy) {
		return fmt.Errorf("%s asked for this install, so somebody else approves it", pend.RequestedBy)
	}
	p, _, err := loadFeaturePackage(root, pend.Name, pend.Digest)
	if err != nil {
		return err
	}
	// Checked again now: what is installed may have moved since the
	// request, and the approval is for what happens now.
	if err := p.Validate(featureChecks(root)); err != nil {
		return err
	}
	st, installed, err := featureState(root)
	if err != nil {
		return err
	}
	var owned []feature.Ref
	if in := installed[p.Name]; in != nil {
		owned = in.Owns
	}
	plan := p.MakePlan(st, owned)
	if len(plan.Conflicts) > 0 {
		return fmt.Errorf("%s can no longer be installed: %s", p.Name, strings.Join(plan.Conflicts, "; "))
	}
	secrets, err := applyFeature(root, p, pend.Digest, plan, caller, []string{pend.RequestedBy, caller.Name})
	if err != nil {
		return err
	}
	for _, sec := range secrets {
		w.Human("webhook secret, shown once: %s\n", sec)
	}
	_ = os.Remove(featurePendingPath(root, id))
	if pend.Rows > 0 {
		var rows feature.Rows
		if err := loadJSON(featurePendingPath(root, id)+".rows", &rows); err != nil {
			return fmt.Errorf("%s is installed, and its records could not be read: %w", p.Name, err)
		}
		n, err := putCheckedRecords(root, rows.Collection, rows.Records, caller)
		if err != nil {
			return fmt.Errorf("%s is installed, and its records were not imported: %w", p.Name, err)
		}
		_ = os.Remove(featurePendingPath(root, id) + ".rows")
		w.Human("imported %d record(s) into %s\n", n, rows.Collection)
	}
	w.Human("installed %s %s, asked for by %s and approved by %s; its pages are in the draft\n",
		p.Name, p.Version, pend.RequestedBy, caller.Name)
	return nil
}

var reFeatureID = regexp.MustCompile(`^[0-9a-f]{12}$`)

// applyFeature performs a plan. Everything is checked before anything is
// written; the writes then go in dependency order, removals last.
// featureNeeds is what a package asks of whoever installs it beyond
// installing features: a package that declares agents is managing them, and
// one that sends to another system is an administrator's, as declaring
// either on its own would be.
func featureNeeds(root string, caller *Caller, p *feature.Package) error {
	if held, err := heldRolesChanged(root, p); err != nil {
		return err
	} else if len(held) > 0 {
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return fmt.Errorf("%s changes what people holding %s may do, which is granting access: %w",
				p.Name, strings.Join(held, ", "), err)
		}
	}
	for _, m := range p.Agents {
		if err := manageAgent(root, caller, m.Name); err != nil {
			return fmt.Errorf("%s declares the agent %s, and that takes managing it: %w", p.Name, m.Name, err)
		}
	}
	if len(p.Webhooks) > 0 {
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return fmt.Errorf("%s sends to other systems, which is an administrator's decision: %w", p.Name, err)
		}
	}
	return nil
}

func applyFeature(root string, p *feature.Package, digest string, plan feature.Plan, caller *Caller, by []string) ([]string, error) {
	if err := featureNeeds(root, caller, p); err != nil {
		return nil, err
	}
	act := map[feature.Ref]string{}
	for _, s := range plan.Steps {
		act[s.Ref] = s.Action
	}
	installed, err := loadInstalledFeatures(root)
	if err != nil {
		return nil, err
	}
	prev := installed[p.Name]
	removing := func(kind string) []string {
		var out []string
		for _, s := range plan.Steps {
			if s.Action == feature.Remove && s.Ref.Kind == kind {
				out = append(out, s.Ref.Name)
			}
		}
		return out
	}
	changes := func(kind, name string) bool {
		a := act[feature.Ref{Kind: kind, Name: name}]
		return a == feature.Add || a == feature.Change
	}

	// Types and collections.
	types, err := schema.Load(root)
	if err != nil {
		return nil, err
	}
	for _, t := range p.Types {
		if changes("type", t.Name) {
			if err := types.Registry.Add(t); err != nil {
				return nil, err
			}
		}
	}
	for _, c := range p.Collections {
		if changes("collection", c.Name) {
			if err := types.BindCollection(c.Name, c.Type); err != nil {
				return nil, err
			}
		}
	}
	for _, name := range removing("collection") {
		types.UnbindCollection(name)
	}
	for _, name := range removing("type") {
		if users := typeUsers(types, name); len(users) > 0 {
			return nil, fmt.Errorf("type %s is still used by %s, which this feature did not make", name, strings.Join(users, ", "))
		}
		delete(types.Registry.Types, name)
	}

	// Listings and forms.
	listings, err := loadListings(root)
	if err != nil {
		return nil, err
	}
	for _, l := range p.Listings {
		if changes("listing", l.Name) {
			_ = listings.Remove(l.Name)
			if err := listings.Add(l); err != nil {
				return nil, err
			}
		}
	}
	for _, name := range removing("listing") {
		_ = listings.Remove(name)
	}
	forms, err := loadForms(root)
	if err != nil {
		return nil, err
	}
	for _, f := range p.Forms {
		if changes("form", f.Name) {
			kept := forms.Forms[:0]
			for _, g := range forms.Forms {
				if g.Name != f.Name {
					kept = append(kept, g)
				}
			}
			forms.Forms = kept
			if err := forms.Add(f); err != nil {
				return nil, err
			}
		}
	}
	if gone := removing("form"); len(gone) > 0 {
		kept := forms.Forms[:0]
		for _, g := range forms.Forms {
			if !slices.Contains(gone, g.Name) {
				kept = append(kept, g)
			}
		}
		forms.Forms = kept
	}

	// Pages, staged into the draft together.
	pages, err := draftPages(root)
	if err != nil {
		return nil, err
	}
	pagesChanged := false
	for _, pg := range p.Pages {
		if changes("page", pg.Name) {
			pages[pg.Name] = pg.Body
			pagesChanged = true
		}
	}
	for _, name := range removing("page") {
		delete(pages, name)
		pagesChanged = true
	}

	// Menus, checked against the pages they will point at.
	menus, err := loadMenus(root)
	if err != nil {
		return nil, err
	}
	for _, m := range p.Menus {
		if changes("menu", m.Name) {
			mm := m
			if err := mm.Validate(pages); err != nil {
				return nil, fmt.Errorf("menu %s: %w", m.Name, err)
			}
			_ = menus.Remove(m.Name)
			if err := menus.Add(mm); err != nil {
				return nil, err
			}
		}
	}
	for _, name := range removing("menu") {
		_ = menus.Remove(name)
	}

	// Chatbots.
	bots, err := assistant.Load(assistantsPath(root))
	if err != nil {
		return nil, err
	}
	for _, a := range p.Chatbots {
		if changes("chatbot", a.Name) {
			if err := bots.Put(a); err != nil {
				return nil, err
			}
		}
	}
	for _, name := range removing("chatbot") {
		bots.Remove(name)
	}

	// Webhooks: a new endpoint gets its own secret, shown once.
	hooks, err := loadHooks(root)
	if err != nil {
		return nil, err
	}
	var secrets []string
	// Each endpoint a package adds, changes or takes away is recorded on its
	// own, as `quilzo webhook add` records one: an endpoint is somewhere this
	// organisation's events go, and a package installed from CI is not a
	// reason for that to go unseen by whoever watches webhooks.
	type hookChange struct{ action, url, types string }
	var hookChanges []hookChange
	for _, h := range p.Webhooks {
		switch act[feature.Ref{Kind: "webhook", Name: h.URL}] {
		case feature.Add:
			secret, err := webhook.NewSecret()
			if err != nil {
				return nil, err
			}
			hooks.Endpoints = append(hooks.Endpoints, webhook.Endpoint{URL: h.URL, Secret: secret, Types: h.Types, Note: h.Note})
			secrets = append(secrets, h.URL+"  "+secret)
			hookChanges = append(hookChanges, hookChange{"webhook.add", h.URL, strings.Join(h.Types, ",")})
		case feature.Change:
			for i := range hooks.Endpoints {
				if hooks.Endpoints[i].URL == h.URL {
					hooks.Endpoints[i].Types, hooks.Endpoints[i].Note = h.Types, h.Note
				}
			}
			hookChanges = append(hookChanges, hookChange{"webhook.change", h.URL, strings.Join(h.Types, ",")})
		}
	}
	for _, url := range removing("webhook") {
		hookChanges = append(hookChanges, hookChange{"webhook.remove", url, ""})
	}
	if gone := removing("webhook"); len(gone) > 0 {
		kept := hooks.Endpoints[:0]
		for _, e := range hooks.Endpoints {
			if !slices.Contains(gone, e.URL) {
				kept = append(kept, e)
			}
		}
		hooks.Endpoints = kept
	}

	// Every agent's delegates exist, or arrive with the package, before
	// anything is written.
	if len(p.Agents) > 0 {
		declared, err := loadAgents(root)
		if err != nil {
			return nil, err
		}
		inPkg := map[string]bool{}
		for _, m := range p.Agents {
			inPkg[m.Name] = true
		}
		for _, m := range p.Agents {
			for _, d := range m.Delegates {
				if _, ok := declared.Agents[d]; !ok && !inPkg[d] {
					return nil, fmt.Errorf("agent %s hands work to %s, which is neither declared nor in the package", m.Name, d)
				}
			}
		}
		if len(orderAgents(p.Agents)) != len(p.Agents) {
			return nil, errors.New("the package's agents hand work to each other in a circle")
		}
	}

	// Pages pass the type gate before anything is written, with the new
	// types in place, so a page that does not satisfy its type stops the
	// install here rather than half way through it.
	if pagesChanged {
		if failures := types.Gate(pages); len(failures) > 0 {
			var b strings.Builder
			for _, f := range failures {
				fmt.Fprintf(&b, "\n  %s", f)
			}
			return nil, fmt.Errorf("the feature's pages do not satisfy their types, so nothing was installed:%s", b.String())
		}
	}

	// The writes.
	if err := types.Save(); err != nil {
		return nil, err
	}
	for _, step := range []struct {
		path string
		v    any
	}{{listingPath(root), listings}, {formsPath(root), forms}, {menuPath(root), menus}, {hooksPath(root), hooks}} {
		if err := saveJSON(step.path, step.v); err != nil {
			return nil, err
		}
	}
	if err := assistant.Save(assistantsPath(root), bots); err != nil {
		return nil, err
	}
	if pagesChanged {
		s, err := open(root)
		if err != nil {
			return nil, err
		}
		if err := saveDraft(root, s, pages, "feature "+p.Name+" "+p.Version, caller.Name, ""); err != nil {
			return nil, err
		}
	}
	// Agents last among additions: a declaration is checked against what
	// exists, and an agent's sponsor is the person who approved it. One that
	// hands work to another goes after it.
	for _, m := range orderAgents(p.Agents) {
		switch act[feature.Ref{Kind: "agent", Name: m.Name}] {
		case feature.Add:
			if err := declareAgent(root, m, true, false, caller); err != nil {
				return nil, err
			}
		case feature.Change:
			// Widening was read on the card and approved with it.
			if err := declareAgent(root, m, false, true, caller); err != nil {
				return nil, err
			}
		}
	}
	for _, name := range removing("agent") {
		if err := withdrawAgent(root, name, caller); err != nil {
			return nil, err
		}
	}
	// Roles: whoever holds one that changed holds what it grants now, and
	// one the feature no longer declares is held by nobody.
	if err := reassignRoles(root, p, act, removing("role"), caller); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	in := &feature.Installed{Name: p.Name, Version: p.Version, Digest: digest, Title: p.Title, At: now, By: by, Owns: p.Refs()}
	if prev != nil {
		in.History = append([]feature.Version{{Version: prev.Version, Digest: prev.Digest, At: prev.At, By: prev.By}}, prev.History...)
		if len(in.History) > 20 {
			in.History = in.History[:20]
		}
	}
	if err := os.MkdirAll(filepath.Dir(featureInstalledPath(root, p.Name)), 0o700); err != nil {
		return nil, err
	}
	if err := saveJSON(featureInstalledPath(root, p.Name), in); err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, s := range plan.Steps {
		counts[s.Action]++
	}
	detail := map[string]string{"feature": strings.Clone(p.Name), "version": p.Version, "digest": digest[:16],
		"added": fmt.Sprint(counts[feature.Add]), "changed": fmt.Sprint(counts[feature.Change]),
		"removed": fmt.Sprint(counts[feature.Remove])}
	if len(by) > 1 {
		detail["by"] = by[0]
	}
	// What its card said, so the record shows how risky the install was
	// judged and how many people it took, not only how much it changed.
	card := p.MakeCard()
	detail["risk"], detail["approvers"] = card.Risk, fmt.Sprint(card.Approvers)
	if err := recordE(root, caller.auditRecord("feature.installed", "/", audit.Success, detail)); err != nil {
		return nil, err
	}
	pkg := p.Name
	for _, h := range hookChanges {
		d := map[string]string{"endpoint": h.url, "feature": pkg}
		if h.types != "" {
			d["types"] = h.types
		}
		if err := recordE(root, caller.auditRecord(h.action, "/", audit.Success, d)); err != nil {
			return nil, err
		}
	}
	return secrets, nil
}

// typeUsers is what still depends on a type: bound pages and collections.
func typeUsers(st *schema.Store, name string) []string {
	var out []string
	for page, t := range st.Bound {
		if t == name {
			out = append(out, "page "+page)
		}
	}
	for col, t := range st.Collections {
		if t == name {
			out = append(out, "collection "+col)
		}
	}
	sort.Strings(out)
	return out
}

func featurePendingList(root string) error {
	pend, err := pendingFeatures(root)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"pending": pend}) {
		return nil
	}
	if len(pend) == 0 {
		w.Human("no feature is waiting for a second person\n")
		return nil
	}
	for _, p := range pend {
		w.Human("%s  %s %s  risk %s, asked by %s %s\n", p.ID, p.Name, p.Version, p.Card.Risk, p.RequestedBy,
			p.At.Format("2 Jan 15:04"))
	}
	return nil
}

func pendingFeatures(root string) ([]feature.Pending, error) {
	dir := filepath.Join(featuresDir(root), "pending")
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []feature.Pending
	for _, e := range ents {
		var p feature.Pending
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if loadJSON(filepath.Join(dir, e.Name()), &p) != nil || time.Since(p.At) > feature.PendingTTL {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

func featureList(root string) error {
	installed, err := loadInstalledFeatures(root)
	if err != nil {
		return err
	}
	var names []string
	for n := range installed {
		names = append(names, n)
	}
	sort.Strings(names)
	if w.Mode == out.JSON {
		list := []*feature.Installed{}
		for _, n := range names {
			list = append(list, installed[n])
		}
		w.JSON(map[string]any{"features": list})
		return nil
	}
	if len(names) == 0 {
		w.Human("no features installed\n")
		w.Human("  %squilzo feature example > f.json, edit it, then quilzo feature check f.json%s\n", dim, reset)
		return nil
	}
	for _, n := range names {
		in := installed[n]
		w.Human("%s%s%s %s  %s  %d blocks, by %s %s\n", bold, in.Name, reset, in.Version, in.Title, len(in.Owns),
			strings.Join(in.By, " and "), in.At.Format("2 Jan 2006"))
	}
	return nil
}

func featureShow(root string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: quilzo feature show NAME")
	}
	installed, err := loadInstalledFeatures(root)
	if err != nil {
		return err
	}
	in := installed[args[0]]
	if in == nil {
		return fmt.Errorf("no feature called %s is installed", args[0])
	}
	p, _, err := loadFeaturePackage(root, in.Name, in.Digest)
	if err != nil {
		return err
	}
	card := p.MakeCard()
	if w.JSON(map[string]any{"installed": in, "card": card}) {
		return nil
	}
	printFeatureCard(card)
	w.Human("\n  %sOwns%s\n", bold, reset)
	pol, _ := loadPolicy(root)
	for _, r := range in.Owns {
		if r.Kind == "role" && pol != nil {
			who := holders(pol, r.Name)
			if len(who) == 0 {
				w.Human("    %s  %sheld by nobody%s\n", r, dim, reset)
			} else {
				w.Human("    %s  %sheld by %s%s\n", r, dim, strings.Join(who, ", "), reset)
			}
			continue
		}
		w.Human("    %s\n", r)
	}
	w.Human("\n  installed %s by %s\n", in.At.Format("2 Jan 2006 15:04"), strings.Join(in.By, " and "))
	for _, h := range in.History {
		w.Human("  %searlier %s, %s%s\n", dim, h.Version, h.At.Format("2 Jan 2006"), reset)
	}
	return nil
}

// featureRemove takes back everything a feature made. Records people
// entered stay: unbinding a collection leaves its records where they are.
func featureRemove(root string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: quilzo feature remove NAME")
	}
	return removeFeature(root, args[0], resolveCaller(root, flagToken))
}

func removeFeature(root, name string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActInstall, "/"); err != nil {
		return fmt.Errorf("features are installed and changed by whoever may install them: %w", err)
	}
	if caller.Kind == audit.KindAI {
		return errors.New("a feature is removed by a person")
	}
	installed, err := loadInstalledFeatures(root)
	if err != nil {
		return err
	}
	in := installed[name]
	if in == nil {
		return fmt.Errorf("no feature called %s is installed", name)
	}
	empty := &feature.Package{Format: feature.Format, Name: in.Name, Version: in.Version, Title: in.Title}
	plan := empty.MakePlan(feature.State{}, in.Owns)
	if _, err := applyFeature(root, empty, in.Digest, plan, caller, []string{caller.Name}); err != nil {
		return err
	}
	if err := os.Remove(featureInstalledPath(root, in.Name)); err != nil {
		return err
	}
	record(root, caller.auditRecord("feature.removed", "/", audit.Success, map[string]string{
		"feature": in.Name, "version": in.Version, "blocks": fmt.Sprint(len(in.Owns))}))
	w.Human("removed %s: %d blocks taken back; page removals are in the draft, and records people entered are kept\n",
		in.Name, len(in.Owns))
	return nil
}

// featureRollback reinstalls the version before the current one, under the
// same approval rule as installing it.
func featureRollback(root string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: quilzo feature rollback NAME")
	}
	caller := resolveCaller(root, flagToken)
	p, o, err := rollbackFeature(root, args[0], caller)
	if p == nil {
		return err
	}
	return printOutcome(p, o, err, caller)
}

func rollbackFeature(root, name string, caller *Caller) (*feature.Package, featureOutcome, error) {
	if err := authorise(root, caller, auth.ActInstall, "/"); err != nil {
		return nil, featureOutcome{}, fmt.Errorf("features are installed and changed by whoever may install them: %w", err)
	}
	if caller.Kind == audit.KindAI {
		return nil, featureOutcome{}, errors.New("a feature is rolled back by a person")
	}
	installed, err := loadInstalledFeatures(root)
	if err != nil {
		return nil, featureOutcome{}, err
	}
	in := installed[name]
	if in == nil {
		return nil, featureOutcome{}, fmt.Errorf("no feature called %s is installed", name)
	}
	if len(in.History) == 0 {
		return nil, featureOutcome{}, fmt.Errorf("%s has no earlier version to go back to", in.Name)
	}
	p, body, err := loadFeaturePackage(root, in.Name, in.History[0].Digest)
	if err != nil {
		return nil, featureOutcome{}, err
	}
	if err := p.Validate(featureChecks(root)); err != nil {
		return nil, featureOutcome{}, fmt.Errorf("version %s no longer passes the checks: %w", p.Version, err)
	}
	o, err := requestFeature(root, p, body, caller, true, nil)
	return p, o, err
}

// featureExport is `quilzo feature export NAME [-o FILE] [--sign]`: the
// installed version, exactly, optionally signed with this installation's
// log keys.
func featureExport(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("feature export", flag.ContinueOnError)
	outPath := fs.String("o", "", "write to this file instead of standard output")
	sign := fs.Bool("sign", false, "sign it with this installation's log keys (Ed25519 and ML-DSA)")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: quilzo feature export NAME [-o FILE] [--sign]")
	}
	installed, err := loadInstalledFeatures(root)
	if err != nil {
		return err
	}
	in := installed[pos[0]]
	if in == nil {
		return fmt.Errorf("no feature called %s is installed", pos[0])
	}
	p, _, err := loadFeaturePackage(root, in.Name, in.Digest)
	if err != nil {
		return err
	}
	return writeFeature(root, p, *outPath, *sign)
}

func writeFeature(root string, p *feature.Package, outPath string, sign bool) error {
	p.Signature = nil
	if sign {
		signer, err := headSigner(root)
		if err != nil {
			return err
		}
		digest, err := p.Digest()
		if err != nil {
			return err
		}
		st, err := signer.SignStatement(featureContext, []byte(digest))
		if err != nil {
			return err
		}
		p.Signature = &feature.Signature{KeyID: st.KeyID, Ed25519: st.Ed25519, MLDSA: st.MLDSA, Algorithms: st.Algorithms}
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if outPath == "" {
		_, err = os.Stdout.Write(b)
		return err
	}
	if err := atomicfile.Write(outPath, b, 0o644); err != nil {
		return err
	}
	if sign {
		w.Human("wrote %s, signed; whoever installs it checks it with --keys %s\n", outPath, headKeysPath(root))
	}
	return nil
}

// featureCapture is `quilzo feature capture NAME --title T --purpose P
// [--type A ...]`: a package made from blocks that already exist, so a
// feature somebody built by hand can be handed to another installation.
func featureCapture(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("feature capture", flag.ContinueOnError)
	title := fs.String("title", "", "what the feature is called")
	purpose := fs.String("purpose", "", "what it is for, in a sentence")
	version := fs.String("version", "1.0.0", "its version")
	outPath := fs.String("o", "", "write to this file instead of standard output")
	sign := fs.Bool("sign", false, "sign it with this installation's log keys")
	var types, cols, lists, forms, pages, menus, bots, agents, hooks multiFlag
	fs.Var(&types, "type", "a content type; repeat for more")
	fs.Var(&cols, "collection", "a bound collection")
	fs.Var(&lists, "listing", "a listing")
	fs.Var(&forms, "form", "a form")
	fs.Var(&pages, "page", "a page from the draft")
	fs.Var(&menus, "menu", "a menu")
	fs.Var(&bots, "chatbot", "a chatbot")
	fs.Var(&agents, "agent", "an agent declaration")
	fs.Var(&hooks, "webhook", "a webhook, by URL; its secret is not included")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: quilzo feature capture NAME --title T --purpose P [--type A] [--collection C] " +
			"[--listing L] [--form F] [--page P] [--menu M] [--chatbot B] [--agent A] [--webhook URL] [-o FILE] [--sign]")
	}
	st, _, err := featureState(root)
	if err != nil {
		return err
	}
	p := &feature.Package{Format: feature.Format, Name: pos[0], Version: *version, Title: *title, Purpose: *purpose,
		Made: &feature.Made{By: resolveCaller(root, flagToken).Name, From: "captured from this installation", At: time.Now().UTC()}}
	get := func(kind, name string, into any) error {
		raw, ok := st.Current[feature.Ref{Kind: kind, Name: name}]
		if !ok {
			return fmt.Errorf("there is no %s %q", kind, name)
		}
		return json.Unmarshal(raw, into)
	}
	for _, n := range types {
		var t schema.Type
		if err := get("type", n, &t); err != nil {
			return err
		}
		p.Types = append(p.Types, t)
	}
	for _, n := range cols {
		var c feature.Collection
		if err := get("collection", n, &c); err != nil {
			return err
		}
		p.Collections = append(p.Collections, c)
	}
	for _, n := range lists {
		var l listing.Listing
		if err := get("listing", n, &l); err != nil {
			return err
		}
		p.Listings = append(p.Listings, l)
	}
	for _, n := range forms {
		var f form.Form
		if err := get("form", n, &f); err != nil {
			return err
		}
		p.Forms = append(p.Forms, f)
	}
	for _, n := range pages {
		var body map[string]any
		if err := get("page", n, &body); err != nil {
			return err
		}
		p.Pages = append(p.Pages, feature.Page{Name: n, Body: body})
	}
	for _, n := range menus {
		var m menu.Menu
		if err := get("menu", n, &m); err != nil {
			return err
		}
		p.Menus = append(p.Menus, m)
	}
	for _, n := range bots {
		var a assistant.Assistant
		if err := get("chatbot", n, &a); err != nil {
			return err
		}
		p.Chatbots = append(p.Chatbots, a)
	}
	for _, n := range agents {
		var m agent.Manifest
		if err := get("agent", n, &m); err != nil {
			return err
		}
		p.Agents = append(p.Agents, m)
	}
	for _, n := range hooks {
		var h feature.Webhook
		if err := get("webhook", n, &h); err != nil {
			return err
		}
		p.Webhooks = append(p.Webhooks, h)
	}
	if err := p.Validate(featureChecks(root)); err != nil {
		return err
	}
	return writeFeature(root, p, *outPath, *sign)
}

// orderAgents puts each agent after the package agents it hands work to.
// Agents in a circle are left out, which the caller reports.
func orderAgents(ms []agent.Manifest) []agent.Manifest {
	inPkg := map[string]bool{}
	for _, m := range ms {
		inPkg[m.Name] = true
	}
	done := map[string]bool{}
	var out []agent.Manifest
	for len(out) < len(ms) {
		progressed := false
		for _, m := range ms {
			if done[m.Name] {
				continue
			}
			ready := true
			for _, d := range m.Delegates {
				ready = ready && (!inPkg[d] || done[d])
			}
			if ready {
				done[m.Name], progressed = true, true
				out = append(out, m)
			}
		}
		if !progressed {
			break
		}
	}
	return out
}

// featureHooks are the Make screen's reach into the feature store.
func featureHooks(root string, signedIn func(admin.Actor) *Caller) *admin.FeatureHooks {
	return &admin.FeatureHooks{
		Installed: func() ([]feature.Installed, error) {
			m, err := loadInstalledFeatures(root)
			if err != nil {
				return nil, err
			}
			var out []feature.Installed
			for _, in := range m {
				out = append(out, *in)
			}
			sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
			return out, nil
		},
		Pending: func() ([]feature.Pending, error) { return pendingFeatures(root) },
		Check: func(body []byte) (*feature.Package, feature.Card, feature.Plan, error) {
			return checkFeature(root, body)
		},
		Install: func(body []byte, rowsID string, by admin.Actor) (string, []string, error) {
			caller := signedIn(by)
			if err := authorise(root, caller, auth.ActInstall, "/"); err != nil {
				return "", nil, err
			}
			p, body, err := readFeatureBytes(root, body, "")
			if err != nil {
				return "", nil, err
			}
			var rows *feature.Rows
			if rowsID != "" {
				if rows, err = readRows(featureDraftRowsPath(root, rowsID)); err != nil {
					return "", nil, fmt.Errorf("the spreadsheet's records are no longer here; read the file again: %w", err)
				}
			}
			o, err := requestFeature(root, p, body, caller, false, rows)
			if err == nil && rowsID != "" {
				_ = os.Remove(featureDraftRowsPath(root, rowsID))
			}
			if o.Waiting != nil {
				return o.Waiting.ID, nil, err
			}
			return "", o.Secrets, err
		},
		Draft: func(description string, by admin.Actor) ([]byte, []string, string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), featureDraftTimeout)
			defer cancel()
			d, err := draftFeature(ctx, root, description, signedIn(by))
			if err != nil {
				return nil, nil, "", err
			}
			return d.Body, d.Notes, d.Invalid, nil
		},
		FromData: func(name string, data []byte, _ admin.Actor) ([]byte, string, int, string, []string, error) {
			in, err := feature.Infer(name, data)
			if err != nil {
				return nil, "", 0, "", nil, err
			}
			body, err := json.MarshalIndent(in.Package, "", "  ")
			if err != nil {
				return nil, "", 0, "", nil, err
			}
			id, err := keepDraftRows(root, &feature.Rows{Collection: in.Collection, Records: in.Rows})
			if err != nil {
				return nil, "", 0, "", nil, err
			}
			return append(body, '\n'), id, len(in.Rows), in.Collection, in.Notes, nil
		},
		Decide: func(id string, approve bool, by admin.Actor) error {
			return decideFeature(root, id, approve, signedIn(by))
		},
		Remove: func(name string, by admin.Actor) error { return removeFeature(root, name, signedIn(by)) },
		Rollback: func(name string, by admin.Actor) (string, error) {
			_, o, err := rollbackFeature(root, name, signedIn(by))
			if o.Waiting != nil {
				return o.Waiting.ID, err
			}
			return "", err
		},
	}
}

// checkFeature reads a package and works out its card and its plan against
// what is installed, changing nothing.
func checkFeature(root string, body []byte) (*feature.Package, feature.Card, feature.Plan, error) {
	p, _, err := readFeatureBytes(root, body, "")
	if err != nil {
		return nil, feature.Card{}, feature.Plan{}, err
	}
	st, installed, err := featureState(root)
	if err != nil {
		return nil, feature.Card{}, feature.Plan{}, err
	}
	var owned []feature.Ref
	if in := installed[p.Name]; in != nil {
		owned = in.Owns
	}
	return p, p.MakeCard(), p.MakePlan(st, owned), nil
}

// programCaller is a program presenting a token over HTTP, such as a CI job:
// a service, held to its token's role, path and limits.
func programCaller(tok auth.Token) *Caller {
	return &Caller{Name: tok.Principal, Role: tok.Role, Scope: tok.Resource, Limits: tok.Scope,
		Kind: audit.KindService, Verified: true, Remote: true, Bound: tok.Key != "",
		Life: time.Unix(tok.ExpiresAt, 0).Sub(time.Unix(tok.CreatedAt, 0))}
}

// featureProgram checks and installs packages for a program's token, under
// the same card, plan and approvals as the Make screen.
func featureProgram(root string) *admin.FeatureProgram {
	forbidden := func(err error) error { return fmt.Errorf("%w: %v", admin.ErrForbidden, err) }
	return &admin.FeatureProgram{
		Check: func(body []byte, tok auth.Token) (*feature.Package, feature.Card, feature.Plan, error) {
			if err := authorise(root, programCaller(tok), auth.ActView, "/"); err != nil {
				return nil, feature.Card{}, feature.Plan{}, forbidden(err)
			}
			return checkFeature(root, body)
		},
		Install: func(body []byte, tok auth.Token) (string, []string, error) {
			caller := programCaller(tok)
			if err := authorise(root, caller, auth.ActInstall, "/"); err != nil {
				return "", nil, forbidden(fmt.Errorf("features are installed by whoever may install them: %w", err))
			}
			if err := riskyNeedsProof(root, caller, auth.RoleAdmin); err != nil {
				return "", nil, forbidden(err)
			}
			p, body, err := readFeatureBytes(root, body, "")
			if err != nil {
				return "", nil, err
			}
			o, err := requestFeature(root, p, body, caller, false, nil)
			if o.Waiting != nil {
				return o.Waiting.ID, nil, err
			}
			return "", o.Secrets, err
		},
	}
}

// featureDraftRowsPath is where a spreadsheet's rows wait between reading
// it on the Make screen and installing the feature.
func featureDraftRowsPath(root, id string) string {
	return filepath.Join(featuresDir(root), "drafts", id+".rows.json")
}

// keepDraftRows keeps rows under a new id, readable only here, and clears
// out rows nobody installed within a day.
func keepDraftRows(root string, rows *feature.Rows) (string, error) {
	dir := filepath.Join(featuresDir(root), "drafts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if ents, err := os.ReadDir(dir); err == nil {
		for _, e := range ents {
			if fi, err := e.Info(); err == nil && time.Since(fi.ModTime()) > 24*time.Hour {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	body, err := json.Marshal(rows)
	if err != nil {
		return "", err
	}
	return id, atomicfile.Write(featureDraftRowsPath(root, id), body, 0o600)
}
