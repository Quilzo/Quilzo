// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/ext"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/notify"
	"github.com/quilzo/quilzo/internal/provenance"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/telemetry"
)

// Telling customers and subscribers what happened.
//
// Two phases everywhere it matters. `notify plan` shows who would be told and
// who would not and why; `notify send` takes that plan. A notice cannot be
// recalled, and during a breach — the one time this is used in anger — the
// person reading the plan is the only thing between a hurried incident lead
// and a message telling four thousand unaffected customers their data leaked.
//
// The lawful basis is decided by the kind of notice and is not a setting. A
// contact who objected to everything still gets a breach notice, because
// Article 34 is an obligation and an obligation has no opt-out. That is one
// line in internal/notify and it is the whole reason this is a package rather
// than a mailing list.

func notifyDir(root string) string { return filepath.Join(root, "notify") }

func cmdNotify(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "contacts":
		return notifyContacts(root)
	case "add":
		return notifyAdd(root, args[1:])
	case "object":
		return notifyObject(root, args[1:])
	case "erase":
		return notifyErase(root, args[1:])
	case "draft":
		return notifyDraft(root, args[1:])
	case "list":
		return notifyList(root)
	case "plan":
		return notifyPlan(root, args[1:])
	case "send":
		return notifySend(root, args[1:])
	case "publish":
		return notifyPublish(root, args[1:])
	case "inbox":
		return notifyInbox(root, args[1:])
	default:
		return fmt.Errorf("unknown notify command %q; try contacts, add, "+
			"object, erase, draft, list, plan, send, publish or inbox",
			args[0])
	}
}

// contactID parses "issuer:value".
func contactID(s string) (telemetry.ID, error) {
	issuer, value, found := strings.Cut(strings.TrimSpace(s), ":")
	if !found || strings.TrimSpace(issuer) == "" ||
		strings.TrimSpace(value) == "" {
		return telemetry.ID{}, fmt.Errorf(
			"%q is not a contact. Write it as issuer:value, such as "+
				"crm:cust-1043 — two systems both issue the same customer "+
				"number, and a list that joins on the value alone sends one "+
				"person's breach notice to another", s)
	}
	return telemetry.ID{Issuer: strings.TrimSpace(issuer),
		Value: strings.TrimSpace(value)}, nil
}

func notifyContacts(root string) error {
	st, err := notify.OpenStore(notifyDir(root))
	if err != nil {
		return err
	}
	a, err := st.Audience()
	if err != nil {
		return err
	}
	all := a.All()
	if w.JSON(map[string]any{
		"contacts": all, "reachable_for_breach": a.Reachable(notify.Breach),
		"suppressed": len(a.Suppressions()),
	}) {
		return nil
	}
	if len(all) == 0 {
		w.Human("nobody is on the list\n")
		return nil
	}
	for _, c := range all {
		state, colour := "", green
		switch {
		case c.Erased():
			state, colour = "erased", dim
		case !c.ObjectedAt.IsZero():
			state, colour = "objected", yellow
		}
		w.Human("%s%s%s  %s%s%s  %s%s%s\n", bold, c.ID.String(), reset,
			dim, c.Channel, reset, colour, state, reset)
		w.Human("  %sfrom %s since %s%s\n",
			dim, c.Source, c.Since.Format("2006-01-02"), reset)
	}
	// The gap between these two numbers is what matters during a breach and
	// is the one nobody looks at beforehand.
	w.Human("\n%s%d on the list, %d reachable for a breach notice, %d "+
		"suppressed%s\n", bold, a.Len(), a.Reachable(notify.Breach),
		len(a.Suppressions()), reset)
	return nil
}

func notifyAdd(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	channel := fs.String("channel", string(notify.InApp), "app, email or webhook")
	address := fs.String("address", "", "where to reach them")
	name := fs.String("name", "", "what to call them")
	source := fs.String("source", "", "where this contact came from")
	consent := fs.String("consent", "",
		"the exact words they agreed to, for marketing")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo notify add ISSUER:VALUE " +
			"--channel app|email|webhook [--address ...] --source ...")
	}
	id, err := contactID(pos[0])
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}
	st, err := notify.OpenStore(notifyDir(root))
	if err != nil {
		return err
	}
	a, err := st.Audience()
	if err != nil {
		return err
	}
	c := notify.Contact{
		ID: id, Name: strings.TrimSpace(*name),
		Channel: notify.Channel(*channel),
		Address: strings.TrimSpace(*address),
		Source:  strings.TrimSpace(*source), Since: time.Now().UTC(),
	}
	if strings.TrimSpace(*consent) != "" {
		c.ConsentAt = time.Now().UTC()
		c.ConsentText = strings.TrimSpace(*consent)
	}
	if _, err := a.Add(c); err != nil {
		return err
	}
	if err := st.SaveAudience(a); err != nil {
		return err
	}
	// No address in the record. The audit log is exported.
	record(root, audit.Record{
		Action: "notify.added", Resource: "/notify/" + id.String(),
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Kind != audit.KindUnknown,
		Detail: map[string]string{
			"contact": id.String(), "channel": *channel,
			"source": c.Source,
		},
	})
	if w.JSON(map[string]any{"added": id.String()}) {
		return nil
	}
	w.Human("%s%s%s added\n", bold, id.String(), reset)
	return nil
}

func notifyObject(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("object", flag.ContinueOnError)
	kinds := fs.String("kinds", "",
		"comma-separated kinds; empty means everything that can be declined")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo notify object ISSUER:VALUE [--kinds ...]")
	}
	id, err := contactID(pos[0])
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}
	st, err := notify.OpenStore(notifyDir(root))
	if err != nil {
		return err
	}
	a, err := st.Audience()
	if err != nil {
		return err
	}
	var want []notify.Kind
	for _, k := range strings.Split(*kinds, ",") {
		if strings.TrimSpace(k) != "" {
			want = append(want, notify.Kind(strings.TrimSpace(k)))
		}
	}
	ignored, err := a.Object(id, want, time.Now().UTC())
	if err != nil {
		return err
	}
	if err := st.SaveAudience(a); err != nil {
		return err
	}
	record(root, audit.Record{
		Action: "notify.objected", Resource: "/notify/" + id.String(),
		Outcome: audit.Denied, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Kind != audit.KindUnknown,
		Detail: map[string]string{
			"contact": id.String(), "kinds": *kinds,
		},
	})
	if w.JSON(map[string]any{"objected": id.String(), "ignored": ignored}) {
		return nil
	}
	w.Human("%s%s%s will not be sent what they declined\n",
		bold, id.String(), reset)
	if len(ignored) > 0 {
		// Reported, not refused. Somebody asking not to be told about a
		// breach has told you something real; the answer is that the law
		// does not let them decline, and the answer is more useful than
		// an error.
		var names []string
		for _, k := range ignored {
			names = append(names, string(k))
		}
		w.Human("  %s%s cannot be declined: %s rests on a legal obligation "+
			"or on the contract, and is sent regardless%s\n",
			yellow, strings.Join(names, ", "), strings.Join(names, "/"), reset)
	}
	return nil
}

func notifyErase(root string, args []string) error {
	pos, _ := leadingArgs(args, 1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo notify erase ISSUER:VALUE")
	}
	id, err := contactID(pos[0])
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	st, err := notify.OpenStore(notifyDir(root))
	if err != nil {
		return err
	}
	a, err := st.Audience()
	if err != nil {
		return err
	}
	if err := a.Erase(id, time.Now().UTC()); err != nil {
		return err
	}
	if err := st.SaveAudience(a); err != nil {
		return err
	}
	if err := st.ForgetInbox(id); err != nil {
		return err
	}
	record(root, audit.Record{
		Action: "notify.erased", Resource: "/notify/" + id.String(),
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Kind != audit.KindUnknown,
		Detail:   map[string]string{"contact": id.String()},
	})
	if w.JSON(map[string]any{"erased": id.String()}) {
		return nil
	}
	w.Human("%s%s%s erased\n", bold, id.String(), reset)
	w.Human("  %sthe address is gone and a keyed fingerprint remains, so a "+
		"re-import from a CRM is refused rather than quietly re-adding "+
		"them%s\n", dim, reset)
	w.Human("  %sthey can no longer be sent a breach notice; if they are "+
		"ever affected, that is the Article 34(3)(c) conversation%s\n",
		yellow, reset)
	return nil
}

func notifyDraft(root string, args []string) error {
	fs := flag.NewFlagSet("draft", flag.ContinueOnError)
	kind := fs.String("kind", string(notify.Change), "breach, incident, "+
		"maintenance, change, deprecation or marketing")
	subject := fs.String("subject", "", "one line")
	body := fs.String("body", "", "what to tell them")
	occurred := fs.String("occurred", "", "when it happened, RFC3339")
	aware := fs.String("aware", "", "when this organisation found out, RFC3339")
	nature := fs.String("nature", "", "Article 34(2)(a): what the breach was")
	contact := fs.String("contact", "", "Article 34(2)(b): the DPO or contact point")
	consequences := fs.String("consequences", "",
		"Article 34(2)(c): the likely consequences")
	measures := fs.String("measures", "",
		"Article 34(2)(d): the measures taken or proposed")
	affected := fs.String("affected", "",
		"comma-separated issuer:value of the people affected")
	public := fs.String("public", "",
		"Article 34(3)(c): why individual notification is disproportionate")
	mitigated := fs.String("mitigated", "",
		"Article 34(3)(a) or (b): why the high risk does not arise")
	if err := fs.Parse(args); err != nil {
		return err
	}

	caller := resolveCaller(root, flagToken)
	when := func(s string, fallback time.Time) (time.Time, error) {
		if strings.TrimSpace(s) == "" {
			return fallback, nil
		}
		return time.Parse(time.RFC3339, strings.TrimSpace(s))
	}
	nowUTC := time.Now().UTC()
	occ, err := when(*occurred, nowUTC)
	if err != nil {
		return fmt.Errorf("--occurred is an RFC3339 time: %w", err)
	}
	aw, err := when(*aware, nowUTC)
	if err != nil {
		return fmt.Errorf("--aware is an RFC3339 time: %w", err)
	}

	n := notify.Notice{
		Kind: notify.Kind(*kind), Subject: strings.TrimSpace(*subject),
		Body: strings.TrimSpace(*body), Occurred: occ, Aware: aw,
		Nature: strings.TrimSpace(*nature),
		// Article 34(2)(b) is a contact point, not this program's caller.
		Contact:      strings.TrimSpace(*contact),
		Consequences: strings.TrimSpace(*consequences),
		Measures:     strings.TrimSpace(*measures),
		Public:       strings.TrimSpace(*public),
		Mitigated:    strings.TrimSpace(*mitigated),
		Author:       caller.Name, Kinded: caller.Kind,
	}
	for _, s := range strings.Split(*affected, ",") {
		if strings.TrimSpace(s) == "" {
			continue
		}
		id, ierr := contactID(s)
		if ierr != nil {
			return ierr
		}
		n.Affected = append(n.Affected, id)
	}
	n.ID = notify.Ident(n.Kind, n.Subject, n.Aware)
	if err := n.Validate(); err != nil {
		return err
	}

	st, err := notify.OpenStore(notifyDir(root))
	if err != nil {
		return err
	}
	if err := st.SaveNotice(n); err != nil {
		return err
	}
	if w.JSON(n) {
		return nil
	}
	w.Human("%s%s%s drafted\n", bold, n.ID, reset)
	w.Human("  %s%s: %s%s\n", dim, n.Kind, n.Subject, reset)
	if n.Kind == notify.Breach {
		w.Human("  %sArticle 33 gives until %s to tell the supervisory "+
			"authority%s\n", yellow,
			n.AuthorityDue().Format(time.RFC3339), reset)
		_, why := n.SubjectDue()
		w.Human("  %s%s%s\n", yellow, why, reset)
	}
	w.Human("\n  %snothing has been sent. quilzo notify plan %s%s\n",
		dim, n.ID, reset)
	return nil
}

func notifyList(root string) error {
	st, err := notify.OpenStore(notifyDir(root))
	if err != nil {
		return err
	}
	all, err := st.Notices()
	if err != nil {
		return err
	}
	live, draft, perr := noticePages(root)
	if perr != nil {
		return perr
	}
	if w.JSON(map[string]any{
		"notices": all, "public_live": live, "public_draft": draft,
	}) {
		return nil
	}
	if len(all) == 0 {
		w.Human("nothing has been drafted\n")
		return nil
	}
	at := time.Now().UTC()
	for _, n := range all {
		w.Human("%s%s%s  %s%s%s  %s\n",
			bold, n.ID, reset, dim, n.Kind, reset, n.Subject)
		if n.Kind == notify.Breach {
			state, colour := "within the Article 33 window", green
			if n.Overdue(at) {
				state, colour = "past the Article 33 deadline", red
			}
			w.Human("  %s%s; %s since anybody knew%s\n",
				colour, state, n.Undue(at).Round(time.Minute), reset)
		}
		reportPublicPage(n, live, draft)
	}
	return nil
}

// reportPublicPage says where a notice's public communication stands.
//
// The case worth printing is the last one. If a public communication is how
// somebody was told, taking the page down three weeks later unmakes the
// notification — and the way that is discovered otherwise is from a
// regulator.
func reportPublicPage(n notify.Notice, live, draft map[string]bool) {
	name := n.PageName()
	switch {
	case live[name]:
		w.Human("  %spublic communication live at /%s%s\n",
			green, name, reset)
	case draft[name]:
		w.Human("  %spublic communication written as %s and not published: "+
			"quilzo publish%s\n", yellow, name, reset)
	case n.Kind == notify.Breach && strings.TrimSpace(n.Public) != "":
		w.Human("  %sthis notice records an Article 34(3)(c) reason and "+
			"there is no public communication: /%s is neither live nor in "+
			"the draft. If the page was taken down, the people who were "+
			"told only that way are no longer told%s\n", red, name, reset)
	}
}

// noticePages reads which notice pages exist, live and in the draft.
func noticePages(root string) (live, draft map[string]bool, err error) {
	live, draft = map[string]bool{}, map[string]bool{}
	s, err := open(root)
	if err != nil {
		// A notification store can exist before a site does. Reporting no
		// pages is the truth in that case, and failing would make `notify
		// list` unusable on a deployment that only ever notifies.
		return live, draft, nil
	}
	for ref, into := range map[string]map[string]bool{
		site.RefLive: live, site.RefDraft: draft,
	} {
		commit := s.GetRef(ref)
		if commit == "" {
			continue
		}
		pages, perr := site.PagesAt(s, commit)
		if perr != nil {
			return nil, nil, perr
		}
		for name := range pages {
			if strings.HasPrefix(name, "notice-") {
				into[name] = true
			}
		}
	}
	return live, draft, nil
}

func notifyPlan(root string, args []string) error {
	pos, _ := leadingArgs(args, 1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo notify plan NOTICE")
	}
	st, n, a, err := notifyLoad(root, pos[0])
	if err != nil {
		return err
	}
	at := time.Now().UTC()
	plan, err := notify.Prepare(n, a, at)
	if err != nil {
		return err
	}
	// Which channels have nothing behind them, found now rather than during
	// the send. A deployment discovers its mail relay was never configured
	// at the worst possible moment otherwise, and the plan is the moment
	// somebody is actually reading.
	senders, err := notifySenders(root, st, at)
	if err != nil {
		return err
	}
	unconfigured := missingChannels(plan, senders)
	if w.JSON(map[string]any{
		"plan": plan, "unconfigured": unconfigured,
	}) {
		return nil
	}
	reportPlan(n, plan)
	for _, c := range unconfigured {
		w.Human("  %snothing is configured to send on the %s channel, and "+
			"%d of these deliveries need it%s\n",
			red, c.channel, c.count, reset)
	}
	w.Human("\n  %snothing was sent. quilzo notify send %s%s\n",
		dim, n.ID, reset)
	return nil
}

type channelGap struct {
	channel notify.Channel
	count   int
}

// missingChannels names the channels a plan needs and this deployment has not
// set up.
func missingChannels(plan notify.Plan, senders notify.ByChannel) []channelGap {
	counts := map[notify.Channel]int{}
	for _, d := range plan.Send {
		if s, ok := senders[d.Channel]; !ok || s == nil {
			counts[d.Channel]++
		}
	}
	out := make([]channelGap, 0, len(counts))
	for c, n := range counts {
		out = append(out, channelGap{channel: c, count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].channel < out[j].channel
	})
	return out
}

func reportPlan(n notify.Notice, plan notify.Plan) {
	w.Human("%s%s%s  %s\n", bold, n.ID, reset, n.Subject)
	w.Human("  %s%s%s\n", bold, plan.Why(), reset)
	for _, h := range plan.Hold {
		w.Human("  %s%s: %s%s\n", dim, h.To.String(), h.Why, reset)
	}
	for _, m := range plan.Missing {
		w.Human("  %s%s is affected and is not on the list at all%s\n",
			red, m.String(), reset)
	}
	if plan.Unreachable > 0 && n.Kind == notify.Breach && n.Public == "" {
		w.Human("\n  %s%d of the people affected cannot be reached "+
			"individually. Article 34(3)(c) permits a public communication "+
			"when individual notification would involve disproportionate "+
			"effort; record the reason with --public%s\n",
			yellow, plan.Unreachable, reset)
	}
}

func notifySend(root string, args []string) error {
	pos, _ := leadingArgs(args, 1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo notify send NOTICE")
	}
	st, n, a, err := notifyLoad(root, pos[0])
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	// Telling customers something is the organisation speaking. The same
	// authority as publishing, and for the same reason.
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return err
	}
	at := time.Now().UTC()
	plan, err := notify.Prepare(n, a, at)
	if err != nil {
		return err
	}
	box, err := st.Outbox()
	if err != nil {
		return err
	}
	senders, err := notifySenders(root, st, at)
	if err != nil {
		return err
	}
	out, err := notify.Deliver(n, plan, box, senders, at)
	// Saved whatever happened. An outbox that is only written on success
	// forgets who was told when something goes wrong halfway, and what it
	// forgets is the reason not to tell them again.
	if serr := st.SaveOutbox(box); serr != nil {
		return serr
	}
	if err != nil {
		return err
	}
	// The Article 33(5) documentation of the notice, then one record per
	// delivery. Recorded after the send, so nothing claims somebody was told
	// who was not.
	//
	// Not written when a re-run sent nothing. A second notice.breach entry
	// against the same notice reads, years later and without any of this
	// context, like a second breach — and the documentation Article 33(5)
	// asks for is meant to let a supervisory authority verify compliance,
	// not to be counted.
	if len(out.Sent) > 0 || len(out.Failed) > 0 {
		record(root, n.Record(len(out.Sent), len(plan.Hold)))
	}
	for _, d := range out.Sent {
		record(root, d.Record(n, caller.Name, caller.Kind))
	}

	if w.JSON(out) {
		return nil
	}
	w.Human("%s%s%s\n", bold, out.Summary(), reset)
	for _, f := range out.Failed {
		w.Human("  %s%s: %s%s\n", red, f.Delivery.To.String(), f.Why, reset)
	}
	if len(out.Failed) > 0 {
		w.Human("  %sthose were not recorded as sent; running send again "+
			"reaches them and tells nobody else twice%s\n", dim, reset)
	}
	return nil
}

// notifySenders builds the channel routing for this deployment.
//
// In-app always, because it needs no configuration and is the channel whose
// delivery is a fact. Mail and webhook only where they have been set up — and
// a delivery on a channel with nothing behind it is an error rather than a
// quiet fallback, because a person recorded as told by the wrong channel is
// one the retry will skip for ever.
func notifySenders(root string, st *notify.Store, at time.Time) (
	notify.ByChannel, error) {

	clock := func() time.Time { return at }
	out := notify.ByChannel{
		notify.InApp: notify.AppSender{Store: st, At: clock},
	}
	conf, err := loadMailConfig(root)
	if err != nil {
		return nil, err
	}
	if conf != nil {
		conf.At = clock
		out[notify.Email] = *conf
	}
	hookSecret, err := loadHookSecret(root)
	if err != nil {
		return nil, err
	}
	if hookSecret != "" {
		out[notify.Webhook] = notify.HookSender{
			// The same SSRF-hardened client the CMS webhooks use. A
			// customer's endpoint is a URL somebody configured and this
			// program requests it from inside the network, which is the
			// shape that needs a connect-time address check.
			Post: sender{fetch.New()}, Secret: hookSecret, At: clock,
		}
	}
	return out, nil
}

// mailConfig is notify/mail.json.
//
// A file rather than flags. The credentials for a mail relay on a command
// line end up in a shell history and in the process table, and the one
// command they would be typed on is the one run during an incident with
// somebody watching over a shoulder.
type mailConfig struct {
	Host        string `json:"host"`
	From        string `json:"from"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	Unsubscribe string `json:"unsubscribe,omitempty"`
}

func loadMailConfig(root string) (*notify.Mailer, error) {
	var c mailConfig
	b, err := os.ReadFile(filepath.Join(notifyDir(root), "mail.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if uerr := json.Unmarshal(b, &c); uerr != nil {
		return nil, fmt.Errorf("notify/mail.json is unreadable: %w", uerr)
	}
	if strings.TrimSpace(c.Host) == "" || strings.TrimSpace(c.From) == "" {
		return nil, fmt.Errorf(
			"notify/mail.json needs a host and a from address, or mail is " +
				"configured in a way that fails at the moment it is used")
	}
	return &notify.Mailer{
		Host: c.Host, From: c.From, Username: c.Username,
		Password: c.Password, Unsubscribe: c.Unsubscribe,
	}, nil
}

func loadHookSecret(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(notifyDir(root), "hook.secret"))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func notifyLoad(root, id string) (*notify.Store, notify.Notice,
	*notify.Audience, error) {

	st, err := notify.OpenStore(notifyDir(root))
	if err != nil {
		return nil, notify.Notice{}, nil, err
	}
	n, err := st.Notice(id)
	if err != nil {
		return nil, notify.Notice{}, nil, err
	}
	a, err := st.Audience()
	if err != nil {
		return nil, notify.Notice{}, nil, err
	}
	return st, n, a, nil
}

// notifyPublish writes the public communication as a draft page.
//
// A draft, and then it stops. Article 34(3)(c) permits a public
// communication only where the people affected are informed "in an equally
// effective manner", and a notice page that fails the accessibility gate is
// not equally effective for somebody reading it with a screen reader. So it
// goes through `quilzo publish` like every other page, with the same gates in
// front of it. Skipping them to save two minutes during an incident would be
// failing the legal test in order to meet it faster.
func notifyPublish(root string, args []string) error {
	pos, _ := leadingArgs(args, 1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo notify publish NOTICE")
	}
	st, err := notify.OpenStore(notifyDir(root))
	if err != nil {
		return err
	}
	n, err := st.Notice(pos[0])
	if err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}
	at := time.Now().UTC()
	page, err := n.Page(at)
	if err != nil {
		return err
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	parent := s.GetRef(site.RefDraft)
	if parent == "" {
		parent = s.GetRef(site.RefLive)
	}
	pages := map[string]any{}
	if parent != "" {
		if pages, err = site.PagesAt(s, parent); err != nil {
			return err
		}
	}
	name := n.PageName()
	pages[name] = page

	// The same two gates every other write passes. A page that reached the
	// store without them is one an author could not have written by hand,
	// and the store is immutable, so an invalid page that lands in it is in
	// the history for good.
	out, xerr := runExtensions(root, ext.OnTransform, name, page)
	if xerr != nil {
		return xerr
	}
	if _, xerr = runExtensions(root, ext.OnValidate, name, out); xerr != nil {
		return xerr
	}
	pages[name] = out
	if _, err := gateWrite(root, pages); err != nil {
		return err
	}

	cid, err := site.SaveDraftFrom(s, pages,
		"public notice "+n.ID, caller.Name, "")
	if err != nil {
		return err
	}

	// Marked as written by a person, because it was. Without this the
	// provenance gate refuses the publish, and discovering that during an
	// incident is the wrong moment for a surprise.
	if err := markNoticeProvenance(root, s, name, caller.Name); err != nil {
		return err
	}

	record(root, audit.Record{
		Action: "notice.public", Resource: "/" + name,
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
		Verified: caller.Kind != audit.KindUnknown,
		Detail: map[string]string{
			"notice": n.ID, "notice_of": string(n.Kind), "page": name,
			"commit": cid,
		},
	})

	if w.JSON(map[string]any{"page": name, "commit": cid}) {
		return nil
	}
	w.Human("%s%s%s written to the draft as %s\n", bold, n.ID, reset, name)
	if n.Kind == notify.Breach && strings.TrimSpace(n.Public) != "" {
		w.Human("  %sthis is the Article 34(3)(c) communication. The reason "+
			"recorded is: %s%s\n", yellow, n.Public, reset)
	} else if n.Kind == notify.Breach {
		w.Human("  %sthis is in addition to the individual notices and does "+
			"not replace them; the Article 34(3)(c) exemption needs a "+
			"reason recorded with --public%s\n", dim, reset)
	}
	w.Human("  %snobody can read it yet. quilzo publish runs the "+
		"accessibility and provenance gates, and a notice page that fails "+
		"them is not the \"equally effective manner\" Article 34(3)(c) "+
		"asks for%s\n", dim, reset)
	return nil
}

// markNoticeProvenance records the page as human-written.
func markNoticeProvenance(root string, s *store.Store, page, author string) error {
	hashes, err := pageHashes(s, site.RefDraft)
	if err != nil {
		return err
	}
	hash, ok := hashes[page]
	if !ok {
		return fmt.Errorf("%s was written and is not in the draft", page)
	}
	idx, err := loadProvenance(root)
	if err != nil {
		return err
	}
	if err := idx.Set(page, provenance.Record{
		ContentHash: hash, SourceType: provenance.HumanEdits, Author: author,
	}); err != nil {
		return err
	}
	return saveJSON(provPath(root), idx)
}

func notifyInbox(root string, args []string) error {
	pos, _ := leadingArgs(args, 1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo notify inbox ISSUER:VALUE")
	}
	id, err := contactID(pos[0])
	if err != nil {
		return err
	}
	st, err := notify.OpenStore(notifyDir(root))
	if err != nil {
		return err
	}
	items, err := st.InboxFor(id)
	if err != nil {
		return err
	}
	if w.JSON(items) {
		return nil
	}
	if len(items) == 0 {
		w.Human("nothing waiting for %s\n", id.String())
		return nil
	}
	for _, item := range items {
		colour := dim
		if item.Urgent {
			colour = red
		}
		w.Human("%s%s%s  %s%s%s  %s\n", bold, item.Subject, reset,
			colour, item.Kind, reset, item.At.Format(time.RFC3339))
		w.Human("  %s%s%s\n", dim, item.Body, reset)
		if !item.Declinable {
			w.Human("  %sthis kind cannot be turned off%s\n", dim, reset)
		}
	}
	return nil
}
