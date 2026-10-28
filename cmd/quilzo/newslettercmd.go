// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/mail"
	"github.com/quilzo/quilzo/internal/newsletter"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/throttle"
)

// The newsletter (internal/newsletter): the list in newsletter/, which the
// site writes and never reads back, and its key at the store's root, which
// the site reads and cannot write. Issues are published pages, sent by a
// person from here or the admin, one message to each confirmed address,
// through the relay in mail.json.

func newsletterDir(root string) string     { return filepath.Join(root, "newsletter") }
func newsletterKeyPath(root string) string { return filepath.Join(root, "newsletter.key") }

// openNewsletter opens the list, making its key the first time. The
// confined site cannot make it, and does not need to: it is made before the
// site is confined (siteconfine.go).
func openNewsletter(root string) (*newsletter.List, error) {
	l, err := newsletter.Open(newsletterDir(root), newsletterKeyPath(root))
	if errors.Is(err, newsletter.ErrNoKey) {
		if err := newsletter.MakeKey(newsletterKeyPath(root)); err != nil {
			return nil, err
		}
		return newsletter.Open(newsletterDir(root), newsletterKeyPath(root))
	}
	return l, err
}

// siteBaseURL is site.base_url, without a trailing slash.
func siteBaseURL(root string) string {
	cfg, err := loadConfig(root)
	if err != nil || cfg == nil {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSpace(cfg.Raw("site.base_url")), "/")
}

// deliverMail sends one message through the relay; a test's own catches
// what would have been sent.
var deliverMail = func(m *mail.Mailer, msg mail.Message) error { return m.Deliver(msg) }

// publicNewsletter is what the site is given: the list, and the relay to
// mail a sign-up its link.
func publicNewsletter(root string) *public.Newsletter {
	list, err := openNewsletter(root)
	if err != nil {
		return nil
	}
	return &public.Newsletter{
		List: list,
		Ready: func() bool {
			m, err := loadMailer(root)
			return err == nil && m != nil
		},
		Mail: func(m mail.Message) error {
			mailer, err := loadMailer(root)
			if err != nil {
				return err
			}
			if mailer == nil {
				return errors.New("no mail is set up (mail.json)")
			}
			return deliverMail(mailer, m)
		},
		Limit: throttle.New(throttlePolicy(mustConfig(root))),
		Audit: func(action, source string, ok bool) {
			outcome := audit.Success
			if !ok {
				outcome = audit.Denied
			}
			if source == "" {
				source = "site"
			}
			// What happened and from where, never to which address: the log
			// outlives the list it would otherwise keep a copy of.
			record(root, audit.Record{Action: action, Resource: "/newsletter", Outcome: outcome,
				Principal: source, Kind: audit.KindUnknown})
		},
		Notify: func(event string) {
			if event == "unsubscribed" {
				go fireWebhooks(root, "unsubscribed", "", nil)
				return
			}
			go fireWebhooks(root, "subscribed", "", nil)
		},
	}
}

// issuePage is a published page an issue can be made from: public now, and
// not for members only. It answers the page and where it is served.
func issuePage(root, name string) (map[string]any, string, error) {
	s, err := store.Open(root)
	if err != nil {
		return nil, "", err
	}
	pages, err := site.PagesAt(s, site.RefLive)
	if err != nil {
		return nil, "", fmt.Errorf("nothing is published yet: %w", err)
	}
	body, ok := site.Visible(pages, time.Now())[name].(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("%q is not a page anybody can read now; an issue is a published page", name)
	}
	if mo, _ := body["members_only"].(bool); mo {
		return nil, "", fmt.Errorf("%q is for members only, and an issue links to the page it is", name)
	}
	path := "/" + name
	if name == "index" {
		path = "/"
	}
	return body, path, nil
}

// newsletterDesignDir is where an issue looks for the site's design: the
// templates directory `quilzo site` and `quilzo serve` use by default.
var newsletterDesignDir = "templates"

// issueSender is everything sending one issue needs.
type issueSender struct {
	list   *newsletter.List
	mailer *mail.Mailer
	letter newsletter.Letter
	base   string
	site   string
	listID string
}

// prepareIssue makes the letter for a page and checks it can be sent:
// mail set up, and the site's https address known, since every link in it
// points there and the one-click unsubscribe must be https.
func prepareIssue(root, page, subject string) (*issueSender, error) {
	mailer, err := loadMailer(root)
	if err != nil {
		return nil, err
	}
	if mailer == nil {
		return nil, errors.New("no mail is set up (mail.json): an issue is sent through your mail relay")
	}
	base := siteBaseURL(root)
	u, err := url.Parse(base)
	if base == "" || err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("site.base_url must be the site's https address: every link in an issue points " +
			"there, and the one-click unsubscribe a mail app offers has to be https")
	}
	body, path, err := issuePage(root, page)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(subject) == "" {
		subject, _ = body["title"].(string)
	}
	if strings.TrimSpace(subject) == "" {
		return nil, errors.New("the page has no title; give the issue a subject")
	}
	list, err := openNewsletter(root)
	if err != nil {
		return nil, err
	}
	name := siteName(root)
	if name == "" {
		name = u.Host
	}
	// The site's own accent for links and buttons, when its design is where
	// the site and the admin look for it by default.
	accent := ""
	if d, err := loadDesign(newsletterDesignDir); err == nil && d.Theme != nil {
		accent, _ = d.Theme.Value("primary", false)
	}
	return &issueSender{list: list, mailer: mailer, base: base, site: name,
		listID: onOneLine(name) + " <newsletter." + u.Hostname() + ">",
		letter: newsletter.Compose(newsletter.Source{Site: name, Base: base, Path: path, Page: body,
			Accent: accent}, subject)}, nil
}

// to sends the letter to one address, with its own way out.
func (is *issueSender) to(addr, id, prefix string) error {
	leave := is.base + "/newsletter/leave?" + url.Values{"s": {id},
		"t": {is.list.Token(newsletter.ForLeave, id)}}.Encode()
	text, page := is.letter.For(leave)
	return deliverMail(is.mailer, mail.Message{To: addr, FromName: is.site, Subject: prefix + is.letter.Subject,
		Body: text, HTML: page, ListID: is.listID, Unsubscribe: leave})
}

// newsletterPace is the time between two messages of an issue: a relay
// that takes a burst of hundreds at once is the exception.
const newsletterPace = 500 * time.Millisecond

// sendRun is one issue this process is sending, and how to stop it.
type sendRun struct {
	stop chan struct{}
	once sync.Once
}

func (r *sendRun) halt() { r.once.Do(func() { close(r.stop) }) }

// sending is the issues this process is sending now.
var (
	sendingMu sync.Mutex
	sending   = map[string]*sendRun{}
)

func issueSending(id string) bool {
	sendingMu.Lock()
	defer sendingMu.Unlock()
	return sending[id] != nil
}

// sendIssue sends an issue, or carries on with one that stopped. In the
// foreground for the command line; the admin runs it in the background.
func sendIssue(root string, is newsletter.Issue, caller *Caller, progress func(newsletter.Issue)) (newsletter.Issue, error) {
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return is, fmt.Errorf("an issue goes to everybody on the list and cannot be taken back, as publishing "+
			"cannot: %w", err)
	}
	snd, err := prepareIssue(root, is.Page, is.Subject)
	if err != nil {
		return is, err
	}
	sendingMu.Lock()
	if sending[is.ID] != nil {
		sendingMu.Unlock()
		return is, errors.New("that issue is being sent now")
	}
	run := &sendRun{stop: make(chan struct{})}
	sending[is.ID] = run
	sendingMu.Unlock()
	defer func() {
		sendingMu.Lock()
		delete(sending, is.ID)
		sendingMu.Unlock()
	}()
	if err := recordE(root, caller.auditRecord("newsletter.send", "/"+is.Page, audit.Success,
		map[string]string{"issue": is.ID})); err != nil {
		return is, err
	}
	done, err := snd.list.Send(is.ID, caller.Name, func(s newsletter.Subscriber) error {
		return snd.to(s.Email, s.ID, "")
	}, newsletterPace, time.Now, run.stop, progress)
	outcome := audit.Success
	if err != nil || done.State != newsletter.Sent {
		outcome = audit.Failure
	}
	record(root, caller.auditRecord("newsletter.sent", "/"+is.Page, outcome, map[string]string{
		"issue": is.ID, "sent": fmt.Sprint(done.Sent), "of": fmt.Sprint(done.To), "refused": fmt.Sprint(done.Failed)}))
	return done, err
}

// startIssue begins an issue a person sends: a new one, or one an agent
// proposed.
func startIssue(root, page, subject, proposed string, caller *Caller) (newsletter.Issue, error) {
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return newsletter.Issue{}, fmt.Errorf("an issue goes to everybody on the list and cannot be taken back, "+
			"as publishing cannot: %w", err)
	}
	list, err := openNewsletter(root)
	if err != nil {
		return newsletter.Issue{}, err
	}
	if proposed != "" {
		is, err := list.Issue(proposed)
		if err != nil {
			return is, err
		}
		if page != "" && page != is.Page {
			// Another page was chosen after the proposal was opened: that
			// page is what the person decided to send.
			return startIssue(root, page, subject, "", caller)
		}
		if is.State != newsletter.Proposed {
			return is, fmt.Errorf("issue %s is %s, not waiting to be sent", is.ID, is.State)
		}
		if strings.TrimSpace(subject) != "" {
			is.Subject = subject
		}
		// Checked before it is marked as sending: the page may have been
		// unpublished since the agent proposed it.
		if _, err := prepareIssue(root, is.Page, is.Subject); err != nil {
			return is, err
		}
		is.State, is.SentBy = newsletter.Sending, caller.Name
		return is, list.SaveIssue(is)
	}
	snd, err := prepareIssue(root, page, subject)
	if err != nil {
		return newsletter.Issue{}, err
	}
	return list.NewIssue(page, snd.letter.Subject, newsletter.Sending, caller.Name, "", time.Now())
}

// testIssue sends one copy to one address, marked as a test.
func testIssue(root, page, subject, to string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActEditDraft, "/"+page); err != nil {
		return fmt.Errorf("a test of an issue is sent by whoever may edit the page: %w", err)
	}
	addr, err := newsletter.Normalize(to)
	if err != nil {
		return err
	}
	snd, err := prepareIssue(root, page, subject)
	if err != nil {
		return err
	}
	if err := snd.to(addr, snd.list.ID(addr), "[Test] "); err != nil {
		return err
	}
	// To whom is not recorded: a test goes to the person sending it.
	return recordE(root, caller.auditRecord("newsletter.test", "/"+page, audit.Success, nil))
}

// addSubscriber signs an address up for the site's staff: it is mailed the
// same link a sign-up on the site is, and joins when it says yes.
func addSubscriber(root, addr string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return fmt.Errorf("the list is kept by whoever reads what forms collect: %w", err)
	}
	mailer, err := loadMailer(root)
	if err != nil {
		return err
	}
	if mailer == nil {
		return errors.New("no mail is set up (mail.json), so the address cannot be asked")
	}
	base := siteBaseURL(root)
	if base == "" {
		return errors.New("site.base_url is not set, so there is no page for the link to open")
	}
	list, err := openNewsletter(root)
	if err != nil {
		return err
	}
	name := siteName(root)
	if name == "" {
		name = "this site"
	}
	s, outcome, err := list.SignUp(newsletter.Subscriber{Email: addr, Source: "added",
		Consent: name + "'s newsletter, asked by the site's staff and confirmed by the address"}, time.Now())
	if err != nil {
		return err
	}
	if outcome == newsletter.Mail {
		link := base + "/newsletter/confirm?" + url.Values{"s": {s.ID},
			"t": {list.Token(newsletter.ForConfirm, s.ID)}}.Encode()
		body := name + " would like to send you its newsletter.\n\nTo say yes, open this link and press the " +
			"button on the page:\n" + link + "\n\nIf you would rather not, there is nothing to do: nothing more is " +
			"sent, and the address is forgotten in a week.\n"
		if err := deliverMail(mailer, mail.Message{To: s.Email, FromName: name,
			Subject: "Would you like " + name + "'s newsletter?", Body: body}); err != nil {
			list.Unsent(s.ID, time.Now())
			return err
		}
	}
	return recordE(root, caller.auditRecord("newsletter.added", "/newsletter", audit.Success,
		map[string]string{"asked": fmt.Sprint(outcome == newsletter.Mail)}))
}

// removeSubscriber takes an address off the list, by address or id, and
// keeps it from being imported back.
func removeSubscriber(root, who string, caller *Caller) (bool, error) {
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return false, fmt.Errorf("the list is kept by whoever reads what forms collect: %w", err)
	}
	list, err := openNewsletter(root)
	if err != nil {
		return false, err
	}
	id := who
	if !newsletter.ValidID(who) {
		addr, err := newsletter.Normalize(who)
		if err != nil {
			return false, err
		}
		id = list.ID(addr)
	}
	was, err := list.Remove(id, time.Now())
	if err != nil {
		return false, err
	}
	if err := recordE(root, caller.auditRecord("newsletter.removed", "/newsletter", audit.Success,
		map[string]string{"subscriber": id})); err != nil {
		return was, err
	}
	if was {
		go fireWebhooks(root, "unsubscribed", "", nil)
	}
	return was, nil
}

// importSubscribers puts a list from another platform on this one.
func importSubscribers(root string, r io.Reader, agreed string, caller *Caller) (newsletter.Imported, error) {
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return newsletter.Imported{}, fmt.Errorf("an import decides who the next issue goes to, as "+
			"publishing decides what is read: %w", err)
	}
	agreed = strings.TrimSpace(agreed)
	if agreed == "" {
		return newsletter.Imported{}, errors.New("say where these people agreed to get the newsletter, such as " +
			"\"signed up on our Mailchimp form\": they are added as having said yes, and that is the record of it")
	}
	rows, err := newsletter.ReadCSV(io.LimitReader(r, 32<<20))
	if err != nil {
		return newsletter.Imported{}, err
	}
	list, err := openNewsletter(root)
	if err != nil {
		return newsletter.Imported{}, err
	}
	got, err := list.Import(rows, "Imported "+time.Now().UTC().Format("2 January 2006")+"; "+agreed, time.Now())
	if err != nil {
		return got, err
	}
	return got, recordE(root, caller.auditRecord("newsletter.import", "/newsletter", audit.Success,
		map[string]string{"added": fmt.Sprint(got.Added), "left": fmt.Sprint(got.Left),
			"already": fmt.Sprint(got.Already), "skipped": fmt.Sprint(got.Skipped + got.Bad)}))
}

// exportSubscribers writes the confirmed list as a file other platforms
// import.
func exportSubscribers(root string, w io.Writer, caller *Caller) (int, error) {
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return 0, fmt.Errorf("the list is read by whoever reads what forms collect: %w", err)
	}
	list, err := openNewsletter(root)
	if err != nil {
		return 0, err
	}
	all, err := list.All()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, s := range all {
		if !s.Confirmed.IsZero() {
			n++
		}
	}
	if err := newsletter.WriteCSV(w, all); err != nil {
		return n, err
	}
	return n, recordE(root, caller.auditRecord("newsletter.export", "/newsletter", audit.Success,
		map[string]string{"addresses": fmt.Sprint(n)}))
}

// newsletterProblems is what stops the site taking sign-ups or sending
// issues, as a person fixes it.
func newsletterProblems(root string) []string {
	var out []string
	if m, err := loadMailer(root); err != nil {
		out = append(out, "Mail is set up wrongly: "+err.Error())
	} else if m == nil {
		out = append(out, "No mail is set up, so the site cannot mail a sign-up its link. Put your relay in mail.json "+
			"(quilzo help mail).")
	}
	base := siteBaseURL(root)
	if u, err := url.Parse(base); base == "" || err != nil || u.Scheme != "https" {
		out = append(out, "site.base_url is not the site's https address, so links in mail cannot point to it. "+
			"Set it under Settings.")
	}
	return out
}

// cmdNewsletter is `quilzo newsletter …`.
func cmdNewsletter(root string, args []string) error {
	return newsletterCmd(root, args, resolveCaller(root, flagToken))
}

func newsletterCmd(root string, args []string, caller *Caller) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		return newsletterStatus(root, caller)
	case "list":
		return newsletterList(root, args[1:], caller)
	case "add":
		if len(args) != 2 {
			return errors.New("usage: quilzo newsletter add ADDRESS")
		}
		if err := addSubscriber(root, args[1], caller); err != nil {
			return err
		}
		w.Human("asked: it joins when it says yes from the link mailed to it\n")
		return nil
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: quilzo newsletter remove ADDRESS|ID")
		}
		was, err := removeSubscriber(root, args[1], caller)
		if err != nil {
			return err
		}
		if !was {
			w.Human("it was not on the list; it is kept from being imported now\n")
			return nil
		}
		w.Human("removed and deleted; it is kept from being imported back\n")
		return nil
	case "import":
		return newsletterImport(root, args[1:], caller)
	case "export":
		return newsletterExport(root, args[1:], caller)
	case "test":
		return newsletterTest(root, args[1:], caller)
	case "send":
		return newsletterSend(root, args[1:], caller)
	case "issues":
		return newsletterIssues(root, caller)
	case "dismiss":
		if len(args) != 2 {
			return errors.New("usage: quilzo newsletter dismiss ISSUE")
		}
		return dismissIssue(root, args[1], caller)
	default:
		return fmt.Errorf("unknown newsletter command %q; try status, list, add, remove, import, export, test, "+
			"send, issues or dismiss", args[0])
	}
}

func newsletterStatus(root string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	list, err := openNewsletter(root)
	if err != nil {
		return err
	}
	c, err := list.Count()
	if err != nil {
		return err
	}
	problems := newsletterProblems(root)
	if w.JSON(map[string]any{"counts": c, "problems": problems}) {
		return nil
	}
	w.Human("%d subscribed, %d waiting to confirm, %d left\n", c.Subscribed, c.Waiting, c.Left)
	for _, p := range problems {
		w.Human("%s%s%s\n", yellow, p, reset)
	}
	if len(problems) == 0 {
		w.Human("%sa page takes sign-ups with a newsletter section; quilzo newsletter send PAGE sends it%s\n", dim, reset)
	}
	return nil
}

func newsletterList(root string, args []string, caller *Caller) error {
	fs := flag.NewFlagSet("newsletter list", flag.ContinueOnError)
	all := fs.Bool("all", false, "those waiting to confirm as well")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return fmt.Errorf("the list is read by whoever reads what forms collect: %w", err)
	}
	list, err := openNewsletter(root)
	if err != nil {
		return err
	}
	subs, err := list.All()
	if err != nil {
		return err
	}
	var shown []newsletter.Subscriber
	for _, s := range subs {
		if *all || !s.Confirmed.IsZero() {
			shown = append(shown, s)
		}
	}
	if w.JSON(map[string]any{"subscribers": shown}) {
		return nil
	}
	if len(shown) == 0 {
		w.Human("nobody is on the list yet\n")
		return nil
	}
	for _, s := range shown {
		state := ""
		if s.Confirmed.IsZero() {
			state = fmt.Sprintf(" %swaiting to confirm%s", dim, reset)
		}
		w.Human("%s  %s  since %s, %s%s\n", s.ID, s.Email, s.At.Format("2 Jan 2006"), s.Source, state)
	}
	return nil
}

func newsletterImport(root string, args []string, caller *Caller) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("newsletter import", flag.ContinueOnError)
	agreed := fs.String("agreed", "", "where these people agreed to get the newsletter")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: quilzo newsletter import FILE.csv --agreed \"where they signed up\"")
	}
	f, err := os.Open(pos[0])
	if err != nil {
		return err
	}
	defer f.Close()
	got, err := importSubscribers(root, f, *agreed, caller)
	if err != nil {
		return err
	}
	if w.JSON(got) {
		return nil
	}
	w.Human("added %d; %d already here; %d kept as having left, so never sent to; %d skipped as never confirmed "+
		"or not an address\n", got.Added, got.Already, got.Left, got.Skipped+got.Bad)
	return nil
}

func newsletterExport(root string, args []string, caller *Caller) error {
	var buf bytes.Buffer
	n, err := exportSubscribers(root, &buf, caller)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		_, err := os.Stdout.Write(buf.Bytes())
		return err
	}
	if err := os.WriteFile(args[0], buf.Bytes(), 0o600); err != nil {
		return err
	}
	w.Human("wrote %d addresses to %s, as a file other newsletter services import\n", n, args[0])
	return nil
}

func newsletterTest(root string, args []string, caller *Caller) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("newsletter test", flag.ContinueOnError)
	to := fs.String("to", "", "the address to send the test to")
	subject := fs.String("subject", "", "the subject; the page's title when not given")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 || *to == "" {
		return errors.New("usage: quilzo newsletter test PAGE --to ADDRESS [--subject S]")
	}
	if err := testIssue(root, pos[0], *subject, *to, caller); err != nil {
		return err
	}
	w.Human("sent a test of %q to %s\n", pos[0], *to)
	return nil
}

func newsletterSend(root string, args []string, caller *Caller) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("newsletter send", flag.ContinueOnError)
	subject := fs.String("subject", "", "the subject; the page's title when not given")
	issue := fs.String("issue", "", "send an issue an agent proposed, or carry on with one that stopped")
	yes := fs.Bool("yes", false, "send it; without this, only say who it would go to")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 && *issue == "" {
		return errors.New("usage: quilzo newsletter send PAGE [--subject S] --yes, or --issue ID --yes")
	}
	list, err := openNewsletter(root)
	if err != nil {
		return err
	}
	ids, err := list.ConfirmedIDs()
	if err != nil {
		return err
	}
	page := ""
	if len(pos) == 1 {
		page = pos[0]
	}
	if !*yes {
		if *issue == "" {
			if _, err := prepareIssue(root, page, *subject); err != nil {
				return err
			}
		}
		w.Human("this would go to %d confirmed address(es) and cannot be taken back. Send yourself one first "+
			"(quilzo newsletter test PAGE --to YOU), then run this again with --yes\n", len(ids))
		return nil
	}
	var is newsletter.Issue
	if *issue != "" {
		is, err = list.Issue(*issue)
		if err == nil && is.State == newsletter.Proposed {
			is, err = startIssue(root, "", *subject, *issue, caller)
		}
	} else {
		is, err = startIssue(root, page, *subject, "", caller)
	}
	if err != nil {
		return err
	}
	w.Human("sending %q to %d address(es)…\n", is.Subject, len(ids))
	done, err := sendIssue(root, is, caller, nil)
	if err != nil {
		return fmt.Errorf("%w; quilzo newsletter send --issue %s --yes carries on where it stopped", err, is.ID)
	}
	w.Human("sent to %d of %d%s\n", done.Sent, done.To, map[bool]string{true: fmt.Sprintf("; %d refused, the "+
		"last: %s", done.Failed, done.Problem), false: ""}[done.Failed > 0])
	return nil
}

func newsletterIssues(root string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActView, "/"); err != nil {
		return err
	}
	list, err := openNewsletter(root)
	if err != nil {
		return err
	}
	all, err := list.Issues()
	if err != nil {
		return err
	}
	for i := range all {
		if all[i].State == newsletter.Sending && !issueSending(all[i].ID) {
			all[i].State = newsletter.Stopped
		}
	}
	if w.JSON(map[string]any{"issues": all}) {
		return nil
	}
	if len(all) == 0 {
		w.Human("no issues yet\n")
		return nil
	}
	for _, is := range all {
		switch is.State {
		case newsletter.Proposed:
			w.Human("%s  %s  %q, page %s, proposed by %s\n", is.ID, is.State, is.Subject, is.Page, is.By)
		default:
			w.Human("%s  %s  %q, page %s, %d of %d\n", is.ID, is.State, is.Subject, is.Page, is.Sent, is.To)
		}
	}
	return nil
}

// dismissIssue sets aside an issue an agent proposed.
func dismissIssue(root, id string, caller *Caller) error {
	if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
		return fmt.Errorf("a proposed issue is dismissed by whoever may send one: %w", err)
	}
	list, err := openNewsletter(root)
	if err != nil {
		return err
	}
	is, err := list.Issue(id)
	if err != nil {
		return err
	}
	if is.State != newsletter.Proposed {
		return fmt.Errorf("issue %s is %s; only a proposed issue is dismissed", id, is.State)
	}
	is.State = newsletter.Dismissed
	if err := list.SaveIssue(is); err != nil {
		return err
	}
	return recordE(root, caller.auditRecord("newsletter.dismissed", "/"+is.Page, audit.Success,
		map[string]string{"issue": id}))
}

// proposeIssue is an agent proposing an issue for a person to send.
func proposeIssue(root, page, subject, note string, caller *Caller) (newsletter.Issue, error) {
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return newsletter.Issue{}, err
	}
	body, _, err := issuePage(root, page)
	if err != nil {
		return newsletter.Issue{}, err
	}
	if strings.TrimSpace(subject) == "" {
		subject, _ = body["title"].(string)
	}
	list, err := openNewsletter(root)
	if err != nil {
		return newsletter.Issue{}, err
	}
	is, err := list.NewIssue(page, subject, newsletter.Proposed, caller.Name, note, time.Now())
	if err != nil {
		return is, err
	}
	return is, recordE(root, caller.auditRecord("newsletter.proposed", "/"+page, audit.Success,
		map[string]string{"issue": is.ID}))
}

// newsletterHooks are the admin's way to the list.
func newsletterHooks(root string, signedIn func(admin.Actor) *Caller) *admin.NewsletterHooks {
	return &admin.NewsletterHooks{
		Problems: func() []string { return newsletterProblems(root) },
		Counts: func() (newsletter.Counts, error) {
			list, err := openNewsletter(root)
			if err != nil {
				return newsletter.Counts{}, err
			}
			return list.Count()
		},
		List: func() ([]newsletter.Subscriber, error) {
			list, err := openNewsletter(root)
			if err != nil {
				return nil, err
			}
			return list.All()
		},
		Issues: func() ([]newsletter.Issue, error) {
			list, err := openNewsletter(root)
			if err != nil {
				return nil, err
			}
			all, err := list.Issues()
			for i := range all {
				if all[i].State == newsletter.Sending && !issueSending(all[i].ID) {
					all[i].State = newsletter.Stopped
				}
			}
			return all, err
		},
		Pages: func() ([]string, error) {
			s, err := store.Open(root)
			if err != nil {
				return nil, err
			}
			pages, err := site.PagesAt(s, site.RefLive)
			if err != nil {
				return nil, nil
			}
			var out []string
			for name, body := range site.Visible(pages, time.Now()) {
				if m, ok := body.(map[string]any); ok {
					if mo, _ := m["members_only"].(bool); !mo {
						out = append(out, name)
					}
				}
			}
			return out, nil
		},
		Add:    func(addr string, by admin.Actor) error { return addSubscriber(root, addr, signedIn(by)) },
		Remove: func(id string, by admin.Actor) (bool, error) { return removeSubscriber(root, id, signedIn(by)) },
		Import: func(r io.Reader, agreed string, by admin.Actor) (newsletter.Imported, error) {
			return importSubscribers(root, r, agreed, signedIn(by))
		},
		Export: func(wr io.Writer, by admin.Actor) (int, error) { return exportSubscribers(root, wr, signedIn(by)) },
		Test: func(page, subject, to string, by admin.Actor) error {
			return testIssue(root, page, subject, to, signedIn(by))
		},
		Send: func(page, subject, proposed string, by admin.Actor) (newsletter.Issue, error) {
			caller := signedIn(by)
			is, err := startIssue(root, page, subject, proposed, caller)
			if err != nil {
				return is, err
			}
			go func() { _, _ = sendIssue(root, is, caller, nil) }()
			return is, nil
		},
		Continue: func(id string, by admin.Actor) error {
			caller := signedIn(by)
			list, err := openNewsletter(root)
			if err != nil {
				return err
			}
			is, err := list.Issue(id)
			if err != nil {
				return err
			}
			if is.State == newsletter.Proposed || is.State == newsletter.Dismissed || issueSending(id) {
				return fmt.Errorf("issue %s is not one that stopped", id)
			}
			if err := authorise(root, caller, auth.ActPublish, "/"); err != nil {
				return err
			}
			go func() { _, _ = sendIssue(root, is, caller, nil) }()
			return nil
		},
		Stop: func(id string, by admin.Actor) error {
			if err := authorise(root, signedIn(by), auth.ActPublish, "/"); err != nil {
				return err
			}
			sendingMu.Lock()
			defer sendingMu.Unlock()
			if run := sending[id]; run != nil {
				run.halt()
				return nil
			}
			return fmt.Errorf("issue %s is not being sent", id)
		},
		Dismiss: func(id string, by admin.Actor) error { return dismissIssue(root, id, signedIn(by)) },
	}
}
