// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/store"
)

// The design and the settings, read again without a restart.
//
// Both servers read templates/ and the configuration once, when they
// started, and kept what they read. So a typeface added to templates/fonts/
// was refused by the admin's Design screen — "this site does not serve a font
// by that name" — until `quilzo serve` restarted, and `site.events` set by
// `quilzo events setup` did nothing on the public site until `quilzo site`
// restarted. The advice was to restart both after any change, which is advice
// nobody remembers until the second time.
//
// # When each server reads them again
//
// The admin reads the design again when templates/ or templates/fonts/
// changes, looked at no more than once a second as requests arrive, and on
// SIGHUP. Its settings were already read when they are used.
//
// The public site reads its settings again when the configuration, the
// listings or the languages change, looked at the same way, and reads both
// the design and the settings when a publish moves the pages it serves, and
// on SIGHUP.
//
// The site does not take a design change the moment the file changes, and
// that is deliberate. The publish gate is what holds the design to the
// standard: it computes every contrast pair the theme makes, and renders
// every page through the layouts to check them. `quilzo theme set --force`
// saves a palette that fails and says the gate will refuse it. A site that
// served whatever templates/ held a second after it was written would put
// that palette in front of readers without the gate ever running. So the
// design reaches readers with the publish the gate passed, or when somebody
// running the site says so with SIGHUP — the same say-so a restart was.
//
// # What a reload keeps
//
// What a visitor is in the middle of. A rebuilt site keeps the previous
// one's rate limits and their counts, the signals it is counting, its
// sign-in ceremonies, its chatbots' rating keys, the newsletter's hourly
// count and the fediverse delivery queue (carrySiteState). Rebuilding those
// would hand every visitor a fresh allowance whenever somebody published,
// which is a limit that resets on a schedule an attacker can watch. The
// settings behind them therefore take effect at the next restart, and the
// documentation says which.
//
// # A reload that fails
//
// Changes nothing. A layout that does not parse, a theme file that is not
// JSON, a setting the site refuses at start, a configuration file caught
// empty while it is being written (configSays): the site goes on serving what
// it served, says why on its error output and in the audit log, and does not
// try again until something changes again. A server that went down because
// somebody saved a file half-edited would make every save a risk. A publish
// whose build was refused for any of those but its own design brings that
// design with the next build that succeeds.

// lookEvery is the most often a server looks at the files on disk. A stat
// of a handful of files is microseconds; doing it once a second rather than
// on every request is so a busy site is not a busy disk.
const lookEvery = time.Second

// The reasons a site is built again, as the audit log records them.
const (
	reloadPublish  = "publish"
	reloadSettings = "settings"
	reloadSignal   = "signal"
)

// dirState is how the files in some directories stand, without reading
// them: each regular file's name, size and modification time. A missing
// directory is a state of its own, so making one is a change.
func dirState(dirs ...string) string {
	var b strings.Builder
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Fprintf(&b, "%s -\n", dir)
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			fmt.Fprintf(&b, "%s/%s %d %d\n", dir, e.Name(), fi.Size(), fi.ModTime().UnixNano())
		}
	}
	return b.String()
}

// filesState is dirState for named files.
//
// Size as well as time, for the reason tokenReloader gives: a same-second
// rewrite of a nearly same-size file is the case modification time alone
// misses.
func filesState(paths ...string) string {
	var b strings.Builder
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(&b, "%s -\n", p)
			continue
		}
		fmt.Fprintf(&b, "%s %d %d\n", p, fi.Size(), fi.ModTime().UnixNano())
	}
	return b.String()
}

// designDigest is a design as readers receive it, as one hash: every layout,
// the stylesheet and every face. Two readings that hash the same are the same
// design, so a reload that changed nothing is not reported as a change.
func designDigest(d *Design) string {
	if d == nil {
		return ""
	}
	h := sha256.New()
	for _, name := range d.Layouts.Names() {
		src, _ := d.Layouts.Source(name)
		fmt.Fprintf(h, "layout %s %d\n%s", name, len(src), src)
	}
	fmt.Fprintf(h, "stylesheet %d\n%s", len(d.Stylesheet), d.Stylesheet)
	for _, f := range d.Fonts.Faces() {
		fmt.Fprintf(h, "face %s %d\n", f.File, len(f.Bytes))
		h.Write(f.Bytes)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// siteSettingsFiles are the files the public site's settings are read from
// when it is built: the configuration, the declared listings (which name the
// events, the blog and the catalogue) and the languages. Everything else it
// serves from the store is read per request already.
func siteSettingsFiles(root string) []string {
	return []string{configPath(root), listingPath(root), localesPath(root)}
}

// settingsDigest is those files' contents, as one hash.
func settingsDigest(root string) string {
	h := sha256.New()
	for _, p := range siteSettingsFiles(root) {
		b, err := os.ReadFile(p)
		fmt.Fprintf(h, "%s %d %v\n", filepath.Base(p), len(b), err == nil)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// designWatch is the admin's design, read again when its directory changes.
type designWatch struct {
	dir   string
	every time.Duration
	now   func() time.Time
	// apply is told each design read, so the server renders with it.
	apply func(*Design)
	// say is where a reload that failed, and the notes of one that did not,
	// are written: the admin's error output.
	say func(format string, a ...any)

	cur atomic.Pointer[Design]

	mu     sync.Mutex
	seen   string
	looked time.Time
}

func newDesignWatch(dir string, d *Design, apply func(*Design)) *designWatch {
	dw := &designWatch{dir: dir, every: lookEvery, now: time.Now, apply: apply,
		say: func(format string, a ...any) { fmt.Fprintf(os.Stderr, format, a...) }}
	if d == nil {
		d = &Design{}
	}
	dw.cur.Store(d)
	dw.seen = dw.state()
	return dw
}

func (dw *designWatch) state() string {
	return dirState(dw.dir, filepath.Join(dw.dir, "fonts"))
}

// Current is the design as last read.
func (dw *designWatch) Current() *Design { return dw.cur.Load() }

// Check reads the design again if its directory has changed since it was
// last looked at, at most once every dw.every. A request that arrives while
// another is reading it carries on with the design there is.
func (dw *designWatch) Check() {
	if !dw.mu.TryLock() {
		return
	}
	defer dw.mu.Unlock()
	now := dw.now()
	if now.Sub(dw.looked) < dw.every {
		return
	}
	dw.looked = now
	if st := dw.state(); st != dw.seen {
		dw.seen = st
		_ = dw.load()
	}
}

// Reload reads the design again whatever the directory says: SIGHUP.
func (dw *designWatch) Reload() error {
	dw.mu.Lock()
	defer dw.mu.Unlock()
	dw.seen = dw.state()
	return dw.load()
}

func (dw *designWatch) load() error {
	d, err := loadDesign(dw.dir)
	if err != nil {
		dw.say("  %sthe design in %s was not read again: %v. The one read before "+
			"is still in use%s\n", yellow, dw.dir, err, reset)
		return err
	}
	for _, note := range d.Notes {
		dw.say("  %s%s%s\n", dim, note, reset)
	}
	dw.cur.Store(d)
	if dw.apply != nil {
		dw.apply(d)
	}
	return nil
}

// Wrap checks the design before each request is served.
func (dw *designWatch) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dw.Check()
		next.ServeHTTP(w, r)
	})
}

// adminDesignHooks is how the Design screen reads and changes the design in
// dir, answering from the design as dw last read it.
func adminDesignHooks(dir string, dw *designWatch) *admin.Design {
	return &admin.Design{
		Dir:     dir,
		Tokens:  func() (map[string]string, error) { return loadThemeFile(dir) },
		Save:    func(values map[string]string) error { return writeThemeFile(dir, values) },
		Layouts: func() []string { return dw.Current().Layouts.Names() },
		Fonts:   func() []string { return dw.Current().Fonts.Names() },
		FontFile: func(name string) ([]byte, bool) {
			d := dw.Current()
			if d.Fonts == nil {
				return nil, false
			}
			return d.Fonts.File(name)
		},
		OwnStylesheet: func() bool {
			return fileExists(filepath.Join(dir, "site.css"))
		},
		InstallLayout: func(name string) ([]string, error) {
			return installStarter(dir, name)
		},
		// The same operation as `quilzo theme font add` (themefont.go). Read
		// again straight after, so the screen it returns to lists the face.
		AddFont: func(filename string, body []byte, name string, replace bool) (admin.FontAdded, error) {
			added, err := addFont(dir, filename, body, name, replace)
			if err != nil {
				return admin.FontAdded{}, err
			}
			_ = dw.Reload()
			return added.FontAdded, nil
		},
	}
}

// siteGen is one build of what the public site serves.
type siteGen struct {
	st      *public.Site
	handler http.Handler
	design  *Design
	// designSum and settingsSum are what it was built from, so the next
	// build can say whether anything a reader gets changed.
	designSum, settingsSum string
	// configSaid is that it was built from a configuration file that said
	// something (configSays).
	configSaid bool
}

// siteReloader serves the public site and builds it again when its
// settings change, when a publish moves what it serves, and on SIGHUP.
type siteReloader struct {
	root string
	// dir is the template directory the site was started with.
	dir   string
	store *store.Store
	// ref is the ref this server serves: live, or an environment's.
	ref string
	// build makes a site from a design, keeping what the previous one holds
	// that must outlive it (carrySiteState).
	build func(d *Design, prev *public.Site) (*public.Site, error)
	every time.Duration
	now   func() time.Time
	say   func(format string, a ...any)

	gen atomic.Pointer[siteGen]

	mu     sync.Mutex
	live   string
	files  string
	looked time.Time
	// designDue is a publish whose design has not reached readers yet,
	// because the build it came with was refused for a reason that was not
	// the design: the next build that succeeds takes it.
	designDue bool
}

func newSiteReloader(root, dir string, s *store.Store, ref string, d *Design, st *public.Site,
	build func(*Design, *public.Site) (*public.Site, error)) *siteReloader {

	rl := &siteReloader{root: root, dir: dir, store: s, ref: ref, build: build,
		every: lookEvery, now: time.Now,
		say: func(format string, a ...any) { fmt.Fprintf(os.Stderr, format, a...) }}
	rl.gen.Store(&siteGen{st: st, handler: st.Handler(), design: d,
		designSum: designDigest(d), settingsSum: settingsDigest(root), configSaid: configSays(root)})
	rl.live = s.GetRef(ref)
	rl.files = filesState(siteSettingsFiles(root)...)
	return rl
}

// Site is the site being served now.
func (rl *siteReloader) Site() *public.Site { return rl.gen.Load().st }

// ServeHTTP serves a request from the site as it is now, after looking
// whether it should be built again.
func (rl *siteReloader) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rl.Check()
	rl.gen.Load().handler.ServeHTTP(w, r)
}

// Check builds the site again when a publish has moved what it serves, or,
// at most once every rl.every, when its settings files have changed.
//
// The request that notices does the building and is served by the result;
// requests arriving meanwhile are served by the site there is.
func (rl *siteReloader) Check() {
	// The ref is a small file the site reads several times a request already;
	// a publish is noticed by the first request after it.
	live := rl.store.GetRef(rl.ref)
	if !rl.mu.TryLock() {
		return
	}
	defer rl.mu.Unlock()
	now := rl.now()
	if live != rl.live {
		rl.live, rl.looked = live, now
		rl.files = filesState(siteSettingsFiles(rl.root)...)
		_ = rl.reload(reloadPublish)
		return
	}
	if now.Sub(rl.looked) < rl.every {
		return
	}
	rl.looked = now
	if st := filesState(siteSettingsFiles(rl.root)...); st != rl.files {
		rl.files = st
		_ = rl.reload(reloadSettings)
	}
}

// Reload builds the site again from the design and settings on disk, whatever
// has or has not changed: SIGHUP, which is how a service manager says reload.
func (rl *siteReloader) Reload() error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.live = rl.store.GetRef(rl.ref)
	rl.files = filesState(siteSettingsFiles(rl.root)...)
	rl.looked = rl.now()
	return rl.reload(reloadSignal)
}

// reload builds one generation. Called with rl.mu held.
func (rl *siteReloader) reload(trigger string) error {
	cur := rl.gen.Load()
	design := cur.design
	var designErr error
	// The design only with a publish, which the gate has passed, or when
	// told: see the comment at the top of this file.
	withDesign := trigger != reloadSettings || rl.designDue
	refused := func(err error) error {
		rl.say("  %sthe site was not rebuilt (%s): %v. It is serving what it served "+
			"before%s\n", yellow, trigger, err, reset)
		rl.record(trigger, audit.Failure, map[string]string{"why": err.Error()})
		// The publish's design waits for the next build that succeeds,
		// rather than for the next publish.
		rl.designDue = rl.designDue || withDesign
		return err
	}
	says := configSays(rl.root)
	if cur.configSaid && !says && fileExists(configPath(rl.root)) {
		return refused(fmt.Errorf("%s is empty, which is how a file looks while it is being "+
			"written, so the site keeps the settings it has. Write {} to it, or remove it, "+
			"to put every setting back to its default", configPath(rl.root)))
	}
	if withDesign {
		if d, err := loadDesign(rl.dir); err != nil {
			designErr = err
		} else {
			design = d
		}
	}
	st, err := rl.build(design, cur.st)
	if err != nil {
		return refused(err)
	}
	next := &siteGen{st: st, handler: st.Handler(), design: design,
		designSum: designDigest(design), settingsSum: settingsDigest(rl.root), configSaid: says}
	rl.gen.Store(next)
	// Taken, or tried and not readable: a design that does not read waits
	// for the next publish or SIGHUP, as it did.
	rl.designDue = false

	detail := map[string]string{
		"design":   changedOrSame(cur.designSum, next.designSum),
		"settings": changedOrSame(cur.settingsSum, next.settingsSum),
	}
	if designErr != nil {
		detail["design"] = "kept"
		detail["why"] = designErr.Error()
		rl.say("  %sthe design in %s was not read again: %v. The site keeps the one "+
			"it had%s\n", yellow, rl.dir, designErr, reset)
		rl.record(trigger, audit.Failure, detail)
		return designErr
	}
	if detail["design"] == "changed" {
		for _, note := range design.Notes {
			rl.say("  %s%s%s\n", dim, note, reset)
		}
	}
	// A reload that changed nothing a reader gets is not news, unless
	// somebody asked for it.
	if detail["design"] == "changed" || detail["settings"] == "changed" || trigger == reloadSignal {
		rl.say("  %ssite rebuilt (%s): design %s, settings %s%s\n", dim, trigger,
			detail["design"], detail["settings"], reset)
		rl.record(trigger, audit.Success, detail)
	}
	return nil
}

// configSays reports whether the configuration file says anything: it is
// there and it is not blank.
//
// config.Parse reads a blank file as every setting at its default, which is
// right for a file somebody emptied on purpose and wrong for one caught
// between being truncated and being written, which is what `>`, `cp` and an
// editor that writes in place all leave for a moment. A running site that
// read its settings in that moment lost its classification banner, its
// Strict-Transport-Security and its security.txt, and recorded the change as
// a success. So a site built from a configuration that said something does
// not take a blank one as the next (siteReloader.reload); `{}` or no file at
// all is how to ask for the defaults.
func configSays(root string) bool {
	b, err := os.ReadFile(configPath(root))
	return err == nil && len(bytes.TrimSpace(b)) > 0
}

func changedOrSame(before, after string) string {
	if before == after {
		return "same"
	}
	return "changed"
}

// record writes a reload to the audit log: the moment a change to the design
// or the settings reached readers, which is the moment an incident review
// asks about.
func (rl *siteReloader) record(trigger string, outcome audit.Outcome, detail map[string]string) {
	d := map[string]string{"trigger": trigger}
	for k, v := range detail {
		d[k] = v
	}
	if live := rl.live; live != "" {
		d["commit"] = live
	}
	record(rl.root, audit.Record{Action: "site.reload", Resource: "/", Outcome: outcome,
		Principal: "quilzo", Kind: audit.KindService, Verified: true, Detail: d})
}

// carrySiteState moves what a running site holds for its visitors from the
// site it was to the site it is becoming.
//
// What is carried is state, not settings: rate limits and their counts, the
// signals being counted, sign-in ceremonies in progress, the chatbots' keys
// for the ratings they handed out and the ones already used, and which pages
// are new to them, the newsletter's count of mail sent this hour, and the
// fediverse queue with the loop that empties it. A part turned off by the new settings stays off
// (nil): turning something off takes effect at once. A part turned on is
// new.
//
// The accounts are carried whole only while their mode and their relying
// party are what they were, because those decide who may sign in; when
// either changes, the new ones are used with the old store, limits and
// lockouts, so a change of mode cannot clear a lockout.
func carrySiteState(prev, next *public.Site) {
	if prev == nil || next == nil {
		return
	}
	// Started once with the process (cmdSite), so the site that holds the
	// queue the loop empties is the one every later site uses.
	next.Federation = prev.Federation
	if next.Signals != nil && prev.Signals != nil {
		next.Signals = prev.Signals
	}
	if next.Forms != nil && prev.Forms != nil {
		next.Forms = prev.Forms
	}
	if next.Boards != nil && prev.Boards != nil {
		next.Boards = prev.Boards
	}
	if next.Bookings != nil && prev.Bookings != nil {
		next.Bookings = prev.Bookings
	}
	if next.Newsletter != nil && prev.Newsletter != nil {
		next.Newsletter = prev.Newsletter
	}
	// The chatbots are the new ones, so a guardrail set since screens what
	// they answer from, carrying on from the previous ones' ratings and new
	// pages (public.Assistants.Keep) and with their count of questions. They
	// were kept whole, and with them the guardrail they were built with.
	if next.Assistants != nil && prev.Assistants != nil {
		next.Assistants.Keep(prev.Assistants)
		if next.Assistants.Questions != nil && prev.Assistants.Questions != nil {
			next.Assistants.Questions = prev.Assistants.Questions
		}
	}
	if next.Share != nil && prev.Share != nil && next.Share.Form == prev.Share.Form {
		next.Share = prev.Share
	}
	if next.Members != nil && prev.Members != nil {
		if next.Members.Mode == prev.Members.Mode && reflect.DeepEqual(next.Members.Party, prev.Members.Party) {
			next.Members = prev.Members
		} else {
			next.Members.Store = prev.Members.Store
			next.Members.Limit = prev.Members.Limit
			next.Members.Lockout = prev.Members.Lockout
		}
	}
	if next.Listings != nil && prev.Listings != nil {
		// A cache of indexes by tree, which is right for any set of listings.
		next.Listings.Index = prev.Listings.Index
	}
}

// onHangup calls reload each time the process is sent SIGHUP, until ctx is
// done.
//
// SIGHUP is what a service manager sends for "reload" (`systemctl reload`,
// with the unit's ExecReload), and what an operator sends by hand. It used to
// end the process, because nothing asked for it, so a reload was a restart
// that dropped every connection. A platform with no SIGHUP never sends one,
// and the other ways in still work.
func onHangup(ctx context.Context, name string, reload func() error) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
				if err := reload(); err == nil {
					fmt.Fprintf(os.Stderr, "  %s%s: read again on SIGHUP%s\n", dim, name, reset)
				}
			}
		}
	}()
}
