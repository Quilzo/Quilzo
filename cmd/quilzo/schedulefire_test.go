// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/schedule"
	"github.com/quilzo/quilzo/internal/site"
)

// scheduledDraft is the demonstration shop with a change in its draft,
// scheduled by who for an hour from now, on a store where dana administers
// and sam and rhea are what roles says.
func scheduledDraft(t *testing.T, who schedule.Who, roles ...[2]string) (root, tpl, commit string) {
	t.Helper()
	root, tpl, _ = installedDemo(t)
	seedPolicy(t, root, append([][2]string{{"dana", "admin"}}, roles...)...)
	addOurPage(t, root, "launch", map[string]any{"title": "The autumn range"})
	for _, name := range []string{"launch"} {
		if err := cmdProvenance(root, []string{"set", name, "--source", "humanEdits", "--author", "rae"}); err != nil {
			t.Fatal(err)
		}
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	commit = s.GetRef(site.RefDraft)
	if err := updateSchedule(root, func(sch *schedule.Schedule) error {
		return sch.Add(commit, time.Now().Add(time.Hour), who, "the autumn launch", time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	return root, tpl, commit
}

// addOurPage puts a page into the draft.
func addOurPage(t *testing.T, root, name string, body map[string]any) {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	pages, err := draftPages(root)
	if err != nil {
		t.Fatal(err)
	}
	pages[name] = body
	if err := saveDraft(root, s, pages, "a page for later", "rae", ""); err != nil {
		t.Fatal(err)
	}
}

// inAnHour is a clock just past the hour every test schedules for, and
// less than a minute past it, so nothing reads as late.
func inAnHour() time.Time { return time.Now().Add(time.Hour + 5*time.Second) }

// loggedAs is how the log names somebody: their pseudonym, on a store whose log
// keeps one.
func loggedAs(t *testing.T, root, name string) string {
	t.Helper()
	l, err := openAudit(root)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Pseudonymous() {
		return name
	}
	return audit.Pseudonym(l.Key(), name)
}

func liveIs(t *testing.T, root string) string {
	t.Helper()
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	return s.GetRef(site.RefLive)
}

func entryFor(t *testing.T, root, commit string) schedule.Entry {
	t.Helper()
	sch, err := loadSchedule(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range sch.Entries {
		if e.Commit == commit {
			return e
		}
	}
	t.Fatalf("no entry for %s in %+v", short(commit), sch.Entries)
	return schedule.Entry{}
}

func publishRecords(t *testing.T, root string) []audit.Event {
	t.Helper()
	evs, err := audit.Read(auditPath(root))
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for _, e := range evs {
		if e.Action == "publish" {
			out = append(out, e)
		}
	}
	return out
}

// A scheduled publish goes out as the person who scheduled it, through
// every gate, and the record says it came by the schedule and who fired it.
func TestAScheduledPublishGoesOutAsWhoeverScheduledIt(t *testing.T) {
	root, tpl, commit := scheduledDraft(t, schedule.Who{Name: "sam", Kind: "human", Verified: true},
		[2]string{"sam", "publisher"})
	if got := liveIs(t, root); got == commit {
		t.Fatal("published before its time")
	}
	fired, err := fireDue(root, asAdmin("dana"), inAnHour, fireOptions{templates: tpl})
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 1 || fired[0].Outcome != "published" || fired[0].By != "sam" {
		t.Fatalf("%+v", fired)
	}
	if got := liveIs(t, root); got != commit {
		t.Fatalf("live is %s, not the scheduled %s", short(got), short(commit))
	}
	if e := entryFor(t, root, commit); !e.Done || e.Result != "published" || e.FiredAt == 0 {
		t.Fatalf("not recorded as published: %+v", e)
	}
	recs := publishRecords(t, root)
	last := recs[len(recs)-1]
	if last.Outcome != audit.Success || last.Principal != loggedAs(t, root, "sam") || !last.Verified ||
		last.Detail["via"] != "schedule" || last.Detail["fired_by"] != loggedAs(t, root, "dana") {
		t.Fatalf("the publish is not recorded as sam's, by the schedule: %+v", last)
	}
	// Fired again, nothing happens: it went out once.
	if again, err := fireDue(root, asAdmin("dana"), inAnHour, fireOptions{templates: tpl}); err != nil || len(again) != 0 {
		t.Fatalf("%+v %v", again, err)
	}
}

// Somebody who scheduled a launch and then lost the right to publish does
// not have it published for them by whoever runs the timer.
func TestAScheduleDoesNotOutliveItsAuthority(t *testing.T) {
	root, tpl, commit := scheduledDraft(t, schedule.Who{Name: "sam", Kind: "human", Verified: true},
		[2]string{"sam", "publisher"})
	if _, err := updatePolicy(root, func(p *auth.Policy) error {
		if p.Revoke("sam", auth.RolePublisher, "/") == 0 {
			return fmt.Errorf("sam held no publisher grant to revoke")
		}
		return p.Grant(auth.Binding{Principal: "sam", Role: auth.RoleAuthor, Resource: "/"})
	}); err != nil {
		t.Fatal(err)
	}
	before := liveIs(t, root)
	fired, err := fireDue(root, asAdmin("dana"), inAnHour, fireOptions{templates: tpl})
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 1 || fired[0].Outcome != "refused" {
		t.Fatalf("%+v", fired)
	}
	if liveIs(t, root) != before {
		t.Fatal("published on the authority of somebody who no longer has it")
	}
	if e := entryFor(t, root, commit); !e.Done || !strings.HasPrefix(e.Result, "refused: ") {
		t.Fatalf("the refusal is not on the record: %+v", e)
	}
	recs := publishRecords(t, root)
	if last := recs[len(recs)-1]; last.Outcome != audit.Denied || last.Principal != loggedAs(t, root, "sam") {
		t.Fatalf("the refusal is not in the log as sam's: %+v", last)
	}
}

// An entry recorded as scheduled by an unverified identity is checked as
// one: on a store with access control, it is refused.
func TestAnUnverifiedScheduleIsNotTrusted(t *testing.T) {
	root, tpl, _ := scheduledDraft(t, schedule.Who{Name: "dana", Kind: "human", Verified: false})
	before := liveIs(t, root)
	fired, err := fireDue(root, asAdmin("dana"), inAnHour, fireOptions{templates: tpl})
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 1 || fired[0].Outcome != "refused" || !strings.Contains(fired[0].Reason, "verified") {
		t.Fatalf("%+v", fired)
	}
	if liveIs(t, root) != before {
		t.Fatal("an unverified schedule published")
	}
}

// Whatever fires the schedule needs the right to publish too, and when it
// lacks it nothing is touched: the entries stay pending for a timer that
// has it, rather than being marked refused.
func TestARunnerThatMayNotPublishLeavesTheScheduleAlone(t *testing.T) {
	root, tpl, commit := scheduledDraft(t, schedule.Who{Name: "sam", Kind: "human", Verified: true},
		[2]string{"sam", "publisher"}, [2]string{"rhea", "reader"})
	reader := human("rhea")
	reader.Role = auth.RoleReader
	_, err := fireDue(root, reader, inAnHour, fireOptions{templates: tpl})
	if !errors.Is(err, errRunnerMayNotPublish) {
		t.Fatalf("%v", err)
	}
	if e := entryFor(t, root, commit); e.Done {
		t.Fatalf("an entry was used up by a runner that could not publish it: %+v", e)
	}
	// And a dry run reports without needing the right, or changing anything.
	fired, err := fireDue(root, reader, inAnHour, fireOptions{dry: true, templates: tpl})
	if err != nil || len(fired) != 1 || fired[0].Outcome != "would-publish" {
		t.Fatalf("%+v %v", fired, err)
	}
}

// Two timers firing at once — the server's and a cron job's — publish an
// entry once, and each says only what it did.
func TestTwoTimersPublishAnEntryOnce(t *testing.T) {
	root, tpl, commit := scheduledDraft(t, schedule.Who{Name: "sam", Kind: "human", Verified: true},
		[2]string{"sam", "publisher"})
	before := len(publishRecords(t, root))
	var wg sync.WaitGroup
	results := make([][]firing, 4)
	errs := make([]error, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = fireDue(root, asAdmin("dana"), inAnHour, fireOptions{templates: tpl})
		}(i)
	}
	wg.Wait()
	published := 0
	for i, r := range results {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		for _, f := range r {
			if f.Outcome == "published" {
				published++
			}
		}
	}
	if published != 1 {
		t.Fatalf("published %d times: %+v", published, results)
	}
	if n := len(publishRecords(t, root)) - before; n != 1 {
		t.Fatalf("%d publish records for one scheduled publish", n)
	}
	if liveIs(t, root) != commit {
		t.Fatal("not live")
	}
}

// Entries added from many places at once are all kept: the schedule is
// changed under its lock, not read by each and written back over the rest.
func TestNoScheduledEntryIsLostToAnother(t *testing.T) {
	root := demoStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			commit := fmt.Sprintf("%064x", i+1)
			if err := updateSchedule(root, func(sch *schedule.Schedule) error {
				return sch.Add(commit, time.Now().Add(time.Hour), schedule.Who{Name: "dana", Verified: true}, "", time.Now())
			}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	sch, err := loadSchedule(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(sch.Entries) != 24 {
		t.Fatalf("%d of 24 entries kept", len(sch.Entries))
	}
}

// The server publishes at the time, with no timer to set up, and not
// before; and turned off it leaves the entry for a timer of the operator's.
func TestTheServerPublishesOnTime(t *testing.T) {
	root, tpl, _ := installedDemo(t)
	seedPolicy(t, root, [2]string{"dana", "admin"})
	addOurPage(t, root, "launch", map[string]any{"title": "The autumn range"})
	if err := cmdProvenance(root, []string{"set", "launch", "--source", "humanEdits", "--author", "rae"}); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	commit := s.GetRef(site.RefDraft)
	at := time.Now().Truncate(time.Second).Add(2 * time.Second)
	if err := updateSchedule(root, func(sch *schedule.Schedule) error {
		return sch.Add(commit, at, schedule.Who{Name: "dana", Kind: "human", Verified: true}, "", time.Now())
	}); err != nil {
		t.Fatal(err)
	}

	run := func(on bool) (context.CancelFunc, chan firing) {
		ctx, cancel := context.WithCancel(context.Background())
		got := make(chan firing, 4)
		go runScheduler(ctx, root, scheduler{
			templates: tpl,
			on:        func() bool { return on },
			runner:    func() *Caller { return asAdmin("dana") },
			report: func(f firing, err error) {
				if err != nil {
					t.Errorf("scheduler: %v", err)
					return
				}
				got <- f
			},
		})
		return cancel, got
	}

	// Off: nothing fires, even well after the time.
	cancel, got := run(false)
	select {
	case f := <-got:
		t.Fatalf("fired while off: %+v", f)
	case <-time.After(time.Until(at) + 1500*time.Millisecond):
	}
	cancel()
	if liveIs(t, root) == commit {
		t.Fatal("published while off")
	}

	// On: it fires at once for the overdue entry, as a restart would.
	cancel, got = run(true)
	defer cancel()
	select {
	case f := <-got:
		if f.Outcome != "published" || f.Commit != commit {
			t.Fatalf("%+v", f)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not publish the overdue entry")
	}
	if liveIs(t, root) != commit {
		t.Fatal("not live")
	}
	if e := entryFor(t, root, commit); time.Unix(e.FiredAt, 0).Before(at) {
		t.Fatalf("fired at %v, before its time %v", time.Unix(e.FiredAt, 0), at)
	}
}

// Running, it wakes for the next entry rather than polling past it: an
// entry due in two seconds goes out within a second of its time.
func TestTheServerWakesForTheNextEntry(t *testing.T) {
	root, tpl, _ := installedDemo(t)
	seedPolicy(t, root, [2]string{"dana", "admin"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan firing, 4)
	go runScheduler(ctx, root, scheduler{
		templates: tpl, poll: 500 * time.Millisecond, on: func() bool { return true },
		runner: func() *Caller { return asAdmin("dana") },
		report: func(f firing, err error) {
			if err == nil {
				got <- f
			}
		},
	})
	addOurPage(t, root, "launch", map[string]any{"title": "The autumn range"})
	if err := cmdProvenance(root, []string{"set", "launch", "--source", "humanEdits", "--author", "rae"}); err != nil {
		t.Fatal(err)
	}
	s, err := open(root)
	if err != nil {
		t.Fatal(err)
	}
	commit := s.GetRef(site.RefDraft)
	at := time.Now().Truncate(time.Second).Add(3 * time.Second)
	if err := updateSchedule(root, func(sch *schedule.Schedule) error {
		return sch.Add(commit, at, schedule.Who{Name: "dana", Kind: "human", Verified: true}, "", time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	// The loop was asleep for up to its poll when this was added; it sees it
	// at its next wake and then sleeps until its time. Within a second of it.
	select {
	case f := <-got:
		if f.Outcome != "published" {
			t.Fatalf("%+v", f)
		}
		if late := time.Since(at); late > time.Second {
			t.Fatalf("went out %v after its time", late)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("never fired")
	}
}
