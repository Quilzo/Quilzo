// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package room

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
)

var now = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func open(t *testing.T) *Log {
	t.Helper()
	l, err := New(Room{
		ID: "deploys", Name: "deploys", Kind: Open,
		Purpose: "what is going out and when", Owner: "rashik",
		Created: now.Add(-90 * 24 * time.Hour),
		Members: []string{"rashik", "sam", "alex"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func said(id, who, text string, at time.Time) Message {
	return Message{
		ID: id, Room: "deploys", Author: who, At: at,
		Revisions: []Revision{{Text: text, At: at, By: who,
			Kind: audit.KindHuman}},
	}
}

func post(t *testing.T, l *Log, m Message) *Message {
	t.Helper()
	got, _, err := l.Post(m)
	if err != nil {
		t.Fatalf("post %s: %v", m.ID, err)
	}
	return got
}

// "I said deploy to staging", edited to "I said deploy to prod", is
// unfalsifiable when the previous text is gone.
func TestAnEditAppendsAndTheEarlierWordsStay(t *testing.T) {
	l := open(t)
	m := post(t, l, said("m1", "rashik", "deploying to staging", now))

	if m.Edited() {
		t.Fatal("a fresh message reads as edited")
	}
	if _, err := l.Edit("m1", Revision{Text: "deploying to prod",
		At: now.Add(time.Minute), By: "rashik",
		Kind: audit.KindHuman}); err != nil {
		t.Fatal(err)
	}
	got, _ := l.Get("m1")

	if got.Text() != "deploying to prod" {
		t.Errorf("the message reads %q", got.Text())
	}
	if !got.Edited() {
		t.Fatal("an edited message does not say so")
	}
	history := got.History()
	if len(history) != 2 {
		t.Fatalf("%d revision(s)", len(history))
	}
	if history[0].Text != "deploying to staging" {
		t.Errorf("the first revision reads %q", history[0].Text)
	}
	if !strings.Contains(got.Says(), "the earlier versions are here") {
		t.Errorf("the summary is %q", got.Says())
	}
	// And "edited" is derived rather than stored, so there is no flag to
	// clear: the only way to hide the edit is to remove a revision, which
	// changes the count.
	got.Revisions = got.Revisions[:1]
	if got.Edited() {
		t.Error("edited survived the revision being removed, which means it " +
			"is a flag")
	}
}

// An edit changes what somebody is recorded as having said.
func TestOnlyTheAuthorMayEdit(t *testing.T) {
	l := open(t)
	post(t, l, said("m1", "rashik", "deploying to staging", now))
	_, err := l.Edit("m1", Revision{Text: "deploying to prod",
		At: now.Add(time.Minute), By: "sam", Kind: audit.KindHuman})
	if err == nil {
		t.Fatal("somebody else edited a message")
	}
	if !strings.Contains(err.Error(), "only they may make one") {
		t.Errorf("the refusal is %v", err)
	}
}

func TestAnEditThatChangesNothingIsNotAnEdit(t *testing.T) {
	l := open(t)
	post(t, l, said("m1", "rashik", "hello", now))
	if _, err := l.Edit("m1", Revision{Text: "hello",
		At: now.Add(time.Minute), By: "rashik"}); err != nil {
		t.Fatal(err)
	}
	got, _ := l.Get("m1")
	if got.Edited() {
		t.Error("a keystroke somebody undid produced an edit mark")
	}
}

// A conversation where message 47 is missing and nothing says so is a
// conversation somebody edited.
func TestRemovingAMessageLeavesTheShape(t *testing.T) {
	l := open(t)
	post(t, l, said("m1", "rashik", "the deploy key is hunter2", now))
	if _, err := l.Remove("m1", Tombstone{At: now.Add(time.Minute),
		By: "rashik", Kind: audit.KindHuman, Why: ByAuthor}); err != nil {
		t.Fatal(err)
	}
	got, _ := l.Get("m1")

	if !got.Gone() {
		t.Fatal("a removed message does not say so")
	}
	if got.Text() != "" {
		t.Errorf("a removed message still reads %q", got.Text())
	}
	if !strings.Contains(got.Says(), "deleted by its author") {
		t.Errorf("the summary is %q", got.Says())
	}
	// The shape survives: it is still in the room, in order, with its
	// author and its time.
	if l.Len() != 1 || len(l.All()) != 1 {
		t.Error("the message vanished from the room entirely")
	}
	if got.Author != "rashik" || got.At != now {
		t.Error("the tombstone lost who and when")
	}
}

// Taking down another person's words is a decision, and a decision with no
// reason attached is one nobody can question.
func TestAModeratorRemovalNeedsAReasonAndIsADifferentEvent(t *testing.T) {
	l := open(t)
	post(t, l, said("m1", "sam", "something out of order", now))

	// Calling it the author's own when it is not.
	_, err := l.Remove("m1", Tombstone{At: now, By: "rashik",
		Kind: audit.KindHuman, Why: ByAuthor})
	if err == nil {
		t.Fatal("a moderator removal was recorded as the author's own")
	}
	if !strings.Contains(err.Error(), "different events") {
		t.Errorf("the refusal is %v", err)
	}

	// And as a moderator, with no reason.
	_, err = l.Remove("m1", Tombstone{At: now, By: "rashik",
		Kind: audit.KindHuman, Why: ByModerator})
	if err == nil {
		t.Fatal("a moderator removal with no reason was accepted")
	}
	if !strings.Contains(err.Error(), "nobody can appeal") {
		t.Errorf("the refusal is %v", err)
	}

	if _, err := l.Remove("m1", Tombstone{At: now, By: "rashik",
		Kind: audit.KindHuman, Why: ByModerator,
		Because: "names a customer, moved to the private channel"}); err != nil {
		t.Fatal(err)
	}
	got, _ := l.Get("m1")
	if !strings.Contains(got.Says(), "taken down by rashik") {
		t.Errorf("the summary is %q", got.Says())
	}
	// A removal reads as a denial in the log, so the occasions somebody
	// took words away can be searched for.
	if got.Record("removed", "rashik",
		audit.KindHuman).Outcome != audit.Denied {
		t.Error("taking a message down reads the same as sending one")
	}
}

// Article 17 outranks all of this, and the log holds a digest rather than
// the words so erasing them leaves the chain intact.
func TestErasureTakesTheTextAndLeavesTheProof(t *testing.T) {
	l := open(t)
	m := post(t, l, said("m1", "sam", "my home address is 12 Acacia Ave",
		now))
	digest := m.Revisions[0].Digest()

	// The log entry never held the text.
	rec := m.Record("posted", "sam", audit.KindHuman)
	for k, v := range rec.Detail {
		if strings.Contains(v, "Acacia") {
			t.Fatalf("the audit detail %s carries the message text", k)
		}
	}
	if rec.Detail["digest"] != digest {
		t.Errorf("the record's digest is %q", rec.Detail["digest"])
	}

	if _, err := l.Remove("m1", Tombstone{At: now.Add(time.Hour),
		By: "rashik", Kind: audit.KindHuman, Why: ByErasure,
		Because: "erasure request"}); err != nil {
		t.Fatal(err)
	}
	got, _ := l.Get("m1")
	for _, r := range got.History() {
		if strings.Contains(r.Text, "Acacia") {
			t.Fatal("the text survived an erasure")
		}
	}
	if !strings.Contains(got.Says(), "the fact and no words") {
		t.Errorf("the summary is %q", got.Says())
	}
	// And the digest still proves what it said, to anybody who has the
	// original.
	if (Revision{Text: "my home address is 12 Acacia Ave"}).Digest() !=
		digest {
		t.Error("the digest does not verify the original")
	}
	if !ByErasure.Erases() || ByAuthor.Erases() {
		t.Error("the removals do not agree about which one erases")
	}
}

// A room running for three years still says how much was said and when.
func TestRetentionRemovesContentAndNotTheShape(t *testing.T) {
	l, err := New(Room{
		ID: "deploys", Name: "deploys", Kind: Open, Purpose: "deploys",
		Created:   now.Add(-400 * 24 * time.Hour),
		Retention: 30 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	for n := range 5 {
		post(t, l, said(fmt.Sprintf("old%d", n), "rashik", "old news",
			now.Add(-time.Duration(60+n)*24*time.Hour)))
	}
	post(t, l, said("new", "rashik", "still here", now))

	if n := l.Expire(now); n != 5 {
		t.Fatalf("retention removed %d message(s)", n)
	}
	if l.Len() != 6 {
		t.Fatalf("the room now holds %d message(s); the shape was lost",
			l.Len())
	}
	old, _ := l.Get("old0")
	if old.Text() != "" {
		t.Error("retention left the text")
	}
	if !strings.Contains(old.Says(), "a message was here") {
		t.Errorf("the summary is %q", old.Says())
	}
	fresh, _ := l.Get("new")
	if fresh.Text() != "still here" {
		t.Error("retention took something inside the period")
	}
	// Running it again changes nothing.
	if n := l.Expire(now); n != 0 {
		t.Errorf("a second pass removed %d more", n)
	}
}

// A client that timed out and retried has sent one thing.
func TestTheSameMessageTwiceIsOneMessage(t *testing.T) {
	l := open(t)
	m := said("m1", "rashik", "deploying", now)
	first, isNew, err := l.Post(m)
	if err != nil || !isNew {
		t.Fatalf("first post: %v new=%v", err, isNew)
	}
	second, isNew, err := l.Post(m)
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Fatal("a retry was recorded as a second message")
	}
	if second.ID != first.ID || l.Len() != 1 {
		t.Errorf("the room holds %d message(s)", l.Len())
	}
	// And a message with no identifier is refused, because a retry of one
	// cannot be recognised.
	if err := (Message{Room: "deploys", Author: "a", At: now,
		Revisions: []Revision{{Text: "x", At: now, By: "a"}}}).
		Validate(); err == nil {
		t.Error("a message with no identifier was accepted")
	}
}

// Two clients that received the same messages in different orders have to
// display the same conversation.
func TestTheOrderIsTotalAndNotArrivalOrder(t *testing.T) {
	build := func(order []int) []Message {
		l := open(t)
		stamps := []time.Time{now, now.Add(time.Second), now, now.Add(2 * time.Second)}
		ids := []string{"b", "c", "a", "d"}
		for _, i := range order {
			post(t, l, said(ids[i], "rashik", "x", stamps[i]))
		}
		return l.All()
	}
	one := build([]int{0, 1, 2, 3})
	two := build([]int{3, 2, 1, 0})
	if len(one) != len(two) {
		t.Fatal("different lengths")
	}
	for i := range one {
		if one[i].ID != two[i].ID {
			t.Fatalf("two clients disagree at position %d: %s and %s", i,
				one[i].ID, two[i].ID)
		}
	}
	// Same instant, so the identifier decides, and "a" sorts before "b".
	if one[0].ID != "a" {
		t.Errorf("the tie broke to %s", one[0].ID)
	}
}

// A reply in a thread nobody is following is the commonest structural
// complaint about Slack, and the reason is that a thread is a separate place.
func TestAThreadReplyIsUnreadInTheRoom(t *testing.T) {
	l := open(t)
	post(t, l, said("m1", "rashik", "shipping at four", now))
	reply := said("m2", "sam", "the migration has not run", now.Add(time.Hour))
	reply.Reply = "m1"
	post(t, l, reply)

	unread := l.Unread("alex", now.Add(30*time.Minute), false)
	if len(unread) != 1 || unread[0].ID != "m2" {
		t.Fatalf("somebody not following the thread sees %v", unread)
	}
	// Muting silences the room, threaded or not — one decision, not two.
	if got := l.Unread("alex", now.Add(30*time.Minute), true); len(got) != 0 {
		t.Errorf("a muted room produced %d unread", len(got))
	}
	// Your own message is not news.
	if got := l.Unread("sam", now.Add(30*time.Minute), false); len(got) != 0 {
		t.Errorf("somebody's own reply is unread to them")
	}
	thread, err := l.Thread("m2")
	if err != nil {
		t.Fatal(err)
	}
	if len(thread) != 2 || thread[0].ID != "m1" {
		t.Errorf("the thread is %v", thread)
	}
}

// A thread of threads is a thread nobody can follow.
func TestThreadsAreOneLevelDeep(t *testing.T) {
	l := open(t)
	post(t, l, said("m1", "rashik", "top", now))
	reply := said("m2", "sam", "reply", now.Add(time.Minute))
	reply.Reply = "m1"
	post(t, l, reply)

	nested := said("m3", "alex", "reply to the reply", now.Add(2*time.Minute))
	nested.Reply = "m2"
	if _, _, err := l.Post(nested); err == nil {
		t.Fatal("a reply to a reply was accepted")
	}
	// And a reply to something that is not here at all.
	orphan := said("m4", "alex", "x", now)
	orphan.Reply = "nowhere"
	if _, _, err := l.Post(orphan); err == nil {
		t.Fatal("a reply to a message in another room was accepted")
	}
}

// Everything anybody finds tiring about a place like this is made of
// messages like this one — so the number is shown before it is sent.
func TestABroadcastSaysHowManyPeopleItInterrupts(t *testing.T) {
	r := Room{ID: "all", Name: "all", Kind: Closed, Purpose: "everybody",
		Created: now}
	for n := range 214 {
		r.Members = append(r.Members, fmt.Sprintf("p%d", n))
	}
	broad := Reaches("@room the office is closed tomorrow", r)
	if !broad.Broadcast || broad.People != 214 {
		t.Fatalf("a broadcast reaches %+v", broad)
	}
	if !strings.Contains(broad.Why(), "all 214 people") {
		t.Errorf("the summary is %q", broad.Why())
	}
	if !strings.Contains(broad.Why(), "made of messages like this one") {
		t.Errorf("the summary does not say what it costs: %q", broad.Why())
	}

	named := Reaches("@sam @alex can one of you look?", r)
	if named.Broadcast || named.People != 2 {
		t.Fatalf("naming two people reaches %+v", named)
	}
	if named.Named[0] != "alex" || named.Named[1] != "sam" {
		t.Errorf("the named are %v", named.Named)
	}
	// The three spellings of a broadcast are one thing, because a product
	// with several ways to interrupt everybody has several ways to
	// interrupt everybody.
	for _, word := range []string{"@room", "@everyone", "@channel"} {
		if !Reaches(word+" hello", r).Broadcast {
			t.Errorf("%s did not read as a broadcast", word)
		}
	}
	if Reaches("no mentions here", r).People != 0 {
		t.Error("a plain message notifies somebody")
	}
}

// Reactions arrive out of order on a bad connection and two clients must
// agree about the result.
func TestReactionsFoldOverTimeAndNotArrival(t *testing.T) {
	l := open(t)
	post(t, l, said("m1", "rashik", "shipping", now))
	for _, r := range []Reaction{
		{Message: "m1", Emoji: "eyes", By: "sam", At: now.Add(time.Second)},
		{Message: "m1", Emoji: "eyes", By: "sam",
			At: now.Add(3 * time.Second), Off: true},
		// Arrives last, happened first.
		{Message: "m1", Emoji: "eyes", By: "sam", At: now},
		{Message: "m1", Emoji: "tick", By: "alex", At: now},
	} {
		if err := l.React(r); err != nil {
			t.Fatal(err)
		}
	}
	got := l.Reactions("m1")
	if len(got["eyes"]) != 0 {
		t.Errorf("a reaction taken back is still there: %v", got["eyes"])
	}
	if len(got["tick"]) != 1 || got["tick"][0] != "alex" {
		t.Errorf("tick is %v", got["tick"])
	}
	if err := l.React(Reaction{Message: "nowhere", Emoji: "x", By: "a",
		At: now}); err == nil {
		t.Error("a reaction to a message in another room was accepted")
	}
}

// A room nobody can state the purpose of accumulates people.
func TestARoomNobodyCanExplainIsRefused(t *testing.T) {
	good := Room{ID: "deploys", Name: "deploys", Kind: Open,
		Purpose: "what is going out", Created: now}
	for name, spoil := range map[string]func(*Room){
		"no purpose": func(r *Room) { r.Purpose = "" },
		"no name":    func(r *Room) { r.Name = "" },
		"no kind":    func(r *Room) { r.Kind = "" },
		"no time":    func(r *Room) { r.Created = time.Time{} },
		"closed with nobody in it": func(r *Room) {
			r.Kind, r.Members = Closed, nil
		},
		"negative retention": func(r *Room) { r.Retention = -time.Hour },
	} {
		x := good
		spoil(&x)
		if err := x.Validate(); err == nil {
			t.Errorf("a room with %s was accepted", name)
		}
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("an ordinary room was refused: %v", err)
	}
	// A direct conversation has no name and no purpose, and two people.
	direct := Room{ID: "d1", Kind: Direct, Created: now,
		Members: []string{"rashik", "sam"}}
	if err := direct.Validate(); err != nil {
		t.Fatalf("a direct conversation was refused: %v", err)
	}
	direct.Members = direct.Members[:1]
	if err := direct.Validate(); err == nil {
		t.Error("a direct conversation with one person was accepted")
	}
}

func TestSomebodyOutsideAClosedRoomCannotPostToIt(t *testing.T) {
	l, err := New(Room{ID: "private", Name: "private", Kind: Closed,
		Purpose: "the board", Created: now,
		Members: []string{"rashik", "sam"}})
	if err != nil {
		t.Fatal(err)
	}
	m := said("m1", "alex", "hello", now)
	m.Room = "private"
	if _, _, err := l.Post(m); err == nil {
		t.Fatal("somebody outside a closed room posted to it")
	}
	if !l.Room().Holds("rashik") || l.Room().Holds("alex") {
		t.Error("membership does not hold")
	}
}

func TestAMessageThatCannotBeStoredIsRefused(t *testing.T) {
	good := said("m1", "rashik", "hello", now)
	for name, spoil := range map[string]func(*Message){
		"no room":      func(m *Message) { m.Room = "" },
		"no author":    func(m *Message) { m.Author = "" },
		"no time":      func(m *Message) { m.At = time.Time{} },
		"nothing said": func(m *Message) { m.Revisions = nil },
		"an empty revision": func(m *Message) {
			m.Revisions[0].Text = "  "
		},
		"a revision by nobody": func(m *Message) {
			m.Revisions[0].By = ""
		},
		"a reply to itself": func(m *Message) { m.Reply = m.ID },
		"a message used as a file": func(m *Message) {
			m.Revisions[0].Text = strings.Repeat("x", MaxMessage+1)
		},
		"history out of order": func(m *Message) {
			m.Revisions = append(m.Revisions, Revision{Text: "later",
				At: m.At.Add(-time.Hour), By: m.Author})
		},
	} {
		x := said("m1", "rashik", "hello", now)
		spoil(&x)
		if err := x.Validate(); err == nil {
			t.Errorf("a message with %s was accepted", name)
		}
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("an ordinary message was refused: %v", err)
	}
}

func TestEditingOrRemovingSomethingAlreadyGoneIsRefused(t *testing.T) {
	l := open(t)
	post(t, l, said("m1", "rashik", "hello", now))
	if _, err := l.Remove("m1", Tombstone{At: now, By: "rashik",
		Kind: audit.KindHuman, Why: ByAuthor}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Edit("m1", Revision{Text: "x", At: now.Add(time.Hour),
		By: "rashik"}); err == nil {
		t.Error("a removed message was edited")
	}
	if _, err := l.Remove("m1", Tombstone{At: now, By: "rashik",
		Why: ByAuthor}); err == nil {
		t.Error("a removed message was removed twice")
	}
	if _, err := l.Edit("nowhere", Revision{Text: "x", At: now,
		By: "rashik"}); err == nil {
		t.Error("a message in another room was edited")
	}
}

func TestEveryEventReachesARealAuditLog(t *testing.T) {
	dir := t.TempDir()
	k, err := audit.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.New(audit.Options{Path: dir + "/audit.jsonl", Key: k,
		Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	m := said("m1", "rashik", "hello", now)
	for _, action := range []string{"posted", "edited", "removed"} {
		if _, aerr := log.Append(m.Record(action, "rashik",
			audit.KindHuman)); aerr != nil {
			t.Fatalf("%s: %v", action, aerr)
		}
	}
	events, err := audit.Read(dir + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("%d entries", len(events))
	}
	for _, e := range events {
		if strings.Contains(fmt.Sprint(e.Detail), "hello") {
			t.Error("the audit log holds the message text")
		}
	}
}
