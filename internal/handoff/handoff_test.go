// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package handoff

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var day0 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

func opened(t *testing.T) (Store, string, string) {
	t.Helper()
	s := Store{Dir: t.TempDir()}
	secret, id, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open("help", id, "can I return an opened bottle?",
		"I'd like to ask somebody about a return", day0); err != nil {
		t.Fatal(err)
	}
	return s, secret, id
}

func TestAConversationIsTheReplayOfWhatWasSaid(t *testing.T) {
	s, _, id := opened(t)
	if _, err := s.Say("help", id, Person, "dana", "Of course — which order?",
		day0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Say("help", id, Visitor, "", "Order 1182",
		day0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	c, err := s.Get("help", id)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Messages) != 3 || c.Messages[1].By != "dana" ||
		c.Messages[2].N != 3 || c.Question != "can I return an opened bottle?" ||
		!c.Last.Equal(day0.Add(2*time.Minute)) || !c.Waiting() {
		t.Fatalf("the conversation is %+v", c)
	}
	if got := c.After(2); len(got) != 1 || got[0].Text != "Order 1182" {
		t.Errorf("after the second message there is %+v", got)
	}
	if got := c.After(3); got != nil {
		t.Errorf("after the last message there is %+v", got)
	}
}

// The store keeps a digest. A copy of it is not a way into a conversation.
func TestTheStoreDoesNotHoldWhatTheVisitorHolds(t *testing.T) {
	s, secret, id := opened(t)
	if id == secret || strings.Contains(id, secret) || IDFor(secret) != id {
		t.Fatal("the identifier gives back the secret, or is not derived from it")
	}
	err := filepath.Walk(s.Dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(p, secret) {
			t.Errorf("a path holds the secret: %s", p)
		}
		if !fi.IsDir() {
			b, _ := os.ReadFile(p)
			if strings.Contains(string(b), secret) {
				t.Errorf("%s holds the secret", p)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("%s is readable by others: %v", p, fi.Mode())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	other, _, _ := NewSecret()
	if _, err := s.Get("help", IDFor(other)); err != ErrNotFound {
		t.Errorf("another secret reached something: %v", err)
	}
}

func TestOnlyTheTwoSidesSpeakAndAnAnswerSaysWhoGaveIt(t *testing.T) {
	s, _, id := opened(t)
	for _, bad := range []struct{ from, by, text string }{
		{"assistant", "", "I am the model"},
		{Person, "", "no name"},
		{Person, "  ", "blank name"},
		{Visitor, "", "   "},
		{Visitor, "", strings.Repeat("x", MaxText+1)},
	} {
		if _, err := s.Say("help", id, bad.from, bad.by, bad.text, day0); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
	// A visitor cannot sign a message as somebody at the business.
	m, err := s.Say("help", id, Visitor, "dana", "it's me, dana", day0)
	if err != nil || m.By != "" {
		t.Errorf("a visitor's message carries a name: %+v %v", m, err)
	}
}

func TestAnEndedConversationTakesNoMore(t *testing.T) {
	s, _, id := opened(t)
	if err := s.Close("help", id, "dana", day0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Say("help", id, Visitor, "", "wait!", day0.Add(2*time.Hour)); err != ErrClosed {
		t.Errorf("a message reached an ended conversation: %v", err)
	}
	c, _ := s.Get("help", id)
	if !c.Closed || c.ClosedBy != "dana" || c.Waiting() {
		t.Errorf("the ended conversation is %+v", c)
	}
	// Closing twice is not an error and changes nothing.
	if err := s.Close("help", id, "sam", day0.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if c2, _ := s.Get("help", id); c2.ClosedBy != "dana" || !c2.Last.Equal(c.Last) {
		t.Errorf("closing again changed it: %+v", c2)
	}
}

func TestANameThatIsNotOneReachesNothing(t *testing.T) {
	s, _, id := opened(t)
	for _, bad := range []struct{ assistant, id string }{
		{"../help", id}, {"help", "../../etc/passwd"}, {"help", id + "0"},
		{"Help", id}, {"", id}, {"help", strings.ToUpper(id)},
	} {
		if _, err := s.Get(bad.assistant, bad.id); err != ErrNotFound {
			t.Errorf("%+v answered %v", bad, err)
		}
		if _, err := s.Say(bad.assistant, bad.id, Visitor, "", "hi", day0); err == nil {
			t.Errorf("%+v took a message", bad)
		}
	}
	if _, err := s.Open("help", id, "", "again", day0); err == nil {
		t.Error("a conversation was opened twice under one identifier")
	}
}

// Both servers write. Neither may lose or tear the other's message.
func TestTwoWritersAtOnceLoseNothing(t *testing.T) {
	s, _, id := opened(t)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			from, by := Visitor, ""
			if i%2 == 1 {
				from, by = Person, "dana"
			}
			if _, err := s.Say("help", id, from, by,
				strings.Repeat("m", 300+i), day0); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	c, err := s.Get("help", id)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Messages) != 41 {
		t.Errorf("%d of 41 messages survived", len(c.Messages))
	}
}

func TestAConversationIsDeletedWhenItHasNotMovedForLongEnough(t *testing.T) {
	s, _, quiet := opened(t)
	_, recentID, _ := NewSecret()
	if _, err := s.Open("help", recentID, "", "still here", day0.Add(25*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	_, goneID, _ := NewSecret()
	if _, err := s.Open("removed", goneID, "", "its assistant is gone", day0); err != nil {
		t.Fatal(err)
	}
	keep := func(a string) time.Duration {
		if a == "help" {
			return 20 * 24 * time.Hour
		}
		return 0
	}
	n, err := s.Expire(keep, day0.Add(21*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d were deleted", n)
	}
	if _, err := s.Get("help", quiet); err != ErrNotFound {
		t.Error("a conversation past its period is still there")
	}
	if _, err := s.Get("help", recentID); err != nil {
		t.Error("a recent one was deleted")
	}
	// An assistant that no longer exists keeps the default, not forever.
	if n, _ := s.Expire(keep, day0.Add((DefaultDays+1)*24*time.Hour)); n != 1 {
		t.Errorf("the orphan was not deleted at the default (%d)", n)
	}
	// A deleted conversation is not brought back by a late message.
	if _, err := s.Say("help", quiet, Visitor, "", "hello?", day0); err != ErrNotFound {
		t.Errorf("a message reached a deleted conversation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "help", quiet+".jsonl")); err == nil {
		t.Error("the late message recreated the file")
	}
}

func TestTheListPutsWhoeverIsWaitingFirst(t *testing.T) {
	s, _, answered := opened(t)
	s.Say("help", answered, Person, "dana", "done", day0.Add(5*time.Minute))
	_, waiting, _ := NewSecret()
	s.Open("help", waiting, "", "hello?", day0.Add(time.Minute))
	_, ended, _ := NewSecret()
	s.Open("help", ended, "", "bye", day0.Add(10*time.Minute))
	s.Close("help", ended, "", day0.Add(11*time.Minute))
	all, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].ID != waiting || all[1].ID != answered ||
		all[2].ID != ended || all[2].ClosedBy != Visitor {
		t.Errorf("the order is %v %v %v", all[0].ID, all[1].ID, all[2].ID)
	}
}

func TestALineCutShortDoesNotLoseWhatCameBefore(t *testing.T) {
	s, _, id := opened(t)
	p := filepath.Join(s.Dir, "help", id+".jsonl")
	f, _ := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0o600)
	f.WriteString(`{"kind":"say","at":"2026-10-01T09:0`)
	f.Close()
	if _, err := s.Say("help", id, Person, "dana", "after the tear", day0); err != nil {
		t.Fatal(err)
	}
	c, err := s.Get("help", id)
	if err != nil || len(c.Messages) != 2 || c.Messages[1].Text != "after the tear" {
		t.Fatalf("a torn line lost the conversation, or what came after "+
			"it: %+v %v", c, err)
	}
}

// The names that reach a path are checked even where the file they would
// name exists.
func TestAnAssistantNameCannotReachOutOfTheStore(t *testing.T) {
	parent := t.TempDir()
	s := Store{Dir: filepath.Join(parent, "handoff")}
	_, id, _ := NewSecret()
	// A conversation-shaped file beside the store, where "../outside" would
	// find it.
	if err := os.MkdirAll(filepath.Join(parent, "outside"), 0o700); err != nil {
		t.Fatal(err)
	}
	line := `{"kind":"open","at":"2026-10-01T09:00:00Z"}` + "\n"
	if err := os.WriteFile(filepath.Join(parent, "outside", id+".jsonl"),
		[]byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("../outside", id); err != ErrNotFound {
		t.Errorf("a file outside the store was read: %v", err)
	}
	if err := s.append("../outside", id, event{Kind: "say", Text: "x"}); err != ErrNotFound {
		t.Errorf("a file outside the store was written: %v", err)
	}
}

// Appending to a conversation that has gone does not start a new one.
func TestAWriteToAMissingConversationCreatesNothing(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	_, id, _ := NewSecret()
	if err := os.MkdirAll(filepath.Join(s.Dir, "help"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.append("help", id, event{Kind: "say", From: Visitor, Text: "hi"}); err != ErrNotFound {
		t.Errorf("appending to nothing answered %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "help", id+".jsonl")); err == nil {
		t.Error("the write created the conversation")
	}
}

// Kept from when it last moved, not from when it started: a conversation
// still going is not deleted for being old.
func TestALongConversationStillGoingIsKept(t *testing.T) {
	s, _, id := opened(t)
	if _, err := s.Say("help", id, Person, "dana", "still here", day0.Add(40*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	keep := func(string) time.Duration { return 30 * 24 * time.Hour }
	if n, _ := s.Expire(keep, day0.Add(45*24*time.Hour)); n != 0 {
		t.Error("a conversation that moved five days ago was deleted")
	}
}
