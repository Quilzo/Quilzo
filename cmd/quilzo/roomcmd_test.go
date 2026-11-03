// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/room"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// roomStore is an empty store whose commands answer in JSON, run by
// whoever the test names with inRoom: nobody has been granted anything, so the
// name is the operator's own, unverified, as on a single-user machine.
func roomStore(t *testing.T) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("QUILZO_TOKEN", "")
	return connectStore(t)
}

// inRoom runs one room command as somebody, and returns what it answered.
func inRoom(t *testing.T, root, who string, args ...string) map[string]any {
	t.Helper()
	got, err := tryInRoom(t, root, who, args...)
	if err != nil {
		t.Fatalf("%s: room %v: %v", who, args, err)
	}
	return got
}

// tryInRoom is inRoom, for a command that may be refused.
func tryInRoom(t *testing.T, root, who string, args ...string) (map[string]any, error) {
	t.Helper()
	raw, err := roomSaid(t, root, who, args...)
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	return got, err
}

// roomSaid runs one room command as somebody and returns everything it
// wrote, whatever shape.
func roomSaid(t *testing.T, root, who string, args ...string) ([]byte, error) {
	t.Helper()
	t.Setenv("USER", who)
	var buf bytes.Buffer
	w.Out = &buf
	err := cmdRoom(root, args)
	return buf.Bytes(), err
}

// An erasure takes the words off the disk, not only out of the room.
//
// It did not. A room's messages are a file of lines, one per change, and
// the last line for a message is its state; the erasure was appended as
// one more line. `room read` said "erased under Article 17" while the
// lines above it still held what was said, and every edit before it, for
// anybody who opened rooms/ and in every backup made after.
func TestErasingAMessageTakesItsWordsOffTheDisk(t *testing.T) {
	root := roomStore(t)
	inRoom(t, root, "sam", "open", "plans", "--purpose", "what ships when")
	id, _ := inRoom(t, root, "sam", "say", "plans", "my home address is 12 Acacia Ave")["message"].(string)
	inRoom(t, root, "sam", "edit", "plans", id, "my home address is 14 Acacia Ave")
	other, _ := inRoom(t, root, "sam", "say", "plans", "the release is on Friday")["message"].(string)
	inRoom(t, root, "sam", "remove", "plans", id, "--erase")

	b, err := os.ReadFile(roomMessages(root, "plans"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("Acacia")) {
		t.Fatalf("an erased message's words are still in the room's file:\n%s", b)
	}

	// The erased message keeps its shape and the rest of the room is as it
	// was, read back from the file that was rewritten.
	l, err := loadRoom(root, "plans")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := l.Get(id)
	if !ok || !m.Gone() || m.Deleted.Why != room.ByErasure {
		t.Fatalf("the erased message lost its tombstone: %+v", m)
	}
	if o, ok := l.Get(other); !ok || o.Text() != "the release is on Friday" {
		t.Fatalf("the message beside it changed: %+v", o)
	}
}

// A change to a room waits for the one before it.
//
// An erasure rewrites the room's file now, and a message appended by
// another process while it did so would have gone into the copy the rename
// threw away: its sender told it was sent, the room without it. So every
// change holds the room's lock from the read to the write.
func TestAChangeToARoomWaitsForTheOneBeforeIt(t *testing.T) {
	root := roomStore(t)
	inRoom(t, root, "sam", "open", "plans", "--purpose", "what ships when")

	unlock, err := atomicfile.Lock(roomMessages(root, "plans") + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("USER", "sam")
	w.Out = &bytes.Buffer{}
	done := make(chan error, 1)
	go func() {
		done <- cmdRoom(root, []string{"say", "plans", "while the room was being rewritten"})
	}()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("a message was written while another change held the room (%v)", err)
	case <-time.After(300 * time.Millisecond):
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	l, err := loadRoom(root, "plans")
	if err != nil {
		t.Fatal(err)
	}
	if l.Len() != 1 {
		t.Fatalf("the room holds %d message(s) after one was sent", l.Len())
	}
}

// A room's retention is applied, by the admin's sweep and not the site's.
//
// `room open --retention` said how long a room's text is kept and
// room.Log.Expire was written to enforce it, and nothing called it: a room
// kept every word for ever, whatever it declared. The public site's sweep
// must leave rooms alone, because rooms/ is outside what the confined site
// may write.
func TestARoomsRetentionIsApplied(t *testing.T) {
	root := roomStore(t)
	inRoom(t, root, "sam", "open", "plans", "--purpose", "what ships when",
		"--retention", "720h")
	first, _ := inRoom(t, root, "sam", "say", "plans", "the launch code is marmalade")["message"].(string)
	inRoom(t, root, "sam", "say", "plans", "and the venue is the old mill")
	before, err := os.ReadFile(roomMessages(root, "plans"))
	if err != nil {
		t.Fatal(err)
	}

	var sweep *upkeep.Job
	for _, j := range upkeepJobs(root, upkeep.Job{Name: "posture"}) {
		if j.Name == "rooms" {
			sweep = &j
		}
	}
	if sweep == nil {
		t.Fatal("the admin's sweep has nothing that applies a room's retention")
	}

	// Inside the period, nothing.
	if n, err := sweep.Do(time.Now().Add(24 * time.Hour)); err != nil || n != 0 {
		t.Fatalf("a day later the sweep took %d message(s) (%v)", n, err)
	}
	// The site's sweep, past the period: it must not touch rooms/.
	if site, ok := retentionJob(root); ok {
		if _, err := site.Do(time.Now().Add(31 * 24 * time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if after, _ := os.ReadFile(roomMessages(root, "plans")); !bytes.Equal(before, after) {
		t.Fatal("the sweep the public site runs changed a room")
	}

	// The admin's, past the period: the words go, from the disk too.
	n, err := sweep.Do(time.Now().Add(31 * 24 * time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("past the period the sweep took %d message(s) (%v)", n, err)
	}
	b, err := os.ReadFile(roomMessages(root, "plans"))
	if err != nil {
		t.Fatal(err)
	}
	for _, words := range []string{"marmalade", "old mill"} {
		if bytes.Contains(b, []byte(words)) {
			t.Errorf("%q outlived its room's retention on disk:\n%s", words, b)
		}
	}
	l, err := loadRoom(root, "plans")
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := l.Get(first); !ok || !m.Gone() || m.Deleted.Why != room.ByRetention {
		t.Fatalf("an expired message lost its shape: %+v", m)
	}
	// And again changes nothing.
	if n, err := sweep.Do(time.Now().Add(32 * 24 * time.Hour)); err != nil || n != 0 {
		t.Errorf("a second pass took %d more (%v)", n, err)
	}
}

// A closed room, or a direct one, is read by the people in it.
//
// room.Room.Holds says who can see a room, and only posting asked it:
// anybody who could view the store read every closed room and every direct
// conversation, saw each message's history, and had the list of who was
// talking to whom. A member reads as before, and somebody outside who may
// take a message down still can, without being shown what it said.
func TestOnlyItsMembersReadAClosedRoom(t *testing.T) {
	root := roomStore(t)
	inRoom(t, root, "sam", "open", "board", "--purpose", "the merger",
		"--kind", "closed", "--members", "sam,lee")
	id, _ := inRoom(t, root, "sam", "say", "board", "the merger is with Initech")["message"].(string)
	inRoom(t, root, "sam", "open", "sam-lee", "--kind", "direct", "--members", "sam,lee")
	inRoom(t, root, "sam", "say", "sam-lee", "Initech said yes")
	inRoom(t, root, "sam", "open", "lobby", "--purpose", "everybody")

	for _, args := range [][]string{
		{"read", "board"}, {"read", "board", "--thread", id},
		{"history", "board", id}, {"read", "sam-lee"},
	} {
		said, err := roomSaid(t, root, "pat", args...)
		if err == nil {
			t.Errorf("room %v answered somebody outside the room", args)
		}
		if strings.Contains(string(said), "Initech") {
			t.Errorf("room %v showed somebody outside the room what was said: %s", args, said)
		}
	}
	// The list names the rooms somebody is in, and the open ones.
	var listed []struct {
		Room room.Room `json:"room"`
	}
	said, err := roomSaid(t, root, "pat", "list")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(said, &listed); err != nil {
		t.Fatalf("%v: %s", err, said)
	}
	if len(listed) != 1 || listed[0].Room.ID != "lobby" {
		t.Errorf("somebody outside two rooms is shown %+v", listed)
	}

	// A member reads it.
	if _, err := tryInRoom(t, root, "lee", "read", "board"); err != nil {
		t.Errorf("a member could not read the room: %v", err)
	}
	if _, err := tryInRoom(t, root, "LEE", "history", "board", id); err != nil {
		t.Errorf("a member named in another case could not read it: %v", err)
	}

	// Somebody outside may still take a message down, and is told what
	// they did and not what it said.
	got := inRoom(t, root, "pat", "remove", "board", id, "--because", "names a client")
	if b, _ := json.Marshal(got); strings.Contains(string(b), "Initech") || got["deleted"] == nil {
		t.Errorf("a removal from outside the room answered %s", b)
	}
	// And the room still holds the words for its members, as removals do.
	if l, _ := loadRoom(root, "board"); l != nil {
		if m, ok := l.Get(id); !ok || len(m.History()) == 0 || m.History()[0].Text == "" {
			t.Errorf("withholding the words from the answer took them from the room: %+v", m)
		}
	}
}
