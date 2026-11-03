// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/room"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// Conversation, built so that what was said stays said.
//
// An edit appends a revision and the earlier words stay where everybody in
// the room can read them. A removal takes the text and leaves the shape, so
// that a message which vanished and a message which was never sent are
// different facts. Retention does the same with a different actor, and only
// an Article 17 erasure takes the words out of the log as well.
//
// And a broadcast says how many people it interrupts before it goes, which
// is the one thing that would fix the commonest complaint about every product
// in this category and which none of them does.

func roomDir(root string) string { return filepath.Join(root, "rooms") }

func roomPath(root, id string) string {
	return filepath.Join(roomDir(root), safeName(id)+".json")
}

func roomMessages(root, id string) string {
	return filepath.Join(roomDir(root), safeName(id)+".messages.jsonl")
}

// roomReactions are a room's reactions, appended one line each: taking one
// back is a line of its own, so the fold (room.Tally) is over what happened
// rather than over what the file was last told.
func roomReactions(root, id string) string {
	return filepath.Join(roomDir(root), safeName(id)+".reactions.jsonl")
}

// roomSeen is how far each person has read a room, for what is unread.
// In a directory of its own, so the list of rooms never mistakes it for one.
func roomSeen(root, id string) string {
	return filepath.Join(roomDir(root), "seen", safeName(id)+".json")
}

func cmdRoom(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list":
		return roomList(root)
	case "open":
		return roomOpen(root, args[1:])
	case "say":
		return roomSay(root, args[1:])
	case "read":
		return roomRead(root, args[1:])
	case "edit":
		return roomEdit(root, args[1:])
	case "remove":
		return roomRemove(root, args[1:])
	case "history":
		return roomHistory(root, args[1:])
	case "react":
		return roomReact(root, args[1:])
	default:
		return fmt.Errorf("unknown room command %q; try list, open, say, "+
			"read, edit, remove, history or react", args[0])
	}
}

func loadRoom(root, id string) (*room.Log, error) {
	b, err := readFileMaybe(roomPath(root, id))
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("there is no room called %q", id)
	}
	var r room.Room
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	l, err := room.New(r)
	if err != nil {
		return nil, err
	}
	err = loadJSONL(roomMessages(root, id), func(line []byte) error {
		var m room.Message
		if uerr := json.Unmarshal(line, &m); uerr != nil {
			return uerr
		}
		// Replayed in order: an edit or a removal was appended as a whole
		// message, so the last one for an identifier is its state.
		if existing, ok := l.Get(m.ID); ok {
			*existing = m
			return nil
		}
		_, _, perr := l.Post(m)
		return perr
	})
	if err != nil {
		return l, err
	}
	err = loadJSONL(roomReactions(root, id), func(line []byte) error {
		var r room.Reaction
		if uerr := json.Unmarshal(line, &r); uerr != nil {
			return uerr
		}
		return l.React(r)
	})
	return l, err
}

// save appends a message's current state.
//
// The file is a log and the last entry for an identifier wins on replay,
// which is the same fold internal/finding uses for a decision: nothing is
// rewritten in place, so a reader with the file has every version — except
// the words an erasure or retention took, which compactRoom takes out.
func save(root, id string, m *room.Message) error {
	return appendJSONL(roomMessages(root, id), m)
}

// readableRoom loads a room for somebody who means to read it.
//
// A closed room is for its members and a direct one for the people in it
// (room.Room.Holds), and only posting asked: anybody who could view the
// store read every closed room and every direct conversation in it, and
// each message's history. Refused in the words posting uses.
func readableRoom(root, id string, caller *Caller) (*room.Log, error) {
	l, err := loadRoom(root, id)
	if err != nil {
		return nil, err
	}
	if !l.Room().Holds(caller.Name) {
		return nil, fmt.Errorf("%s is not in %s, which is %s: what is said "+
			"there is for the people in it", caller.Name, l.Room().ID,
			l.Room().Kind)
	}
	return l, nil
}

// changeRoom loads a room under its lock, for a command about to change
// it, and returns what releases the lock.
//
// Every change is a read, a decision and a write, and the file is rewritten
// whole when words have to leave it (compactRoom). An append that opened
// the file before such a rewrite would land in the copy the rename just
// unlinked, so a message somebody was told was sent would be gone; a
// rewrite that read the file before an edit was appended would write the
// room back without the edit. So the whole sequence holds one lock.
func changeRoom(root, id string) (*room.Log, func(), error) {
	// Asked first, so a room that does not exist is said to be missing
	// rather than leaving a lock file behind in a directory nobody made.
	if b, err := readFileMaybe(roomPath(root, id)); err != nil {
		return nil, nil, err
	} else if b == nil {
		return nil, nil, fmt.Errorf("there is no room called %q", id)
	}
	unlock, err := atomicfile.Lock(roomMessages(root, id) + ".lock")
	if err != nil {
		return nil, nil, err
	}
	l, err := loadRoom(root, id)
	if err != nil {
		unlock()
		return nil, nil, err
	}
	return l, unlock, nil
}

// compactRoom rewrites a room's file as its messages are now, one line
// each, in the order they arrived; the caller holds the room's lock.
//
// For the removals that have to take words off the disk. An erasure was
// appended like every other change, so `room read` said "erased under
// Article 17" while the lines above it in the file still held what was
// said, and every version of it, for anybody who opened rooms/ and in
// every backup made afterwards. A message's last line carries its whole
// history, so dropping the earlier ones loses nothing but what an erasure
// or retention took out of it. Backups already made keep their copy until
// backup.keep rotates them out; none made from now on has it.
func compactRoom(root, id string, l *room.Log) error {
	var b bytes.Buffer
	for _, m := range l.Arrived() {
		line, err := json.Marshal(m)
		if err != nil {
			return err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return atomicfile.Write(roomMessages(root, id), b.Bytes(), 0o600)
}

// roomRetentionJob takes the text of messages past their room's retention
// out of the room and off the disk.
//
// A room opened with --retention said how long its text is kept, and
// room.Log.Expire was written to enforce it, and nothing called it: every
// room kept every word for ever, whatever it declared. In the admin's
// sweep and never the public site's: rooms/ is outside what the confined
// site may write (siteWritable), so there it could only fail.
func roomRetentionJob(root string) upkeep.Job {
	return upkeep.Job{Name: "rooms", Do: func(now time.Time) (int, error) {
		names, err := jsonNamesIn(roomDir(root), ".messages.json")
		if err != nil {
			return 0, err
		}
		var gone int
		var first error
		for _, id := range names {
			n, err := expireRoom(root, id, now)
			gone += n
			// One room that cannot be read does not keep the others'
			// words past their period.
			if err != nil && first == nil {
				first = fmt.Errorf("room %s: %w", id, err)
			}
		}
		return gone, first
	}}
}

// expireRoom applies one room's retention, under its lock.
func expireRoom(root, id string, now time.Time) (int, error) {
	var r room.Room
	if b, err := readFileMaybe(roomPath(root, id)); err != nil || b == nil {
		return 0, err
	} else if err := json.Unmarshal(b, &r); err != nil {
		return 0, err
	}
	if r.Retention <= 0 {
		// Kept indefinitely, as it says: nothing to lock or read.
		return 0, nil
	}
	l, unlock, err := changeRoom(root, id)
	if err != nil {
		return 0, err
	}
	defer unlock()
	n := l.Expire(now)
	if n == 0 {
		return 0, nil
	}
	if err := compactRoom(root, l.Room().ID, l); err != nil {
		return 0, err
	}
	record(root, audit.Record{
		Action: "room.expired", Resource: "/room/" + l.Room().ID,
		Outcome: audit.Success, Principal: "quilzo", Kind: audit.KindService,
		Verified: true, Detail: map[string]string{"room": l.Room().ID,
			"count": fmt.Sprint(n), "retention": l.Room().Retention.String()},
	})
	return n, nil
}

func roomList(root string) error {
	names, err := jsonNamesIn(roomDir(root), ".messages.json")
	if err != nil {
		return err
	}
	type row struct {
		Room     room.Room `json:"room"`
		Messages int       `json:"messages"`
		Removed  int       `json:"removed"`
		// Unread is what has been said since the caller last read the
		// room, replies in threads included and their own words not.
		Unread int `json:"unread"`
	}
	var rows []row
	caller := resolveCaller(root, flagToken)
	for _, id := range names {
		l, lerr := loadRoom(root, id)
		if lerr != nil {
			return lerr
		}
		// The rooms somebody is in, and the open ones. A list of every
		// direct conversation is a list of who talks to whom.
		if !l.Room().Holds(caller.Name) {
			continue
		}
		r := row{Room: l.Room(), Messages: l.Len(),
			Unread: len(l.Unread(caller.Name, lastRead(root, id, caller.Name),
				false))}
		for _, m := range l.All() {
			if m.Gone() {
				r.Removed++
			}
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Room.ID < rows[j].Room.ID
	})
	if w.JSON(rows) {
		return nil
	}
	if len(rows) == 0 {
		w.Human("no rooms in %s\n", roomDir(root))
		return nil
	}
	for _, r := range rows {
		w.Human("%s%s%s  %s%s%s\n", bold, r.Room.ID, reset, dim,
			r.Room.Kind, reset)
		w.Human("  %s%s%s\n", dim, r.Room.Purpose, reset)
		line := fmt.Sprintf("%d message(s)", r.Messages)
		if r.Unread > 0 {
			line += fmt.Sprintf(", %d unread", r.Unread)
		}
		if r.Removed > 0 {
			line += fmt.Sprintf(", %d removed and still accounted for",
				r.Removed)
		}
		w.Human("  %s%s%s\n", dim, line, reset)
	}
	return nil
}

func roomOpen(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	purpose := fs.String("purpose", "", "what the room is for, in one line")
	kind := fs.String("kind", string(room.Open), "open, closed or direct")
	members := fs.String("members", "", "comma-separated, for a closed room")
	retention := fs.Duration("retention", 0,
		"how long the text is kept, enforced by quilzo serve's sweep; "+
			"indefinitely otherwise")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf(
			"usage: quilzo room open ID --purpose \"...\" [--kind closed]")
	}
	caller := resolveCaller(root, flagToken)
	r := room.Room{
		ID: pos[0], Name: pos[0], Kind: room.Kind(*kind),
		Purpose: strings.TrimSpace(*purpose), Owner: caller.Name,
		Created: time.Now().UTC(), Retention: *retention,
	}
	for _, m := range strings.Split(*members, ",") {
		if strings.TrimSpace(m) != "" {
			r.Members = append(r.Members, strings.TrimSpace(m))
		}
	}
	if r.Kind != room.Open && len(r.Members) == 0 {
		r.Members = []string{caller.Name}
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}
	if b, _ := readFileMaybe(roomPath(root, r.ID)); b != nil {
		return fmt.Errorf("there is already a room called %q", r.ID)
	}
	if err := writeJSON(roomPath(root, r.ID), r); err != nil {
		return err
	}
	record(root, audit.Record{
		Action: "room.opened", Resource: "/room/" + r.ID,
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind, Model: caller.Model,
		Verified: caller.Kind != audit.KindUnknown,
		Detail: map[string]string{"room": r.ID, "kind": string(r.Kind),
			"purpose": r.Purpose},
	})
	if w.JSON(r) {
		return nil
	}
	w.Human("%s%s%s opened\n", bold, r.ID, reset)
	w.Human("  %s%s%s\n", dim, r.Purpose, reset)
	return nil
}

// Loud is the size above which a broadcast asks again.
//
// Twenty. Below it a broadcast is a room; above it, it is an interruption
// somebody should have to mean.
const Loud = 20

func roomSay(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("say", flag.ContinueOnError)
	reply := fs.String("reply", "", "the message this answers")
	anyway := fs.Bool("anyway", false,
		"send a broadcast that would interrupt a large room")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo room say ROOM \"...\" [--reply ID]")
	}
	l, unlock, err := changeRoom(root, pos[0])
	if err != nil {
		return err
	}
	defer unlock()
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}

	// Before anything is sent. The number is the whole point and it is no
	// use afterwards.
	reach := room.Reaches(pos[1], l.Room())
	if reach.Broadcast && reach.People > Loud && !*anyway {
		return fmt.Errorf("%s\n  send it with --anyway if it is worth that",
			reach.Why())
	}

	at := time.Now().UTC()
	id, err := messageID()
	if err != nil {
		return err
	}
	m := room.Message{
		ID: id, Room: l.Room().ID, Author: caller.Name, At: at,
		Reply: strings.TrimSpace(*reply),
		Revisions: []room.Revision{{Text: pos[1], At: at,
			By: caller.Name, Kind: caller.Kind}},
	}
	stored, isNew, err := l.Post(m)
	if err != nil {
		return err
	}
	if err := save(root, l.Room().ID, stored); err != nil {
		return err
	}
	record(root, stored.Record("posted", caller.Name, caller.Kind))

	if w.JSON(map[string]any{"message": stored.ID, "reach": reach,
		"new": isNew}) {
		return nil
	}
	w.Human("%s%s%s\n", bold, stored.ID, reset)
	w.Human("  %s%s%s\n", dim, reach.Why(), reset)
	return nil
}

func messageID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func roomRead(root string, args []string) error {
	pos, flags := leadingArgs(args, 1)
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	thread := fs.String("thread", "", "one thread rather than the room")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo room read ROOM [--thread ID]")
	}
	caller := resolveCaller(root, flagToken)
	l, err := readableRoom(root, pos[0], caller)
	if err != nil {
		return err
	}
	messages := l.All()
	if strings.TrimSpace(*thread) != "" {
		messages, err = l.Thread(*thread)
		if err != nil {
			return err
		}
	} else {
		// The whole room, so what it held is read. Not for one thread: the
		// rest of the room has not been seen.
		markRead(root, l.Room().ID, caller.Name, messages)
	}
	type shown struct {
		room.Message
		Reactions map[string][]string `json:"reactions,omitempty"`
	}
	out := make([]shown, 0, len(messages))
	for _, m := range messages {
		got := l.Reactions(m.ID)
		if len(got) == 0 {
			got = nil
		}
		out = append(out, shown{Message: m, Reactions: got})
	}
	if w.JSON(out) {
		return nil
	}
	for _, m := range messages {
		indent := ""
		if m.Threaded() {
			indent = "    "
		}
		colour := reset
		if m.Gone() {
			colour = dim
		}
		w.Human("%s%s%s%s  %s%s %s%s\n", indent, bold, m.Author, reset,
			dim, m.At.Format("15:04"), m.ID, reset)
		w.Human("%s  %s%s%s\n", indent, colour, m.Says(), reset)
		if got := l.Reactions(m.ID); len(got) > 0 {
			var parts []string
			for emoji, who := range got {
				parts = append(parts, fmt.Sprintf("%s %d", emoji, len(who)))
			}
			sort.Strings(parts)
			w.Human("%s  %s%s%s\n", indent, dim,
				strings.Join(parts, "  "), reset)
		}
	}
	return nil
}

// lastRead is when somebody last read a room, or the zero time if never.
func lastRead(root, id, who string) time.Time {
	var seen map[string]time.Time
	if err := loadJSON(roomSeen(root, id), &seen); err != nil {
		return time.Time{}
	}
	return seen[strings.ToLower(who)]
}

// markRead records that somebody has read a room up to the newest message
// they were shown.
//
// The newest message's time and not the clock's: a message another process
// stamped a moment before this read finished, and that this read never
// showed, stays unread. Never moved back. A failure to write is not a
// failure to read, so it is left for the next read to try.
func markRead(root, id, who string, shown []room.Message) {
	var newest time.Time
	for _, m := range shown {
		if m.At.After(newest) {
			newest = m.At
		}
	}
	if newest.IsZero() {
		return
	}
	_ = atomicfile.Update(roomSeen(root, id), func(seen *map[string]time.Time) error {
		if *seen == nil {
			*seen = map[string]time.Time{}
		}
		key := strings.ToLower(who)
		if !newest.After((*seen)[key]) {
			return atomicfile.ErrUnchanged
		}
		(*seen)[key] = newest
		return nil
	})
}

// roomReact puts a reaction on a message, or takes it back.
//
// `room read` showed reactions and nothing could make one: room.Log.React
// held them in memory, no command called it, and nothing was kept. They
// are appended beside the messages, like an edit, and somebody must be in
// the room to react in it.
func roomReact(root string, args []string) error {
	pos, flags := leadingArgs(args, 3)
	fs := flag.NewFlagSet("react", flag.ContinueOnError)
	off := fs.Bool("off", false, "take the reaction back")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 3 {
		return fmt.Errorf("usage: quilzo room react ROOM MESSAGE EMOJI [--off]")
	}
	l, unlock, err := changeRoom(root, pos[0])
	if err != nil {
		return err
	}
	defer unlock()
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}
	r := room.Reaction{Message: pos[1], Emoji: strings.TrimSpace(pos[2]),
		By: caller.Name, At: time.Now().UTC(), Off: *off}
	if err := l.React(r); err != nil {
		return err
	}
	if err := appendJSONL(roomReactions(root, l.Room().ID), r); err != nil {
		return err
	}
	action := "room.reacted"
	if r.Off {
		action = "room.unreacted"
	}
	record(root, caller.auditRecord(action, "/room/"+l.Room().ID,
		audit.Success, map[string]string{"room": l.Room().ID,
			"message": r.Message, "emoji": r.Emoji}))
	got := l.Reactions(r.Message)
	if w.JSON(map[string]any{"message": r.Message, "reactions": got}) {
		return nil
	}
	var parts []string
	for emoji, who := range got {
		parts = append(parts, fmt.Sprintf("%s %d", emoji, len(who)))
	}
	sort.Strings(parts)
	w.Human("%s%s%s  %s%s%s\n", bold, r.Message, reset, dim,
		strings.Join(parts, "  "), reset)
	return nil
}

func roomEdit(root string, args []string) error {
	pos, _ := leadingArgs(args, 3)
	if len(pos) != 3 {
		return fmt.Errorf("usage: quilzo room edit ROOM MESSAGE \"...\"")
	}
	l, unlock, err := changeRoom(root, pos[0])
	if err != nil {
		return err
	}
	defer unlock()
	caller := resolveCaller(root, flagToken)
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}
	m, err := l.Edit(pos[1], room.Revision{Text: pos[2],
		At: time.Now().UTC(), By: caller.Name, Kind: caller.Kind})
	if err != nil {
		return err
	}
	if err := save(root, l.Room().ID, m); err != nil {
		return err
	}
	record(root, m.Record("edited", caller.Name, caller.Kind))
	if w.JSON(m) {
		return nil
	}
	w.Human("%s%s%s\n", bold, m.ID, reset)
	w.Human("  %s%s%s\n", dim, m.Says(), reset)
	w.Human("  %squilzo room history %s %s shows what it said before%s\n",
		dim, l.Room().ID, m.ID, reset)
	return nil
}

func roomRemove(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	because := fs.String("because", "",
		"why, which taking down somebody else's words requires")
	erase := fs.Bool("erase", false,
		"an Article 17 erasure: the words go from the log as well")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo room remove ROOM MESSAGE " +
			"[--because ...] [--erase]")
	}
	l, unlock, err := changeRoom(root, pos[0])
	if err != nil {
		return err
	}
	defer unlock()
	existing, ok := l.Get(pos[1])
	if !ok {
		return fmt.Errorf("there is no message %s in %s", pos[1], pos[0])
	}
	caller := resolveCaller(root, flagToken)
	why := room.ByAuthor
	switch {
	case *erase:
		why = room.ByErasure
	case !strings.EqualFold(caller.Name, existing.Author):
		why = room.ByModerator
	}
	// Taking down somebody else's words, or erasing under Article 17, is a
	// statement the organisation stands behind.
	act := auth.ActEditDraft
	if why != room.ByAuthor {
		act = auth.ActPublish
	}
	if err := authorise(root, caller, act, "/"); err != nil {
		return err
	}
	m, err := l.Remove(pos[1], room.Tombstone{
		At: time.Now().UTC(), By: caller.Name, Kind: caller.Kind,
		Why: why, Because: strings.TrimSpace(*because),
	})
	if err != nil {
		return err
	}
	// An erasure rewrites the file without the words; any other removal
	// keeps them in the log, out of the room, and is appended.
	if why.Erases() {
		err = compactRoom(root, l.Room().ID, l)
	} else {
		err = save(root, l.Room().ID, m)
	}
	if err != nil {
		return err
	}
	record(root, m.Record("removed", caller.Name, caller.Kind))
	// Somebody outside a closed room may still take a message down, as a
	// moderator or for an erasure; they are told what they did and not
	// what it said, which a removal other than an erasure keeps for the
	// room's members.
	shown := *m
	if !l.Room().Holds(caller.Name) {
		shown.Revisions = make([]room.Revision, len(m.Revisions))
		for i, r := range m.Revisions {
			r.Text = ""
			shown.Revisions[i] = r
		}
	}
	if w.JSON(shown) {
		return nil
	}
	w.Human("%s%s%s\n", bold, m.ID, reset)
	w.Human("  %s%s%s\n", dim, m.Says(), reset)
	if why != room.ByErasure {
		w.Human("  %sthe words are gone and the shape is not: a message "+
			"that vanished and one that was never sent stay different "+
			"facts%s\n", dim, reset)
	} else {
		w.Human("  %sthe words are gone from %s; a backup made before now "+
			"keeps them until backup.keep rotates it out%s\n", dim,
			roomMessages(root, l.Room().ID), reset)
	}
	return nil
}

func roomHistory(root string, args []string) error {
	pos, _ := leadingArgs(args, 2)
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo room history ROOM MESSAGE")
	}
	l, err := readableRoom(root, pos[0], resolveCaller(root, flagToken))
	if err != nil {
		return err
	}
	m, ok := l.Get(pos[1])
	if !ok {
		return fmt.Errorf("there is no message %s in %s", pos[1], pos[0])
	}
	if w.JSON(map[string]any{"message": m, "history": m.History()}) {
		return nil
	}
	w.Human("%s%s%s by %s\n", bold, m.ID, reset, m.Author)
	for i, r := range m.History() {
		mark := dim
		if i == len(m.History())-1 && !m.Gone() {
			mark = reset
		}
		w.Human("  %s%s%s  %s%s%s\n", dim, r.At.Format("2006-01-02 15:04"),
			reset, mark, r.Text, reset)
		w.Human("    %s%s%s\n", dim, r.Digest(), reset)
	}
	if m.Gone() {
		w.Human("\n  %s%s%s\n", yellow, m.Says(), reset)
	}
	w.Human("\n  %severy line above is in the audit chain as a digest, so "+
		"what this said on any day is provable without the log holding a "+
		"word of it%s\n", dim, reset)
	return nil
}
