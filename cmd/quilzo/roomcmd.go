// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/room"
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
	default:
		return fmt.Errorf("unknown room command %q; try list, open, say, "+
			"read, edit, remove or history", args[0])
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
	return l, err
}

// save appends a message's current state.
//
// The file is a log and the last entry for an identifier wins on replay,
// which is the same fold internal/finding uses for a decision: nothing is
// rewritten in place, so a reader with the file has every version.
func save(root, id string, m *room.Message) error {
	return appendJSONL(roomMessages(root, id), m)
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
	}
	var rows []row
	for _, id := range names {
		l, lerr := loadRoom(root, id)
		if lerr != nil {
			return lerr
		}
		r := row{Room: l.Room(), Messages: l.Len()}
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
		"how long the text is kept; indefinitely otherwise")
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
		Outcome: audit.Success, Principal: caller.Name, Kind: caller.Kind,
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
	l, err := loadRoom(root, pos[0])
	if err != nil {
		return err
	}
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
	l, err := loadRoom(root, pos[0])
	if err != nil {
		return err
	}
	messages := l.All()
	if strings.TrimSpace(*thread) != "" {
		messages, err = l.Thread(*thread)
		if err != nil {
			return err
		}
	}
	if w.JSON(messages) {
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

func roomEdit(root string, args []string) error {
	pos, _ := leadingArgs(args, 3)
	if len(pos) != 3 {
		return fmt.Errorf("usage: quilzo room edit ROOM MESSAGE \"...\"")
	}
	l, err := loadRoom(root, pos[0])
	if err != nil {
		return err
	}
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
	l, err := loadRoom(root, pos[0])
	if err != nil {
		return err
	}
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
	if err := save(root, l.Room().ID, m); err != nil {
		return err
	}
	record(root, m.Record("removed", caller.Name, caller.Kind))
	if w.JSON(m) {
		return nil
	}
	w.Human("%s%s%s\n", bold, m.ID, reset)
	w.Human("  %s%s%s\n", dim, m.Says(), reset)
	if why != room.ByErasure {
		w.Human("  %sthe words are gone and the shape is not: a message "+
			"that vanished and one that was never sent stay different "+
			"facts%s\n", dim, reset)
	}
	return nil
}

func roomHistory(root string, args []string) error {
	pos, _ := leadingArgs(args, 2)
	if len(pos) != 2 {
		return fmt.Errorf("usage: quilzo room history ROOM MESSAGE")
	}
	l, err := loadRoom(root, pos[0])
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
