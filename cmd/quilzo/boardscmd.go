// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"flag"
	"fmt"
	"path/filepath"

	"github.com/quilzo/quilzo/internal/admin"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/board"
	"github.com/quilzo/quilzo/internal/public"
	"github.com/quilzo/quilzo/internal/throttle"
)

// Boards: where a site's members may write, and the moderation of what they
// do. See internal/board. Declaring a board is a publish — it opens a place
// on the site where people other than its staff put words — and moderating
// one is editing the site.

func boardsPath(root string) string { return filepath.Join(root, "boards.json") }
func postsDir(root string) string   { return filepath.Join(root, "boards") }

func loadBoards(root string) (*board.Set, error) { return board.Load(boardsPath(root)) }

func openPosts(root string) (*board.Store, error) { return board.Open(postsDir(root)) }

// siteBoards is the public site's boards, or nil when the store cannot open.
func siteBoards(root string) *public.Boards {
	store, err := openPosts(root)
	if err != nil {
		return nil
	}
	return &public.Boards{
		Set:   func() (*board.Set, error) { return loadBoards(root) },
		Store: store,
		Limit: throttle.New(throttlePolicy(mustConfig(root))),
		Audit: func(action, id, name, page string, ok bool) {
			outcome := audit.Success
			if !ok {
				outcome = audit.Denied
			}
			// Who, which board and which page; never what they wrote.
			record(root, audit.Record{Action: action, Resource: "/" + page,
				Outcome: outcome, Principal: "member:" + id, Kind: audit.KindUnknown,
				Detail: map[string]string{"board": name}})
		},
	}
}

func boardUsage() error {
	return fmt.Errorf("usage: quilzo board list | add NAME --title T --moderation pre|post [--max N] [--closed] | " +
		"remove NAME | held | recent | approve ID | delete ID")
}

func cmdBoard(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	caller := resolveCaller(root, "")
	note := func(action, id string) error {
		return recordE(root, caller.auditRecord(action, "/", audit.Success,
			map[string]string{"board": id}))
	}
	posts, err := openPosts(root)
	if err != nil {
		return err
	}
	switch args[0] {
	case "list":
		set, err := loadBoards(root)
		if err != nil {
			return err
		}
		if w.JSON(set) {
			return nil
		}
		if len(set.Boards) == 0 {
			w.Human("  no boards; quilzo board add comments --title Comments --moderation post\n")
		}
		for _, b := range set.Boards {
			state := map[string]string{"pre": "held until a person approves", "post": "shown at once"}[b.Moderation]
			if b.Closed {
				state += ", closed"
			}
			w.Human("  %s%s%s  %s  (%s, up to %d characters)\n", bold, b.Name, reset, onOneLine(b.Title), state, b.Limit())
		}
		return nil
	case "add":
		pos, flags := leadingArgs(args[1:], 1)
		fs := flag.NewFlagSet("board add", flag.ContinueOnError)
		title := fs.String("title", "", "what the board is called on the page")
		mod := fs.String("moderation", "post", "pre: held until a person approves; post: shown at once")
		max := fs.Int("max", 0, fmt.Sprintf("longest post in characters (default %d)", board.DefaultLength))
		closed := fs.Bool("closed", false, "keep what is there and take nothing new")
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) != 1 {
			return boardUsage()
		}
		set, err := loadBoards(root)
		if err != nil {
			return err
		}
		b := board.Board{Name: pos[0], Title: *title, Moderation: *mod, MaxLength: *max, Closed: *closed}
		if err := set.Put(b); err != nil {
			return err
		}
		if err := board.Save(boardsPath(root), set); err != nil {
			return err
		}
		w.Human("declared %s; a page shows it with a comments section naming %q\n", b.Name, b.Name)
		return note("board.declare", b.Name)
	case "remove":
		if len(args) != 2 {
			return boardUsage()
		}
		set, err := loadBoards(root)
		if err != nil {
			return err
		}
		if !set.Remove(args[1]) {
			return fmt.Errorf("no board %q", args[1])
		}
		if err := board.Save(boardsPath(root), set); err != nil {
			return err
		}
		w.Human("removed %s; its posts stay until deleted, and no page shows them\n", args[1])
		return note("board.remove", args[1])
	case "held", "recent":
		list := posts.Held()
		if args[0] == "recent" {
			list = posts.Recent(50)
		}
		if w.JSON(map[string]any{"posts": list}) {
			return nil
		}
		if len(list) == 0 {
			w.Human("  nothing %s\n", map[string]string{"held": "waiting", "recent": "posted"}[args[0]])
		}
		for _, p := range list {
			w.Human("  %s  %s on /%s by %s, %s\n    %s\n", p.ID, p.Board, onOneLine(p.Thread),
				onOneLine(p.Name), p.Created.Format("2 Jan 15:04"), onOneLine(truncate(p.Body, 100)))
		}
		return nil
	case "approve", "delete":
		if len(args) != 2 {
			return boardUsage()
		}
		if args[0] == "approve" {
			err = posts.Approve(args[1])
		} else {
			err = posts.Remove(args[1], "")
		}
		if err != nil {
			return err
		}
		w.Human("%sd %s\n", map[string]string{"approve": "approve", "delete": "delete"}[args[0]], args[1])
		return note("board.post-"+args[0]+"d", args[1])
	}
	return boardUsage()
}

// boardsHooks is the admin's Boards screen.
func boardsHooks(root string) *admin.BoardsAdmin {
	posts, err := openPosts(root)
	if err != nil {
		return nil
	}
	note := func(action, by, id string) error {
		return recordE(root, audit.Record{Action: action, Resource: "/", Outcome: audit.Success,
			Principal: by, Kind: audit.KindHuman, Detail: map[string]string{"board": id}})
	}
	return &admin.BoardsAdmin{
		Set: func() (*board.Set, error) { return loadBoards(root) },
		Save: func(b board.Board, by string) error {
			set, err := loadBoards(root)
			if err != nil {
				return err
			}
			if err := set.Put(b); err != nil {
				return err
			}
			if err := board.Save(boardsPath(root), set); err != nil {
				return err
			}
			return note("board.declare", by, b.Name)
		},
		Remove: func(name, by string) error {
			set, err := loadBoards(root)
			if err != nil {
				return err
			}
			if !set.Remove(name) {
				return fmt.Errorf("no board %q", name)
			}
			if err := board.Save(boardsPath(root), set); err != nil {
				return err
			}
			return note("board.remove", by, name)
		},
		Held:   posts.Held,
		Recent: func() []board.Post { return posts.Recent(50) },
		Approve: func(id, by string) error {
			if err := posts.Approve(id); err != nil {
				return err
			}
			return note("board.post-approved", by, id)
		},
		Delete: func(id, by string) error {
			if err := posts.Remove(id, ""); err != nil {
				return err
			}
			return note("board.post-deleted", by, id)
		},
	}
}
