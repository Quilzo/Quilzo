// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

// Package board keeps what a site's members write: comments under a page,
// posts in a discussion.
//
// # What a board is
//
// A declaration, like a form: a name, a title, whether posts wait for a
// person before anybody else sees them, how long one may be, and whether it
// is open. A page carries a comments section naming a board, and that page
// is the board's thread for it. The owner decides where members may write;
// members cannot make a board or a thread of their own.
//
// # Why posts are files and not content
//
// For the reason accounts and form submissions are: a post is somebody's
// words, which they may take back, and which a person may have to remove.
// The content store keeps everything forever by design. So each post is a
// plain file, deleted when its author deletes it, when staff remove it, or
// when its author's account is deleted.
//
// # What a post may contain
//
// Text. It is stored as written and escaped where it is shown; no markup,
// no links that render as links, no images. A comment box that takes HTML is
// a comment box that eventually serves somebody's script.
//
// # Files
//
//	boards/BOARD/THREAD/ID.json   one post; THREAD is a hash of the page name
package board

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// Board is one declared place members may write.
type Board struct {
	Name  string `json:"name"`
	Title string `json:"title"`
	// Moderation is "pre", a post waits for a person before anybody else
	// sees it, or "post", it is shown at once and can be removed.
	Moderation string `json:"moderation"`
	// MaxLength bounds a post, in characters. Zero is the default.
	MaxLength int `json:"max_length,omitempty"`
	// Closed boards keep what is there and take nothing new.
	Closed bool `json:"closed,omitempty"`
}

// Limits.
const (
	DefaultLength = 2000
	MaxLength     = 10000
	// MaxPerThread bounds what one thread shows and keeps.
	MaxPerThread = 500
)

var reName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)

// Validate refuses a declaration that could not work.
func (b Board) Validate() error {
	if !reName.MatchString(b.Name) {
		return fmt.Errorf("%q is not a usable name: lower-case letters, digits and hyphens", b.Name)
	}
	if strings.TrimSpace(b.Title) == "" {
		return fmt.Errorf("%s needs a title", b.Name)
	}
	if b.Moderation != "pre" && b.Moderation != "post" {
		return fmt.Errorf("%s: moderation is pre, held until a person approves, or post, shown at once", b.Name)
	}
	if b.MaxLength < 0 || b.MaxLength > MaxLength {
		return fmt.Errorf("%s: a post is at most %d characters", b.Name, MaxLength)
	}
	return nil
}

// Limit is the longest post this board takes.
func (b Board) Limit() int {
	if b.MaxLength > 0 {
		return b.MaxLength
	}
	return DefaultLength
}

// Set is every board a site declares.
type Set struct {
	Boards []Board `json:"boards"`
}

// Get finds one.
func (s *Set) Get(name string) (Board, bool) {
	for _, b := range s.Boards {
		if b.Name == name {
			return b, true
		}
	}
	return Board{}, false
}

// Put adds or replaces one, after validating it.
func (s *Set) Put(b Board) error {
	if err := b.Validate(); err != nil {
		return err
	}
	for i := range s.Boards {
		if s.Boards[i].Name == b.Name {
			s.Boards[i] = b
			return nil
		}
	}
	s.Boards = append(s.Boards, b)
	sort.Slice(s.Boards, func(i, j int) bool { return s.Boards[i].Name < s.Boards[j].Name })
	return nil
}

// Remove takes one away; its posts stay until deleted.
func (s *Set) Remove(name string) bool {
	for i := range s.Boards {
		if s.Boards[i].Name == name {
			s.Boards = append(s.Boards[:i], s.Boards[i+1:]...)
			return true
		}
	}
	return false
}

// Load reads a set from a file; a missing file is an empty set.
func Load(path string) (*Set, error) {
	s := &Set{}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, bd := range s.Boards {
		if err := bd.Validate(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Save writes a set.
func Save(path string, s *Set) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}

// -- posts ------------------------------------------------------------------

// States a post is in.
const (
	Visible = "visible"
	Held    = "held"
)

// Post is one thing a member wrote.
type Post struct {
	ID     string `json:"id"`
	Board  string `json:"board"`
	Thread string `json:"thread"`
	// Author is the member's account id; Name is what they were called when
	// they wrote it, so renaming does not rewrite history and a deleted
	// account's posts are deleted rather than left nameless.
	Author  string    `json:"author"`
	Name    string    `json:"name"`
	Body    string    `json:"body"`
	Created time.Time `json:"created"`
	Edited  time.Time `json:"edited,omitempty"`
	State   string    `json:"state"`
}

// Errors a caller distinguishes.
var (
	ErrNotFound = errors.New("no such post")
	ErrNotYours = errors.New("that post is not yours")
)

// Store keeps posts in a directory.
type Store struct {
	Dir string
	Now func() time.Time
	mu  sync.Mutex
}

// Open returns the store under dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// CleanBody is a post as it will be kept: trimmed, controls removed but for
// line breaks, runs of blank lines collapsed. It returns why a body cannot
// be posted at all.
func CleanBody(body string, limit int) (string, error) {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return -1
		}
		return r
	}, body)
	for strings.Contains(body, "\n\n\n") {
		body = strings.ReplaceAll(body, "\n\n\n", "\n\n")
	}
	body = strings.TrimSpace(body)
	if body == "" {
		return "", fmt.Errorf("write something first")
	}
	if n := utf8.RuneCountInString(body); n > limit {
		return "", fmt.Errorf("that is %d characters; this board takes %d", n, limit)
	}
	return body, nil
}

// Add stores a post. Its state comes from the board's moderation.
func (s *Store) Add(b Board, thread, author, name, body string) (Post, error) {
	if b.Closed {
		return Post{}, fmt.Errorf("%s is closed to new posts", b.Title)
	}
	clean, err := CleanBody(body, b.Limit())
	if err != nil {
		return Post{}, err
	}
	if thread == "" || author == "" {
		return Post{}, fmt.Errorf("a post needs a thread and an author")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := s.count(b.Name, thread); n >= MaxPerThread {
		return Post{}, fmt.Errorf("this thread is full")
	}
	id := randomID()
	state := Visible
	if b.Moderation == "pre" {
		state = Held
	}
	p := Post{ID: id, Board: b.Name, Thread: thread, Author: author, Name: name,
		Body: clean, Created: s.now(), State: state}
	return p, s.write(p)
}

// Thread is a thread's posts, oldest first: every visible one, and the
// viewer's own held ones, so somebody can see what they wrote is waiting.
func (s *Store) Thread(board, thread, viewer string) []Post {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Post
	dir, ok := s.threadDir(board, thread)
	if !ok {
		return nil
	}
	for _, p := range s.readDir(dir) {
		if p.State == Visible || (viewer != "" && p.Author == viewer) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// Version names the visible state of a thread, for a page's ETag: it
// changes when a post appears, changes or goes.
func (s *Store) Version(board, thread string) string {
	h := sha256.New()
	for _, p := range s.Thread(board, thread, "") {
		fmt.Fprintf(h, "%s %d %d\n", p.ID, p.Created.UnixNano(), p.Edited.UnixNano())
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Held is every post waiting for a person, oldest first.
func (s *Store) Held() []Post {
	return s.filter(func(p Post) bool { return p.State == Held }, false)
}

// Recent is the newest posts across every board, for the moderation screen.
func (s *Store) Recent(n int) []Post {
	all := s.filter(func(p Post) bool { return p.State == Visible }, true)
	if len(all) > n {
		all = all[:n]
	}
	return all
}

// ByAuthor is a member's own posts, newest first.
func (s *Store) ByAuthor(author string) []Post {
	return s.filter(func(p Post) bool { return p.Author == author }, true)
}

// Get finds one post by id.
func (s *Store) Get(id string) (Post, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, p, err := s.find(id)
	_ = path
	return p, err
}

// Approve shows a held post.
func (s *Store) Approve(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, p, err := s.find(id)
	if err != nil {
		return err
	}
	p.State = Visible
	return s.write(p)
}

// Remove deletes a post outright: staff removing it, or its author
// deleting it. author empty means staff; otherwise it must be theirs.
func (s *Store) Remove(id, author string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, p, err := s.find(id)
	if err != nil {
		return err
	}
	if author != "" && p.Author != author {
		return ErrNotYours
	}
	return os.Remove(path)
}

// Edit changes the text of one's own post. In a board that holds posts,
// an edited post waits again: an approval was of the words approved.
func (s *Store) Edit(b Board, id, author, body string) (Post, error) {
	clean, err := CleanBody(body, b.Limit())
	if err != nil {
		return Post{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, p, err := s.find(id)
	if err != nil {
		return Post{}, err
	}
	if p.Author != author {
		return Post{}, ErrNotYours
	}
	p.Body, p.Edited = clean, s.now()
	if b.Moderation == "pre" {
		p.State = Held
	}
	return p, s.write(p)
}

// RemoveAuthor deletes every post by a member, for an account deleted.
func (s *Store) RemoveAuthor(author string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	s.walk(func(path string, p Post) {
		if p.Author == author {
			if os.Remove(path) == nil {
				n++
			}
		}
	})
	return n
}

// -- files ------------------------------------------------------------------

var reID = regexp.MustCompile(`^[0-9a-f]{24}$`)

func randomID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// threadDir is where a thread's posts live: the board's name, which must be
// one a board can have, and the page name hashed. So no part of the path is
// anything a request named: a caller passing a board name straight from an
// address gets nothing back rather than a path somewhere else.
func (s *Store) threadDir(board, thread string) (string, bool) {
	if !reName.MatchString(board) {
		return "", false
	}
	sum := sha256.Sum256([]byte(thread))
	return filepath.Join(s.Dir, board, hex.EncodeToString(sum[:])[:32]), true
}

func (s *Store) write(p Post) error {
	dir, ok := s.threadDir(p.Board, p.Thread)
	if !ok || !reID.MatchString(p.ID) {
		return fmt.Errorf("that post cannot be stored")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, p.ID+".json"), b, 0o600)
}

func (s *Store) readDir(dir string) []Post {
	entries, _ := os.ReadDir(dir)
	var out []Post
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var p Post
		if json.Unmarshal(b, &p) == nil && p.ID+".json" == e.Name() {
			out = append(out, p)
		}
	}
	return out
}

func (s *Store) count(board, thread string) int {
	dir, ok := s.threadDir(board, thread)
	if !ok {
		return 0
	}
	entries, _ := os.ReadDir(dir)
	return len(entries)
}

// walk visits every post in every board.
func (s *Store) walk(fn func(path string, p Post)) {
	boards, _ := os.ReadDir(s.Dir)
	for _, b := range boards {
		if !b.IsDir() || !reName.MatchString(b.Name()) {
			continue
		}
		threads, _ := os.ReadDir(filepath.Join(s.Dir, b.Name()))
		for _, t := range threads {
			dir := filepath.Join(s.Dir, b.Name(), t.Name())
			for _, p := range s.readDir(dir) {
				fn(filepath.Join(dir, p.ID+".json"), p)
			}
		}
	}
}

func (s *Store) find(id string) (string, Post, error) {
	if !reID.MatchString(id) {
		return "", Post{}, ErrNotFound
	}
	var path string
	var found Post
	s.walk(func(pth string, p Post) {
		if p.ID == id {
			path, found = pth, p
		}
	})
	if path == "" {
		return "", Post{}, ErrNotFound
	}
	return path, found, nil
}

func (s *Store) filter(keep func(Post) bool, newestFirst bool) []Post {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Post
	s.walk(func(_ string, p Post) {
		if keep(p) {
			out = append(out, p)
		}
	})
	sort.Slice(out, func(i, j int) bool {
		if newestFirst {
			return out[i].Created.After(out[j].Created)
		}
		return out[i].Created.Before(out[j].Created)
	})
	return out
}
