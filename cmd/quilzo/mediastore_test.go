package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// An accepted upload has to reach the library.
//
// `quilzo media add` validated the bytes, wrote an audit record saying the
// upload had succeeded, printed "accepted", and dropped the file. Nothing was
// ever stored, so nothing was ever served, and the audit log said otherwise —
// which is worse than the missing feature, because a log that records a write
// that did not happen is a log you cannot use.
//
// internal/medialib was written for exactly this and its own package comment
// says so: "stores accepted uploads, which nothing did". It existed and no
// command was wired to it. Found by adding three images for a demonstration and
// finding an empty picker.
//
// So this is a source test rather than a behaviour one, for the same reason the
// type-gate test is: the failure is a missing call, and the place to catch a
// missing call is where somebody adds the next surface that forgets it.
func TestEveryAcceptedUploadIsStored(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "importcmd.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	checked := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// A function that accepts media is a function that has to store it.
		if !calls(fn, "Accept") {
			continue
		}
		// importMedia writes what an archive already carried and is not an
		// acceptance path of its own; it is recognised by storing too.
		checked++
		if !calls(fn, "Put") {
			t.Errorf("%s calls media.Accept and never stores the result.\n"+
				"  An upload that is validated and dropped is a file the "+
				"library does not have, an audit record that is not true, and "+
				"a page that will 404 on its own image.", fn.Name.Name)
		}
	}
	if checked == 0 {
		t.Fatal("no acceptance path found in importcmd.go; this test would " +
			"pass by checking nothing")
	}
	t.Logf("%d acceptance path(s) checked", checked)
}

// And the message has to match. "accepted" described what the command did to
// the bytes; it is the library that a person is asking about.
func TestTheUploadMessageSaysItWasStored(t *testing.T) {
	raw, err := os.ReadFile("importcmd.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if strings.Contains(body, `w.Human("accepted %s%s%s`) {
		t.Error("the upload still reports 'accepted', which is what happened " +
			"to the bytes rather than what happened to the file")
	}
	if !strings.Contains(body, "stored") {
		t.Error("nothing in the upload path says the file was stored")
	}
}

// The id a media command prints is the id a page can use.
//
// `media add` printed f.ID[:32]. An id is a sha256 and the server looks up the
// whole thing, so half of one is a value that reads like an answer and 404s
// when you put it in a page. Nothing in the audit record cares — it stores a
// deliberately short form — but the line a person copies has to be complete.
//
// The audit helper short() is exempt: an audit detail is a reference for a human
// reading a log, not a value anything resolves.
func TestNoMediaCommandPrintsATruncatedID(t *testing.T) {
	source, err := os.ReadFile("importcmd.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(source), "\n") {
		if !strings.Contains(line, "w.Human(") {
			continue
		}
		if strings.Contains(line, ".ID[:") {
			t.Errorf("this line prints part of an id, which does not resolve:"+
				"\n\t%s", strings.TrimSpace(line))
		}
	}
	if !strings.Contains(string(source), "in a page: /media/%s") {
		t.Error("storing a file should print the path a page asks for; " +
			"otherwise everybody assembles it from the id by hand")
	}

	// The same for the media listing an assistant reads. That one matters more:
	// a person who gets a 404 investigates, and a model writes the short id
	// into the page and reports success.
	ops, err := os.ReadFile("mcpops.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(ops), "\n") {
		if strings.Contains(line, "f.ID[:") {
			t.Errorf("the media listing shortens an id, and whatever reads it "+
				"will put that in a page:\n\t%s", strings.TrimSpace(line))
		}
	}
}

// Every interface that can add a file can take one out.
//
// The admin has had a delete button since the library existed and the command
// line had nothing, so a file could be uploaded from three places and removed
// from one — an operator working in a terminal had no way to undo an upload.
// This is the parity check, done on the source: the dispatch has to know the
// verb, the help has to mention it, and the privilege table has to place it,
// because a command missing from that table is refused as unknown.
func TestTheCommandLineCanRemoveMediaToo(t *testing.T) {
	source, err := os.ReadFile("importcmd.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), `case "remove":`) {
		t.Error("media has no remove subcommand, and the admin has had the " +
			"button all along")
	}
	if !strings.Contains(string(source), "func mediaRemove(") {
		t.Error("no mediaRemove")
	}
	// It refuses a file the live site uses, because a command that quietly
	// breaks a published page is not the visible failure the storage layer's
	// comment argues for.
	if !strings.Contains(string(source), "mediaInUse") {
		t.Error("nothing checks whether the file is in use before removing it")
	}

	help, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(help), "media remove") {
		t.Error("the help does not list media remove; a command nobody can " +
			"find is a command nobody uses")
	}
	priv, err := os.ReadFile("privilege.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(priv), `"media remove"`) {
		t.Error("media remove is not in the privilege table, so it is either " +
			"refused as unknown or runs with the wrong authority")
	}
}
