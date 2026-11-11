// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// The ref lock is atomicfile's file lock, not a copy of it.
//
// The store's lock_unix.go and lock_windows.go were atomicfile's, line for
// line, package clause aside. A fix to one (the byte range Windows locks, a
// retry when flock is interrupted) would have reached the other only if
// somebody remembered it was there, and two writers that lock the same file
// two different ways are two writers that both proceed. So no file of this
// package, on any platform, may reach the kernel's lock itself: it calls
// atomicfile, and the check reads every file whatever its build tag, because
// the Windows copy is the one a Linux test run never compiles.
func TestTheRefLockIsTheOneFileLock(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := n.X.(*ast.Ident); ok && id.Name == "syscall" && (n.Sel.Name == "Flock" || n.Sel.Name == "NewLazyDLL") {
					t.Errorf("%s: %s.%s is a lock of the store's own; call atomicfile.LockFile", fset.Position(n.Pos()), id.Name, n.Sel.Name)
				}
			case *ast.BasicLit:
				if n.Kind == token.STRING && strings.Contains(n.Value, "LockFileEx") {
					t.Errorf("%s: the store reaches LockFileEx itself; call atomicfile.LockFile", fset.Position(n.Pos()))
				}
			}
			return true
		})
	}
}

// The ref lock and atomicfile's lock on the same file shut each other out,
// which is what being one lock means to a second process.
func TestTheRefLockWaitsForAnAtomicfileLockOnTheSameFile(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	release, err := atomicfile.Lock(filepath.Join(s.root, "refs.lock"))
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{})
	go func() {
		_ = s.WithRefLock(func() error { return nil })
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("the ref lock was taken while another descriptor held it")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the ref lock was not taken after the other descriptor let it go")
	}
	if _, err := os.Stat(filepath.Join(s.root, "refs.lock")); err != nil {
		t.Fatal(err)
	}
}
