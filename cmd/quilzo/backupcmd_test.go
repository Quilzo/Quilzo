// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/backup"
	"github.com/quilzo/quilzo/internal/site"
	"github.com/quilzo/quilzo/internal/store"
)

// A store is backed up whole, checked, and restored into an empty
// directory as a store whose history checks and whose site is the same.
func TestAStoreIsBackedUpAndRestored(t *testing.T) {
	root := demoStore(t)
	key, _ := backup.NewKey()
	t.Setenv(backupKeyEnv, backup.EncodeKey(key))
	file := filepath.Join(t.TempDir(), "store.qzb")
	if err := cmdBackup(root, []string{"create", file, "--templates", filepath.Join(filepath.Dir(root), "templates")}); err != nil {
		t.Fatal(err)
	}
	if err := cmdBackup(root, []string{"verify", file}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(file)
	cfg, _ := os.ReadFile(filepath.Join(root, "config.json"))
	if len(cfg) > 20 && strings.Contains(string(raw), string(cfg[:20])) {
		t.Fatal("the backup can be read without its key")
	}
	into := filepath.Join(t.TempDir(), "restored")
	if err := cmdBackup(root, []string{"restore", file, "--into", into}); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(into, "store")
	s, err := store.Open(restored)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.Verify(); err != nil || n == 0 {
		t.Fatalf("%d objects, %v", n, err)
	}
	orig, _ := store.Open(root)
	a, _ := site.PagesAt(orig, site.RefDraft)
	b, _ := site.PagesAt(s, site.RefDraft)
	if len(a) == 0 || len(a) != len(b) {
		t.Fatalf("%d pages, restored %d", len(a), len(b))
	}
	// Another key reads nothing.
	other, _ := backup.NewKey()
	t.Setenv(backupKeyEnv, backup.EncodeKey(other))
	if err := cmdBackup(root, []string{"verify", file}); err == nil {
		t.Fatal("read with another key")
	}
	t.Setenv(backupKeyEnv, "")
	if err := cmdBackup(root, []string{"create", file + "2"}); err == nil || !strings.Contains(err.Error(), "backup key") {
		t.Fatalf("made without a key: %v", err)
	}
}

// With backup.dir set, a backup a day: made, checked, the oldest let go
// past backup.keep, and none made twice in a day.
func TestADailyBackupKeepsItsNumber(t *testing.T) {
	root := demoStore(t)
	key, _ := backup.NewKey()
	t.Setenv(backupKeyEnv, backup.EncodeKey(key))
	dir := filepath.Join(t.TempDir(), "backups")
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("backup.dir", dir, "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("backup.keep", "2", "a test", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	job := backupJob(root)
	now := time.Now()
	for i, made := range []int{1, 0} {
		n, err := job.Do(now)
		if err != nil || n != made {
			t.Fatalf("run %d: %d %v", i, n, err)
		}
	}
	// Older backups, as days pass.
	for d := 1; d <= 2; d++ {
		kept, _ := filepath.Glob(filepath.Join(dir, "quilzo-*.qzb"))
		for _, k := range kept {
			old := now.Add(-48 * time.Hour)
			os.Chtimes(k, old, old)
		}
		if n, err := job.Do(now.Add(time.Duration(d) * time.Second)); err != nil || n != 1 {
			t.Fatalf("day %d: %d %v", d, n, err)
		}
	}
	kept, _ := filepath.Glob(filepath.Join(dir, "quilzo-*.qzb"))
	if len(kept) != 2 {
		t.Fatalf("%d kept", len(kept))
	}
	for _, k := range kept {
		f, _ := os.Open(k)
		if _, err := backup.Verify(f, key); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		f.Close()
	}
}

// A backup kept inside the store it backs up holds none of the backups
// before it. The store was collected whole, so with backup.dir inside it,
// or a backup written into it by hand, each backup held every earlier one
// and the daily backup doubled in size each day until the disk was full.
func TestABackupHoldsNoEarlierBackup(t *testing.T) {
	root := demoStore(t)
	key, _ := backup.NewKey()
	t.Setenv(backupKeyEnv, backup.EncodeKey(key))
	tpl := filepath.Join(t.TempDir(), "tpl")
	files := func(file string) []string {
		t.Helper()
		f, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		m, err := backup.Verify(f, key)
		if err != nil {
			t.Fatal(err)
		}
		var paths []string
		for _, f := range m.Files {
			paths = append(paths, f.Path)
		}
		return paths
	}
	var first []string
	for i := range 3 {
		file := filepath.Join(root, "by-hand", "b"+strconv.Itoa(i)+".qzb")
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := cmdBackup(root, []string{"create", file, "--templates", tpl}); err != nil {
			t.Fatal(err)
		}
		got := files(file)
		if i == 0 {
			first = got
		} else if len(got) != len(first) {
			t.Errorf("backup %d holds %d files, the first %d: %v", i, len(got), len(first), got)
		}
	}

	// And the daily backup, into a backup.dir inside the store.
	dir := filepath.Join(root, "backups")
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("backup.dir", dir, "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	job := backupJob(root)
	now := time.Now()
	for d := range 3 {
		kept, _ := filepath.Glob(filepath.Join(dir, "quilzo-*.qzb"))
		for _, k := range kept {
			old := now.Add(-48 * time.Hour)
			os.Chtimes(k, old, old)
		}
		if n, err := job.Do(now.Add(time.Duration(d) * time.Second)); err != nil || n != 1 {
			t.Fatalf("day %d: %d %v", d, n, err)
		}
	}
	kept, _ := filepath.Glob(filepath.Join(dir, "quilzo-*.qzb"))
	for _, k := range kept {
		for _, p := range files(k) {
			if strings.HasSuffix(p, ".qzb") || strings.HasSuffix(p, ".part") {
				t.Errorf("%s holds the backup %s", filepath.Base(k), p)
			}
		}
	}
}

// damageAnObject rewrites one object of the store's history so that it no
// longer hashes to its name, as a bad sector or a hand edit leaves it, and
// says which.
func damageAnObject(t *testing.T, root string) string {
	t.Helper()
	shards, err := os.ReadDir(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sh := range shards {
		names, _ := os.ReadDir(filepath.Join(root, "objects", sh.Name()))
		for _, n := range names {
			p := filepath.Join(root, "objects", sh.Name(), n.Name())
			os.Chmod(p, 0o600)
			if err := os.WriteFile(p, []byte("blob\x00altered"), 0o600); err != nil {
				t.Fatal(err)
			}
			return sh.Name() + n.Name()
		}
	}
	t.Fatal("the store has no objects")
	return ""
}

// A backup is checked as a restore checks it: every object of the history
// it holds hashes to its name. `backup create` said "backed up and checked",
// the daily backup kept it and let a good one go, and `backup verify` said
// it "checks", exit 0, of a store whose history `quilzo verify` and the
// restore of that very backup refused.
func TestABackupOfADamagedHistoryDoesNotCheck(t *testing.T) {
	root := demoStore(t)
	key, _ := backup.NewKey()
	t.Setenv(backupKeyEnv, backup.EncodeKey(key))
	tpl := filepath.Join(t.TempDir(), "tpl")
	dir := filepath.Join(t.TempDir(), "backups")
	cfg, err := loadConfig(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("backup.dir", dir, "", "test"); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Set("backup.keep", "1", "a test", "test"); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(root, cfg); err != nil {
		t.Fatal(err)
	}
	job := backupJob(root)
	now := time.Now()
	if n, err := job.Do(now); err != nil || n != 1 {
		t.Fatalf("the backup before the damage: %d %v", n, err)
	}
	good, _ := filepath.Glob(filepath.Join(dir, "quilzo-*.qzb"))

	oid := damageAnObject(t, root)
	file := filepath.Join(t.TempDir(), "damaged.qzb")
	if err := cmdBackup(root, []string{"create", file, "--templates", tpl}); err == nil || !strings.Contains(err.Error(), oid) {
		t.Errorf("backup create of a damaged history: %v", err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("a backup that does not check was kept: %v", err)
	}
	for _, k := range good {
		old := now.Add(-48 * time.Hour)
		os.Chtimes(k, old, old)
	}
	if _, err := job.Do(now.Add(time.Second)); err == nil || !strings.Contains(err.Error(), oid) {
		t.Errorf("the daily backup of a damaged history: %v", err)
	}
	if kept, _ := filepath.Glob(filepath.Join(dir, "quilzo-*.qzb")); !slices.Equal(kept, good) {
		t.Errorf("the daily backup kept %v, want the one before the damage, %v", kept, good)
	}

	// A backup that holds the damage, as one made before this checked would.
	srcs, err := backupSources(root, tpl)
	if err != nil {
		t.Fatal(err)
	}
	var made bytes.Buffer
	if _, err := backup.Write(&made, key, srcs, "a test", now); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, made.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdBackup(root, []string{"verify", file}); err == nil || !strings.Contains(err.Error(), oid) {
		t.Errorf("backup verify of a damaged history: %v", err)
	}
}
