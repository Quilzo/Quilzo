// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
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
