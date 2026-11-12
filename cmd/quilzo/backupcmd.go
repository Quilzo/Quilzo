// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/backup"
	"github.com/quilzo/quilzo/internal/store"
	"github.com/quilzo/quilzo/internal/upkeep"
)

// Backups of the whole store (internal/backup).
//
//	quilzo backup key                       a new backup key, printed once
//	quilzo backup create FILE [--templates DIR]
//	quilzo backup verify FILE
//	quilzo backup restore FILE --into DIR
//
// The key comes from QUILZO_BACKUP_KEY, or the file QUILZO_BACKUP_KEY_FILE
// names; never from the command line. With backup.dir set, the admin
// server makes one a day, checks it, and keeps backup.keep of them.

const (
	backupKeyEnv     = "QUILZO_BACKUP_KEY"
	backupKeyFileEnv = "QUILZO_BACKUP_KEY_FILE"
)

// backupKey is the key backups are made and read with.
func backupKey() ([]byte, error) {
	v := os.Getenv(backupKeyEnv)
	if v == "" {
		if f := os.Getenv(backupKeyFileEnv); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", backupKeyFileEnv, err)
			}
			v = string(b)
		}
	}
	if strings.TrimSpace(v) == "" {
		return nil, fmt.Errorf("no backup key: set %s, or %s to a file holding it (quilzo backup key makes one)",
			backupKeyEnv, backupKeyFileEnv)
	}
	return backup.DecodeKey(v)
}

// backupSources are the files a backup of this store holds: the store, its
// history's objects last (after the pointers to them, so every pointer
// taken points at an object taken too), and the layouts beside it.
func backupSources(root, templates string) ([]backup.Source, error) {
	skip := func(rel string) bool {
		switch rel {
		case "tmp", "connect-pending":
			return true
		}
		return false
	}
	srcs, err := backup.Collect(root, "store", skip, "objects")
	if err != nil {
		return nil, err
	}
	if templates != "" {
		if fi, err := os.Stat(templates); err == nil && fi.IsDir() {
			more, err := backup.Collect(templates, "templates", nil)
			if err != nil {
				return nil, err
			}
			srcs = append(srcs, more...)
		}
	}
	return srcs, nil
}

// makeBackup writes a backup to file, through a file beside it that is put
// in place only once it checks.
func makeBackup(root, templates, file string, now time.Time) (backup.Manifest, string, error) {
	key, err := backupKey()
	if err != nil {
		return backup.Manifest{}, "", err
	}
	srcs, err := backupSources(root, templates)
	if err != nil {
		return backup.Manifest{}, "", err
	}
	tmp := file + ".part"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return backup.Manifest{}, "", err
	}
	defer os.Remove(tmp)
	h := sha256.New()
	m, err := backup.Write(io.MultiWriter(out, h), key, srcs, "the store at "+absPath(root), now)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return m, "", err
	}
	// Checked before it is called a backup: read back whole, every part
	// decrypted and every file compared with the manifest.
	in, err := os.Open(tmp)
	if err != nil {
		return m, "", err
	}
	_, verr := backup.Verify(in, key)
	in.Close()
	if verr != nil {
		return m, "", fmt.Errorf("the backup did not check: %w", verr)
	}
	if err := os.Rename(tmp, file); err != nil {
		return m, "", err
	}
	return m, hex.EncodeToString(h.Sum(nil)), nil
}

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func cmdBackup(root string, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: quilzo backup key | create FILE [--templates DIR] | verify FILE | restore FILE --into DIR")
	}
	caller := resolveCaller(root, flagToken)
	switch args[0] {
	case "key":
		k, err := backup.NewKey()
		if err != nil {
			return err
		}
		// The key as one document under --json. This printed its paragraph
		// whatever was asked for, so a script making a key had to cut the
		// one thing it needed out of prose.
		if w.JSON(map[string]string{"key": backup.EncodeKey(k)}) {
			return nil
		}
		fmt.Printf("%s\n\nThis is the backup key. It is shown once and kept nowhere here: keep it where the backups are not,\n"+
			"and give it to Quilzo as %s or in the file %s names. Without it no backup can be read.\n",
			backup.EncodeKey(k), backupKeyEnv, backupKeyFileEnv)
		return nil
	case "create":
		fs := flag.NewFlagSet("backup create", flag.ContinueOnError)
		templates := fs.String("templates", "templates", "the layouts beside the store")
		rest, flags := leadingArgs(args[1:], 1)
		if err := parseFlags(fs, flags, &rest, 1); err != nil {
			return err
		}
		if len(rest) != 1 {
			return errors.New("usage: quilzo backup create FILE [--templates DIR]")
		}
		// A backup of a --root that is no store, an unmounted volume's, was
		// "backed up and checked: 0 files".
		if err := needStore(root); err != nil {
			return err
		}
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return err
		}
		m, sum, err := makeBackup(root, *templates, rest[0], time.Now())
		if err != nil {
			record(root, caller.auditRecord("backup.failed", "/", audit.Failure, map[string]string{"error": clip(err.Error(), 200)}))
			return err
		}
		record(root, caller.auditRecord("backup.created", "/", audit.Success, map[string]string{
			"files": strconv.Itoa(len(m.Files)), "bytes": strconv.FormatInt(m.Bytes, 10), "sha256": sum}))
		if w.JSON(map[string]any{"file": rest[0], "sha256": sum, "files": len(m.Files), "bytes": m.Bytes}) {
			return nil
		}
		w.Human("%sbacked up and checked%s: %d files, %d bytes, in %s\n  %ssha256 %s%s\n", green, reset,
			len(m.Files), m.Bytes, rest[0], dim, sum, reset)
		return nil
	case "verify":
		if len(args) != 2 {
			return errors.New("usage: quilzo backup verify FILE")
		}
		if err := authorise(root, caller, auth.ActView, "/"); err != nil {
			return err
		}
		key, err := backupKey()
		if err != nil {
			return err
		}
		f, err := os.Open(args[1])
		if err != nil {
			return err
		}
		defer f.Close()
		m, err := backup.Verify(f, key)
		if err != nil {
			return err
		}
		if w.JSON(m) {
			return nil
		}
		w.Human("%s%s checks%s: %d files, %d bytes, made %s\n", green, args[1], reset, len(m.Files), m.Bytes,
			m.Created.Local().Format("2 Jan 2006 15:04"))
		return nil
	case "restore":
		fs := flag.NewFlagSet("backup restore", flag.ContinueOnError)
		into := fs.String("into", "", "an empty directory to restore into")
		rest, flags := leadingArgs(args[1:], 1)
		if err := parseFlags(fs, flags, &rest, 1); err != nil {
			return err
		}
		if len(rest) != 1 || *into == "" {
			return errors.New("usage: quilzo backup restore FILE --into DIR")
		}
		key, err := backupKey()
		if err != nil {
			return err
		}
		f, err := os.Open(rest[0])
		if err != nil {
			return err
		}
		defer f.Close()
		m, err := backup.Restore(f, key, *into)
		if err != nil {
			return err
		}
		// And the history checked as a store checks it: every object
		// hashes to its name (and opens, where it is sealed).
		restored := filepath.Join(*into, "store")
		checked := 0
		if s, serr := store.Open(restored); serr == nil {
			if n, verr := s.Verify(); verr != nil {
				return fmt.Errorf("restored, and its history does not check: %w", verr)
			} else {
				checked = n
			}
		}
		w.Human("%srestored and checked%s: %d files, %d objects of history\n", green, reset, len(m.Files), checked)
		w.Human("  the store is %s, the layouts %s: stop Quilzo, move them into place, start it\n",
			restored, filepath.Join(*into, "templates"))
		return nil
	}
	return fmt.Errorf("unknown backup command %q; try key, create, verify or restore", args[0])
}

// backupJob makes a backup a day into backup.dir, checks it, and keeps the
// newest backup.keep, when backup.dir is set and a backup key is given.
func backupJob(root string) upkeep.Job {
	return upkeep.Job{
		Name: "backup",
		Do: func(now time.Time) (int, error) {
			cfg := mustConfig(root)
			dir := strings.TrimSpace(cfg.Raw("backup.dir"))
			if dir == "" {
				return 0, nil
			}
			if _, err := backupKey(); err != nil {
				return 0, err
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return 0, err
			}
			kept, _ := filepath.Glob(filepath.Join(dir, "quilzo-*.qzb"))
			sort.Strings(kept)
			if n := len(kept); n > 0 {
				if fi, err := os.Stat(kept[n-1]); err == nil && now.Sub(fi.ModTime()) < 23*time.Hour {
					return 0, nil
				}
			}
			file := filepath.Join(dir, "quilzo-"+now.UTC().Format("20060102-150405")+".qzb")
			m, sum, err := makeBackup(root, "templates", file, now)
			if err != nil {
				record(root, audit.Record{Action: "backup.failed", Resource: "/", Outcome: audit.Failure,
					Principal: "quilzo", Kind: audit.KindService, Verified: true,
					Detail: map[string]string{"error": clip(err.Error(), 200)}})
				return 0, err
			}
			record(root, audit.Record{Action: "backup.created", Resource: "/", Outcome: audit.Success,
				Principal: "quilzo", Kind: audit.KindService, Verified: true,
				Detail: map[string]string{"files": strconv.Itoa(len(m.Files)), "bytes": strconv.FormatInt(m.Bytes, 10), "sha256": sum}})
			kept = append(kept, file)
			keep := cfg.Int("backup.keep")
			if keep < 1 {
				keep = 7
			}
			for len(kept) > keep {
				_ = os.Remove(kept[0])
				kept = kept[1:]
			}
			return 1, nil
		},
	}
}
