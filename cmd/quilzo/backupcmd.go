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
	"github.com/quilzo/quilzo/internal/vault"
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
//
// Not a backup kept among them, which is no part of the store. Each was
// collected with the rest, so with backup.dir inside the store, or a backup
// written into it by hand, every backup held all the earlier ones, and the
// daily backup doubled in size each day until the disk was full.
func backupSources(root, templates string) ([]backup.Source, error) {
	skip := func(rel string) bool {
		switch rel {
		case "tmp", "connect-pending":
			return true
		}
		// The history's objects are the store's own format, never a backup,
		// and are not opened twice to be told so.
		return !strings.HasPrefix(rel, "objects/") && isBackupFile(filepath.Join(root, filepath.FromSlash(rel)))
	}
	srcs, err := backup.Collect(root, "store", skip, "objects")
	if err != nil {
		return nil, err
	}
	if templates != "" {
		if fi, err := os.Stat(templates); err == nil && fi.IsDir() {
			more, err := backup.Collect(templates, "templates", func(rel string) bool {
				return isBackupFile(filepath.Join(templates, filepath.FromSlash(rel)))
			})
			if err != nil {
				return nil, err
			}
			srcs = append(srcs, more...)
		}
	}
	return srcs, nil
}

// isBackupFile reports whether the file at p is a backup, by the magic
// every backup begins with.
func isBackupFile(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, len(backup.Magic))
	_, err = io.ReadFull(f, head)
	return err == nil && string(head) == backup.Magic
}

// backupHistory is what checking the history a backup holds came to: the
// objects that hash to their names, the sealed ones no key here could open
// to check, and the first that does not check.
type backupHistory struct {
	checked, sealed int
	damaged         error
}

// verifyBackup reads a whole backup as backup.Verify does, and checks each
// object of the history it holds as `quilzo verify` checks a store's, with
// keys for the sealed ones where there are keys. A restore checked the
// history and the backup itself did not: a backup of a store whose objects
// no longer hashed to their names was "backed up and checked", and "checks"
// to `backup verify`, and only its restore said it was damaged.
func verifyBackup(r io.Reader, key []byte, keys *vault.Keyring) (backup.Manifest, backupHistory, error) {
	var h backupHistory
	m, err := backup.VerifyEach(r, key, func(f backup.File, body io.Reader) error {
		oid, ok := backupObject(f.Path)
		if !ok || h.damaged != nil {
			return nil
		}
		b, err := io.ReadAll(body)
		if err != nil {
			return err
		}
		if keys == nil && vault.IsSealed(b) {
			h.sealed++
			return nil
		}
		if h.damaged = store.CheckObject(oid, b, keys); h.damaged == nil {
			h.checked++
		}
		return nil
	})
	return m, h, err
}

// backupObject is the object of the history a backup's file is, where it is
// one: store/objects/SHARD/REST, walked as store.Verify walks them.
func backupObject(p string) (string, bool) {
	rest, ok := strings.CutPrefix(p, "store/objects/")
	if !ok {
		return "", false
	}
	shard, name, ok := strings.Cut(rest, "/")
	if !ok || name == "" || strings.Contains(name, "/") || strings.HasPrefix(name, ".") {
		return "", false
	}
	return shard + name, true
}

// makeBackup writes a backup to file, through a file beside it that is put
// in place only once it checks, its history included.
func makeBackup(root, templates, file string, now time.Time) (backup.Manifest, backupHistory, string, error) {
	key, err := backupKey()
	if err != nil {
		return backup.Manifest{}, backupHistory{}, "", err
	}
	srcs, err := backupSources(root, templates)
	if err != nil {
		return backup.Manifest{}, backupHistory{}, "", err
	}
	tmp := file + ".part"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return backup.Manifest{}, backupHistory{}, "", err
	}
	defer os.Remove(tmp)
	h := sha256.New()
	m, err := backup.Write(io.MultiWriter(out, h), key, srcs, "the store at "+absPath(root), now)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return m, backupHistory{}, "", err
	}
	// Checked before it is called a backup: read back whole, every part
	// decrypted, every file compared with the manifest, and every object of
	// the history hashed to its name, with the store's keys where it has
	// them. Without them a sealed object is checked only as a file, and
	// said to be.
	in, err := os.Open(tmp)
	if err != nil {
		return m, backupHistory{}, "", err
	}
	kr, _ := loadKeyring(root)
	_, hist, verr := verifyBackup(in, key, kr)
	in.Close()
	if verr != nil {
		return m, hist, "", fmt.Errorf("the backup did not check: %w", verr)
	}
	// Not kept, as no backup that does not check is, so the daily backup
	// does not let go of one made before the damage for one made after it.
	if hist.damaged != nil {
		return m, hist, "", fmt.Errorf("the store's history does not check (%w), so no backup of it "+
			"is kept: quilzo verify shows the damage, and the backups made before it are as they were", hist.damaged)
	}
	if err := os.Rename(tmp, file); err != nil {
		return m, hist, "", err
	}
	return m, hist, hex.EncodeToString(h.Sum(nil)), nil
}

// saySealedUnchecked says how many objects of a backup's history are sealed
// and were checked only as files, when there are some, so "checked" does
// not claim more than was.
func saySealedUnchecked(h backupHistory) {
	if h.sealed > 0 {
		w.Human("  %s%d sealed object(s) of the history were checked as files only: no key here opens them%s\n",
			dim, h.sealed, reset)
	}
}

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func cmdBackup(root string, args []string) error {
	if len(args) == 0 {
		return errMisused{errors.New("usage: quilzo backup key | create FILE [--templates DIR] | verify FILE | restore FILE --into DIR")}
	}
	caller := resolveCaller(root, flagToken)
	switch args[0] {
	case "key":
		if err := noArguments(args[1:]); err != nil {
			return err
		}
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
		// The key alone on stdout and its paragraph on stderr, so `backup
		// key > bk.key` writes a file QUILZO_BACKUP_KEY_FILE can name. The
		// file held the paragraph too, and the backup was refused: "a
		// backup key is 32 bytes, base64".
		fmt.Println(backup.EncodeKey(k))
		w.Notes().Human("\nThis is the backup key. It is shown once and kept nowhere here: keep it where the backups are not,\n"+
			"and give it to Quilzo as %s or in the file %s names. Without it no backup can be read.\n",
			backupKeyEnv, backupKeyFileEnv)
		return nil
	case "create":
		fs := flag.NewFlagSet("backup create", flag.ContinueOnError)
		templates := fs.String("templates", "templates", "the layouts beside the store")
		rest, flags := leadingArgs(args[1:], 1)
		if err := parseFlags(fs, flags, &rest, 1); err != nil {
			return err
		}
		if len(rest) != 1 {
			return errMisused{errors.New("usage: quilzo backup create FILE [--templates DIR]")}
		}
		// A backup of a --root that is no store, an unmounted volume's, was
		// "backed up and checked: 0 files".
		if err := needStore(root); err != nil {
			return err
		}
		if err := authorise(root, caller, auth.ActGrant, "/"); err != nil {
			return err
		}
		m, hist, sum, err := makeBackup(root, *templates, rest[0], time.Now())
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
		saySealedUnchecked(hist)
		return nil
	case "verify":
		if len(args) != 2 {
			return errMisused{errors.New("usage: quilzo backup verify FILE")}
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
		// Without keys: the backup may be another store's, and is read as
		// on the day the store is gone.
		m, hist, err := verifyBackup(f, key, nil)
		if err != nil {
			return err
		}
		if hist.damaged != nil {
			return fmt.Errorf("%s is whole, but the history it holds does not check: %w", args[1], hist.damaged)
		}
		if w.JSON(m) {
			return nil
		}
		w.Human("%s%s checks%s: %d files, %d bytes, made %s\n", green, args[1], reset, len(m.Files), m.Bytes,
			m.Created.Local().Format("2 Jan 2006 15:04"))
		saySealedUnchecked(hist)
		return nil
	case "restore":
		fs := flag.NewFlagSet("backup restore", flag.ContinueOnError)
		into := fs.String("into", "", "an empty directory to restore into")
		rest, flags := leadingArgs(args[1:], 1)
		if err := parseFlags(fs, flags, &rest, 1); err != nil {
			return err
		}
		if len(rest) != 1 || *into == "" {
			return errMisused{errors.New("usage: quilzo backup restore FILE --into DIR")}
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
	return errMisused{fmt.Errorf("unknown backup command %q; try key, create, verify or restore", args[0])}
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
			m, _, sum, err := makeBackup(root, "templates", file, now)
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
