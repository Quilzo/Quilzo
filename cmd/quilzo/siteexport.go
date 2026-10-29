// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/collection"
	"github.com/quilzo/quilzo/internal/feature"
	"github.com/quilzo/quilzo/internal/fetch"
	"github.com/quilzo/quilzo/internal/webimport"
)

// Bringing a site from the file its last home exported (internal/webimport/
// export.go and files.go): a WordPress or Squarespace export, a Ghost
// export, or a folder of Markdown or web pages, as a folder or a zip. It is
// read into the same package a site brought by its address is, and its
// posts are staged beside the feature store, for the package to name by
// their hash and the install to write.

// maxZipEntries bounds a zip's directory, read before anything in it is.
const maxZipEntries = webimport.MaxFolderFiles

// exportSource is an export, read: what it is, its bytes or its files.
type exportSource struct {
	kind string
	body []byte
	fsys fs.FS
	name string
}

// openExport reads what is at path: a file of one of the kinds, a zip, or a
// folder, which is read through an os.Root so nothing outside it is.
func openExport(path string) (*exportSource, func(), error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	name := filepath.Base(filepath.Clean(path))
	if info.IsDir() {
		r, err := os.OpenRoot(path)
		if err != nil {
			return nil, nil, err
		}
		return &exportSource{kind: webimport.KindFiles, fsys: r.FS(), name: name}, func() { r.Close() }, nil
	}
	if info.Size() > webimport.MaxExportBytes {
		return nil, nil, fmt.Errorf("%s is larger than %d MB", name, webimport.MaxExportBytes>>20)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	src, err := exportOf(name, body)
	return src, func() {}, err
}

// exportOf reads an export's bytes: an export file, or a zip of a folder.
func exportOf(name string, body []byte) (*exportSource, error) {
	switch webimport.Detect(body) {
	case webimport.KindWordPress:
		return &exportSource{kind: webimport.KindWordPress, body: body, name: name}, nil
	case webimport.KindGhost:
		return &exportSource{kind: webimport.KindGhost, body: body, name: name}, nil
	case webimport.KindFiles:
		zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			return nil, fmt.Errorf("%s is not a zip that can be read: %w", name, err)
		}
		if len(zr.File) > maxZipEntries {
			return nil, fmt.Errorf("%s holds more than %d files", name, maxZipEntries)
		}
		// A zip of one folder is that folder.
		var fsys fs.FS = zr
		if entries, err := fs.ReadDir(zr, "."); err == nil && len(entries) == 1 && entries[0].IsDir() {
			if sub, err := fs.Sub(zr, entries[0].Name()); err == nil {
				fsys = sub
			}
		}
		return &exportSource{kind: webimport.KindFiles, fsys: fsys, name: name}, nil
	}
	return nil, fmt.Errorf("%s is not a WordPress, Squarespace or Ghost export, or a zip of a site's files", name)
}

// importExport reads an export and makes it a package, keeping the pictures
// it describes when pictures is set, and staging its posts. where is where
// the site was, which a Ghost export needs for its pictures.
func importExport(ctx context.Context, root string, src *exportSource, name, where string, pictures bool,
	caller *Caller) (*webimport.Brought, *webimport.Site, error) {
	var base *url.URL
	if where = strings.TrimSpace(where); where != "" {
		u, err := url.Parse(where)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, nil, fmt.Errorf("%q is not the address of a site: give one beginning https://", where)
		}
		base = u
	}
	var site *webimport.Site
	var err error
	switch src.kind {
	case webimport.KindWordPress:
		site, err = webimport.FromWordPress(src.body, src.name)
	case webimport.KindGhost:
		site, err = webimport.FromGhost(src.body, src.name, base)
	default:
		site, err = webimport.FromFiles(src.fsys, src.name)
	}
	if err != nil {
		return nil, nil, err
	}
	var picture webimport.Picture
	if pictures {
		client := fetch.For("import")
		picture = func(u *url.URL, alt string) (string, error) {
			res := &fetch.Result{URL: u.String(), FinalURL: u.String(), Status: 200}
			if u.Scheme == "file" {
				// A file of the folder, read from it and nowhere else.
				if src.fsys == nil {
					return "", errors.New("there is no folder to read it from")
				}
				body, err := fs.ReadFile(src.fsys, strings.TrimPrefix(u.Path, "/"))
				if err != nil {
					return "", err
				}
				res.URL, res.FinalURL, res.Body = filepath.Base(u.Path), src.name+u.Path, body
			} else {
				got, err := client.Get(ctx, u.String())
				if err != nil {
					return "", err
				}
				res = got
			}
			f, err := keepFetched(root, res, alt)
			if err != nil {
				return "", err
			}
			return "/media/" + f.ID, nil
		}
	}
	b, err := webimport.Package(site, name, caller.Name, picture, time.Now())
	if err != nil {
		return nil, site, err
	}
	if len(b.Posts) > 0 {
		set, err := stageRecords(root, "posts", b.Posts)
		if err != nil {
			return nil, site, err
		}
		b.Package.Records = append(b.Package.Records, set)
	}
	if err := b.Package.Validate(featureChecks(root)); err != nil {
		return nil, site, fmt.Errorf("what was read does not make a package that installs: %w", err)
	}
	if err := rememberBuilt(root, b.Package, ""); err != nil {
		return nil, site, err
	}
	record(root, caller.auditRecord("site.imported", "/", audit.Success, map[string]string{
		"from": src.kind, "pages": fmt.Sprint(len(b.Package.Pages)), "posts": fmt.Sprint(len(b.Posts)),
		"redirects": fmt.Sprint(len(b.Redirects))}))
	return b, site, nil
}

// -- Records a package brings ----------------------------------------------------

// stagedPath is where the rows a package names by hash wait to be installed.
func stagedPath(root, sum string) string {
	return filepath.Join(featuresDir(root), "staged", sum+".json")
}

// stagedRow is one staged record: the id it keeps and its fields.
type stagedRow struct {
	ID     string         `json:"id"`
	Fields map[string]any `json:"fields"`
}

// stageRecords writes rows for a package to bring, and says which.
func stageRecords(root, coll string, rows []webimport.Row) (feature.RecordSet, error) {
	out := make([]stagedRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, stagedRow{ID: r.ID, Fields: r.Fields})
	}
	body, err := json.Marshal(out)
	if err != nil {
		return feature.RecordSet{}, err
	}
	sum := sha256.Sum256(body)
	hexSum := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(filepath.Dir(stagedPath(root, hexSum)), 0o700); err != nil {
		return feature.RecordSet{}, err
	}
	if err := atomicfile.Write(stagedPath(root, hexSum), body, 0o600); err != nil {
		return feature.RecordSet{}, err
	}
	pruneStaged(root)
	return feature.RecordSet{Collection: coll, Count: len(out), SHA256: hexSum}, nil
}

// pruneStaged forgets rows staged a fortnight ago and never installed.
func pruneStaged(root string) {
	dir := filepath.Join(featuresDir(root), "staged")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > 14*24*time.Hour {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// readStaged reads staged rows, refusing any whose bytes are not the ones
// the package names.
func readStaged(root string, set feature.RecordSet) ([]stagedRow, error) {
	body, err := os.ReadFile(stagedPath(root, set.SHA256))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("the %d record(s) this package brings into %s were staged where the site was brought "+
			"in, not here: bring it in again on this installation", set.Count, set.Collection)
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != set.SHA256 {
		return nil, fmt.Errorf("the staged records for %s are not the ones the package names", set.Collection)
	}
	var rows []stagedRow
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	if len(rows) != set.Count {
		return nil, fmt.Errorf("%d staged records for %s, and the package says %d", len(rows), set.Collection, set.Count)
	}
	return rows, nil
}

// applyRecords writes the rows a package brings, once, when it is first
// installed, each checked against its collection's type first: one that
// does not satisfy it stops them all.
func applyRecords(root string, p *feature.Package, firstInstall bool, caller *Caller) error {
	if len(p.Records) == 0 || !firstInstall {
		return nil
	}
	check := recordGate(root)
	s, err := open(root)
	if err != nil {
		return err
	}
	tree, err := draftTree(s)
	if err != nil {
		return err
	}
	total := 0
	for _, set := range p.Records {
		rows, err := readStaged(root, set)
		if err != nil {
			return err
		}
		batch := make([]collection.Record, 0, len(rows))
		for i, r := range rows {
			if err := check(set.Collection, r.Fields); err != nil {
				return fmt.Errorf("record %d brought into %s does not satisfy its type: %w", i+1, set.Collection, err)
			}
			batch = append(batch, collection.Record{ID: r.ID, Fields: r.Fields})
		}
		if tree, _, err = collection.PutMany(s, tree, set.Collection, batch, time.Now()); err != nil {
			return err
		}
		total += len(batch)
	}
	if err := commitTree(root, s, tree, fmt.Sprintf("feature %s: bring %d record(s)", p.Name, total), caller.Name); err != nil {
		return err
	}
	for _, set := range p.Records {
		_ = os.Remove(stagedPath(root, set.SHA256))
	}
	pkg := p.Name
	return recordE(root, caller.auditRecord("feature.records", "/", audit.Success,
		map[string]string{"feature": pkg, "records": fmt.Sprint(total)}))
}
