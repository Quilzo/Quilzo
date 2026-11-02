// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/agent"
	"github.com/quilzo/quilzo/internal/cdp"
)

// The browser and the workspace, working together: a page saved into the
// workspace as a PDF, a picture, its markup or its words; a file a link
// leads to downloaded there; and a file from there put into a page's file
// field.
//
// Saving and downloading write the workspace, so they are held to its
// quota and refused for a run that only reads (internal/shell). Putting a
// file into a page is the workspace's words given to a host, so it is
// done only on a host the agent may send to, and it always waits for a
// person, who is told which file, how large, and where it would go.

// Files is the run's workspace, as the browser uses it.
type Files interface {
	SaveFile(name string, data []byte) (string, error)
	LoadFile(name string) ([]byte, error)
}

// Bounds on what moves between the browser and the workspace.
const (
	// MaxDownload is the largest download kept; a larger one is stopped.
	MaxDownload = 32 << 20
	// MaxUpload is the largest file put into a page.
	MaxUpload = 10 << 20
	// DownloadWait is the longest a download is waited for.
	DownloadWait = 2 * time.Minute
	// MaxShot is the tallest whole-page picture, in pixels.
	MaxShot = 16384
)

var (
	reSafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	reRun      = regexp.MustCompile(`[._-]{2,}`)
)

// safeName is a name a page or an address suggested, made one the
// workspace takes: no folders, no dots at the start, nothing odd.
func safeName(s, fallback string) string {
	s = path.Base(strings.ReplaceAll(s, "\\", "/"))
	s = strings.Trim(reRun.ReplaceAllString(reSafeName.ReplaceAllString(s, "-"), "-"), "._-")
	if len(s) > 100 {
		ext := path.Ext(s)
		s = s[:100-len(ext)] + ext
	}
	if s == "" || s == "." || s == ".." {
		return fallback
	}
	return s
}

func (d *Driver) files() (Files, error) {
	if d.Files == nil {
		return nil, errors.New("this agent has no workspace to keep files in: it needs file_write (or file_read) " +
			"and a workspace")
	}
	return d.Files, nil
}

// save keeps the page in the workspace: as a PDF, a picture of all of it,
// its markup, or its words.
func (d *Driver) save(ctx context.Context, a agent.Action) (string, error) {
	files, err := d.files()
	if err != nil {
		return "", err
	}
	as := strings.ToLower(nonEmpty(str(a, "as"), "pdf"))
	var data []byte
	switch as {
	case "pdf":
		var r struct {
			Data string `json:"data"`
		}
		if err := d.page.Call(ctx, "Page.printToPDF", map[string]any{"printBackground": true, "preferCSSPageSize": true}, &r); err != nil {
			return "", err
		}
		if data, err = base64.StdEncoding.DecodeString(r.Data); err != nil {
			return "", err
		}
	case "png":
		var m struct {
			Content struct {
				W float64 `json:"width"`
				H float64 `json:"height"`
			} `json:"cssContentSize"`
		}
		if err := d.page.Call(ctx, "Page.getLayoutMetrics", nil, &m); err != nil {
			return "", err
		}
		h := min(m.Content.H, MaxShot)
		var r struct {
			Data string `json:"data"`
		}
		if err := d.page.Call(ctx, "Page.captureScreenshot", map[string]any{"format": "png", "captureBeyondViewport": true,
			"clip": map[string]any{"x": 0, "y": 0, "width": m.Content.W, "height": h, "scale": 1}}, &r); err != nil {
			return "", err
		}
		if data, err = base64.StdEncoding.DecodeString(r.Data); err != nil {
			return "", err
		}
	case "html":
		html, err := d.page.HTML(ctx)
		if err != nil {
			return "", err
		}
		data = []byte(html)
	case "text":
		var text string
		if err := d.page.Run(ctx, `function(){return document.body?document.body.innerText:""}`, nil, false, &text); err != nil {
			return "", err
		}
		data = []byte(text)
	default:
		return "", fmt.Errorf("%q is not a way to save a page; it is pdf, png, html or text", as)
	}
	title, at := d.where(ctx)
	name := str(a, "path")
	if name == "" {
		host := "page"
		if u, err := url.Parse(at); err == nil && u.Hostname() != "" {
			host = u.Hostname()
		}
		name = "saved/" + safeName(host+"-"+nonEmpty(title, "page"), "page") + "." + as
	}
	used, err := files.SaveFile(name, data)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("saved %q (%s) as %s, %d bytes", title, d.redact(at), used, len(data)), nil
}

// download presses an element that downloads a file, and keeps the file in
// the workspace: the press is weighed as any press is (Weighs), and the
// browser saves only while this waits for it.
func (d *Driver) download(ctx context.Context, a agent.Action) (string, error) {
	files, err := d.files()
	if err != nil {
		return "", err
	}
	if d.Downloads == "" {
		return "", errors.New("this run's browser has nowhere to download to")
	}
	e, err := d.element(ctx, str(a, "ref"))
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(d.Downloads, 0o700); err != nil {
		return "", err
	}
	evs, cancel := d.browser.Subscribe(func(ev cdp.Event) bool {
		return ev.Method == "Browser.downloadWillBegin" || ev.Method == "Browser.downloadProgress"
	})
	defer cancel()
	if err := d.browser.Call(ctx, "", "Browser.setDownloadBehavior", map[string]any{"behavior": "allowAndName",
		"downloadPath": d.Downloads, "eventsEnabled": true}, nil); err != nil {
		return "", err
	}
	// Downloads are allowed only while this waits for one.
	defer func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = d.browser.Call(c, "", "Browser.setDownloadBehavior", map[string]any{"behavior": "deny"}, nil)
	}()
	if err := d.page.Click(ctx, e.Backend); err != nil {
		return "", err
	}
	var guid, suggested string
	begun := time.NewTimer(8 * time.Second)
	defer begun.Stop()
	deadline := time.NewTimer(DownloadWait)
	defer deadline.Stop()
	for {
		select {
		case ev := <-evs:
			var p struct {
				GUID      string  `json:"guid"`
				URL       string  `json:"url"`
				Suggested string  `json:"suggestedFilename"`
				State     string  `json:"state"`
				Total     float64 `json:"totalBytes"`
				Received  float64 `json:"receivedBytes"`
			}
			if json.Unmarshal(ev.Params, &p) != nil {
				continue
			}
			if ev.Method == "Browser.downloadWillBegin" {
				if guid == "" {
					guid, suggested = p.GUID, p.Suggested
					begun.Stop()
				}
				continue
			}
			if p.GUID != guid {
				continue
			}
			if p.Total > MaxDownload || p.Received > MaxDownload {
				_ = d.browser.Call(ctx, "", "Browser.cancelDownload", map[string]any{"guid": guid}, nil)
				return "", fmt.Errorf("the download is larger than the %d MB kept, so it was stopped", MaxDownload>>20)
			}
			switch p.State {
			case "canceled":
				return "", errors.New("the download was cancelled")
			case "completed":
				return d.keepDownload(files, guid, suggested, e)
			}
		case <-begun.C:
			if guid == "" {
				d.read = false
				out, err := d.readPage(ctx, fmt.Sprintf("pressing %s %q started no download; the page is now ", e.Role, e.Name))
				if err != nil {
					return "", err
				}
				return "", errors.New(out)
			}
		case <-deadline.C:
			if guid != "" {
				_ = d.browser.Call(ctx, "", "Browser.cancelDownload", map[string]any{"guid": guid}, nil)
			}
			return "", fmt.Errorf("the download did not finish in %s", DownloadWait)
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

// keepDownload moves a finished download from the browser's folder into
// the workspace.
func (d *Driver) keepDownload(files Files, guid, suggested string, e Element) (string, error) {
	if strings.ContainsAny(guid, `/\`) || guid == "" || strings.HasPrefix(guid, ".") {
		return "", errors.New("the browser named its download strangely, so it was not kept")
	}
	p := filepath.Join(d.Downloads, guid)
	defer os.Remove(p)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > MaxDownload {
		return "", errors.New("the download is not a plain file within the bound, so it was not kept")
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	used, err := files.SaveFile("downloads/"+safeName(suggested, "download"), data)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("downloaded %s by pressing %s %q: %d bytes, kept as %s", safeName(suggested, "a file"),
		e.Role, e.Name, len(data), used), nil
}

// fileField is the backend id of a file field, by its reference.
func (d *Driver) fileField(ctx context.Context, ref string) (Element, error) {
	if !d.read {
		return Element{}, errors.New("read the page first (browser_read): a reference names an element of the outline read last")
	}
	e, ok := d.outline.Elements[ref]
	if !ok {
		return Element{}, fmt.Errorf("%q is not on the outline read last; read the page again", ref)
	}
	var isFile bool
	world, err := d.page.Isolated(ctx)
	if err != nil {
		return Element{}, err
	}
	obj, err := d.page.Resolve(ctx, e.Backend, world)
	if err != nil {
		return Element{}, fmt.Errorf("%s is no longer on the page; read it again", ref)
	}
	var r struct {
		Result struct {
			Value bool `json:"value"`
		} `json:"result"`
	}
	if err := d.page.Call(ctx, "Runtime.callFunctionOn", map[string]any{"objectId": obj, "returnByValue": true,
		"functionDeclaration": `function(){return this instanceof HTMLInputElement&&this.type==="file"&&this.ownerDocument===document}`},
		&r); err != nil {
		return Element{}, err
	}
	isFile = r.Result.Value
	if !isFile {
		return Element{}, fmt.Errorf("%s %q is not a field that takes a file", e.Role, e.Name)
	}
	return e, nil
}

// weighUpload is why putting a file into a page waits for a person: always,
// saying which file, how large, and where.
func (d *Driver) weighUpload(ctx context.Context, a agent.Action) string {
	e, err := d.fileField(ctx, str(a, "ref"))
	if err != nil {
		return ""
	}
	why := fmt.Sprintf("it puts the workspace's %s into the file field %q on %s, and the page may send it there",
		str(a, "path"), e.Name, d.host(ctx))
	d.frame(ctx, a.Op, why, e.Backend)
	return d.redact(why)
}

// upload puts a workspace file into a page's file field, as choosing it in
// the file picker does; the page sends it when its form is sent, which is
// weighed as any press is.
func (d *Driver) upload(ctx context.Context, a agent.Action) (string, error) {
	files, err := d.files()
	if err != nil {
		return "", err
	}
	host := d.host(ctx)
	if !d.decl().Writes(host) {
		return "", fmt.Errorf("%s is not a host this agent may send to, and a file put into its page is sent there", host)
	}
	e, err := d.fileField(ctx, str(a, "ref"))
	if err != nil {
		return "", err
	}
	name := str(a, "path")
	data, err := files.LoadFile(name)
	if err != nil {
		return "", err
	}
	if len(data) > MaxUpload {
		return "", fmt.Errorf("%s is %d bytes; at most %d are put into a page", name, len(data), MaxUpload)
	}
	kind := mime.TypeByExtension(path.Ext(name))
	if kind == "" {
		kind = "application/octet-stream"
	}
	world, err := d.page.Isolated(ctx)
	if err != nil {
		return "", err
	}
	obj, err := d.page.Resolve(ctx, e.Backend, world)
	if err != nil {
		return "", err
	}
	// Made into a file in this program's world and given to the field as
	// the picker would; the page's own script sees a file chosen.
	fn := `function(b64,name,type){const s=atob(b64);const u=new Uint8Array(s.length);for(let i=0;i<s.length;i++)u[i]=s.charCodeAt(i);` +
		`const dt=new DataTransfer();dt.items.add(new File([u],name,{type}));this.files=dt.files;` +
		`this.dispatchEvent(new Event("input",{bubbles:true}));this.dispatchEvent(new Event("change",{bubbles:true}));return this.files.length}`
	var r struct {
		Result struct {
			Value int `json:"value"`
		} `json:"result"`
	}
	if err := d.page.Call(ctx, "Runtime.callFunctionOn", map[string]any{"objectId": obj, "functionDeclaration": fn,
		"arguments":     []map[string]any{{"value": base64.StdEncoding.EncodeToString(data)}, {"value": path.Base(name)}, {"value": kind}},
		"returnByValue": true}, &r); err != nil {
		return "", err
	}
	if r.Result.Value != 1 {
		return "", fmt.Errorf("the field %q did not take the file", e.Name)
	}
	return fmt.Sprintf("put %s (%d bytes, %s) into the file field %q on %s; it is sent when the form is", name, len(data), kind, e.Name, host), nil
}
