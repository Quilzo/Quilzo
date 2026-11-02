// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package browser

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/quilzo/quilzo/internal/agent"
)

// memFiles is a workspace in memory.
type memFiles struct {
	mu    sync.Mutex
	files map[string][]byte
}

func (m *memFiles) SaveFile(name string, data []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.files == nil {
		m.files = map[string][]byte{}
	}
	used := name
	for i := 2; m.files[used] != nil; i++ {
		used = fmt.Sprintf("%s-%d", name, i)
	}
	m.files[used] = data
	return used, nil
}

func (m *memFiles) LoadFile(name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.files[name]; ok {
		return b, nil
	}
	return nil, errors.New(name + " is not in the workspace")
}

type office struct {
	base string
	mu   sync.Mutex
	got  []string
}

func newOffice(t *testing.T) *office {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	o := &office{base: "http://" + ln.Addr().String()}
	page := func(w http.ResponseWriter, title, body string) {
		fmt.Fprintf(w, `<!doctype html><html lang=en><title>%s</title><body>%s</body></html>`, title, body)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/report":
			page(w, "Monthly report", `<h1>October</h1><p>Loaves sold: 4,210.</p>`)
		case "/files":
			page(w, "Files", `<a href="/prices.csv">Price list</a> <button>Does nothing</button>`)
		case "/prices.csv":
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", `attachment; filename="../../prices.csv"`)
			io.WriteString(w, "loaf,3\nbun,1\n")
		case "/apply":
			page(w, "Apply", `<form method=post enctype=multipart/form-data action="/got">`+
				`<label>Your CV <input type=file name=cv></label><button>Send</button></form>`)
		case "/got":
			if err := r.ParseMultipartForm(1 << 20); err == nil {
				if f, h, err := r.FormFile("cv"); err == nil {
					b, _ := io.ReadAll(f)
					o.mu.Lock()
					o.got = append(o.got, h.Filename+": "+string(b))
					o.mu.Unlock()
				}
			}
			page(w, "Thanks", "<h1>Received</h1>")
		}
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return o
}

func officeDriver(t *testing.T) (*Driver, *office, *memFiles) {
	t.Helper()
	o := newOffice(t)
	d, _ := newDriver(t, agent.NewSession(shopper(), nil))
	files := &memFiles{}
	d.Files, d.Downloads = files, t.TempDir()
	return d, o, files
}

// A page is kept in the workspace as a PDF, a picture, its markup or its
// words, under a name of its own when none is given.
func TestAPageIsSavedIntoTheWorkspace(t *testing.T) {
	d, o, files := officeDriver(t)
	must(t, d, act("browser_open", "url", o.base+"/report"))
	for as, magic := range map[string]string{"pdf": "%PDF", "png": "\x89PNG", "html": "<html", "text": "October"} {
		out := must(t, d, act("browser_save", "as", as, "path", "report."+as))
		if !strings.Contains(out, "as report."+as) {
			t.Fatalf("%s: %s", as, out)
		}
		if b := files.files["report."+as]; !bytes.Contains(b[:min(len(b), 600)], []byte(magic)) {
			t.Errorf("%s does not start like one: %q", as, b[:min(len(b), 20)])
		}
	}
	out := must(t, d, act("browser_save"))
	if !strings.Contains(out, "saved/127.0.0.1-Monthly-report.pdf") {
		t.Errorf("%s", out)
	}
	if _, err := perform(t, d, act("browser_save", "as", "doc")); err == nil {
		t.Error("saved as something that is not a way to save")
	}
	none, _ := newDriver(t, agent.NewSession(shopper(), nil))
	must(t, none, act("browser_open", "url", o.base+"/report"))
	if _, err := perform(t, none, act("browser_save")); err == nil || !strings.Contains(err.Error(), "no workspace") {
		t.Errorf("%v", err)
	}
}

// A link that downloads is pressed and the file kept, under a name of its
// own and never a path the server chose; a press that downloads nothing
// says so.
func TestADownloadIsKeptInTheWorkspace(t *testing.T) {
	d, o, files := officeDriver(t)
	out := must(t, d, act("browser_open", "url", o.base+"/files"))
	got := must(t, d, act("browser_download", "ref", ref(t, out, "link", "Price list")))
	if !strings.Contains(got, "kept as downloads/prices.csv") || string(files.files["downloads/prices.csv"]) != "loaf,3\nbun,1\n" {
		t.Fatalf("%s %v", got, files.files)
	}
	out = must(t, d, act("browser_read"))
	if _, err := perform(t, d, act("browser_download", "ref", ref(t, out, "button", "Does nothing"))); err == nil ||
		!strings.Contains(err.Error(), "started no download") {
		t.Errorf("%v", err)
	}
}

// A workspace file is put into a page's file field only on a host the
// agent may send to, and only after a person was asked, naming the file;
// then the page sends it with its form.
func TestAFileIsPutIntoAPageOnlyWhereItMaySend(t *testing.T) {
	d, o, files := officeDriver(t)
	files.files = map[string][]byte{"cv.txt": []byte("Ana, baker since 2013")}
	out := must(t, d, act("browser_open", "url", o.base+"/apply"))
	field := ref(t, out, "button", "Your CV")
	up := act("browser_upload", "ref", field, "path", "cv.txt")
	why := d.Weighs(up)
	if !strings.Contains(why, "puts the workspace's cv.txt into the file field") || !strings.Contains(why, "may send it") {
		t.Fatalf("an upload was weighed as %q", why)
	}
	if c := agent.CommitOf(up, why, agent.WaitAsk, false); c != "sends" {
		t.Errorf("an upload commits to %q", c)
	}
	if out := must(t, d, up); !strings.Contains(out, "put cv.txt (21 bytes, text/plain") {
		t.Fatalf("%s", out)
	}
	out = must(t, d, act("browser_read"))
	must(t, d, act("browser_click", "ref", ref(t, out, "button", "Send")))
	o.mu.Lock()
	sent := strings.Join(o.got, "\n")
	o.mu.Unlock()
	if sent != "cv.txt: Ana, baker since 2013" {
		t.Fatalf("the page received %q", sent)
	}
	// On a host it may only read, nothing is put in.
	readBase := strings.Replace(o.base, "127.0.0.1", "localhost", 1)
	out = must(t, d, act("browser_open", "url", readBase+"/apply"))
	if _, err := perform(t, d, act("browser_upload", "ref", ref(t, out, "button", "Your CV"), "path", "cv.txt")); err == nil ||
		!strings.Contains(err.Error(), "not a host this agent may send to") {
		t.Errorf("%v", err)
	}
	// Nor into something that is not a file field.
	out = must(t, d, act("browser_open", "url", o.base+"/apply"))
	if _, err := perform(t, d, act("browser_upload", "ref", ref(t, out, "button", "Send"), "path", "cv.txt")); err == nil ||
		!strings.Contains(err.Error(), "not a field that takes a file") {
		t.Errorf("%v", err)
	}
}
