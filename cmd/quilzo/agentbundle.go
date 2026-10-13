// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
)

// A run's replay bundle: one self-contained HTML file of everything a
// person or an auditor should see of a run — its steps, the pictures kept
// with the ones that asked, and the receipt that proves each record in the
// log — opened by anybody, needing nothing, carrying its own proof.
//
// The bundle is evidence, not verification: it embeds the receipt with its
// inclusion proofs and signed head, and says plainly that checking it is
// `quilzo agent verify-receipt` against the keys you were given. A file
// that claimed to verify itself would be claiming the trust it was given.
// What it does guarantee, by construction, is that the pictures and the
// steps and the proof travel together: nothing in it can be swapped out
// without the receipt's digests noticing.

// maxBundleFrames is how many pictures a bundle carries: the ones that
// asked, first, then the newest of the rest. A run of hundreds of steps
// makes a bundle of hundreds of megabytes otherwise.
const maxBundleFrames = 24

// receiptBundle writes the bundle of one run.
func receiptBundle(root, run, outPath string, now time.Time) error {
	rec, err := loadAgentRun(root, run)
	if err != nil {
		return err
	}
	// The receipt is the run's proof; a run whose records are not in the
	// log — moved in by hand, or pruned — still gets its replay, saying so.
	rf, rerr := buildReceipt(root, run, now)
	frames, err := loadRunFrames(root, run)
	if err != nil {
		frames = nil
	}
	var picked []runFrame
	for _, f := range frames {
		if f.Asking != "" {
			picked = append(picked, f)
		}
	}
	for i := len(frames) - 1; i >= 0 && len(picked) < maxBundleFrames; i-- {
		if frames[i].Asking == "" {
			picked = append(picked, frames[i])
		}
	}

	var b strings.Builder
	esc := html.EscapeString
	fmt.Fprintf(&b, "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
	// The file carries words pages wrote; nothing in it runs, whatever
	// they say.
	fmt.Fprintf(&b, "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; img-src data:; style-src 'unsafe-inline'\">\n")
	fmt.Fprintf(&b, "<title>Run %s — %s</title>\n", esc(run), esc(rec.Agent))
	fmt.Fprintf(&b, "<style>\nbody{font:15px/1.55 system-ui,sans-serif;max-width:72ch;margin:2rem auto;padding:0 1rem;color:#1a1a1a}\n")
	fmt.Fprintf(&b, "h1{font-size:1.3rem}table{border-collapse:collapse;width:100%%;font-size:13px}\n")
	fmt.Fprintf(&b, "td,th{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}\n")
	fmt.Fprintf(&b, "code,pre{font:12px/1.5 ui-monospace,monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere}\n")
	fmt.Fprintf(&b, "img{max-width:320px;border:1px solid #ccc}.ask{outline:3px solid #b00}\n")
	fmt.Fprintf(&b, ".denied{color:#b00}.ok{color:#060}.hint{color:#666}\n</style>\n</head>\n<body>\n")
	fmt.Fprintf(&b, "<h1>A run of %s</h1>\n<p>%s", esc(rec.Agent), esc(nonEmpty(rec.Goal, "(no goal was given)")))
	if rec.Model != "" {
		fmt.Fprintf(&b, " — each action chosen by %s", esc(rec.Model))
	}
	fmt.Fprintf(&b, "<br><span class=\"hint\">run %s, started by %s, %s; bundle made %s</span></p>\n",
		esc(run), esc(rec.By), esc(rec.Started.Format("2 Jan 2006, 15:04")), esc(now.UTC().Format("2 Jan 2006, 15:04 UTC")))
	if rec.Trace.Stopped != "" {
		fmt.Fprintf(&b, "<p><strong>Stopped before finishing:</strong> %s</p>\n", esc(rec.Trace.Stopped))
	}

	fmt.Fprintf(&b, "<h2>Step by step</h2>\n<table>\n<tr><th>#</th><th>It tried</th><th>Outcome</th><th>What came back</th></tr>\n")
	for _, st := range rec.Trace.Steps {
		what := st.Action.Op
		if st.Action.Tool != "" {
			what = "tool:" + st.Action.Tool
		} else if st.Action.Delegate != "" {
			what = "hand to " + st.Action.Delegate
		} else if what == "" {
			what = "finished"
		}
		outcome, tone := "done", "ok"
		switch {
		case !st.Allowed:
			outcome, tone = "refused: "+st.Why, "denied"
		case st.Err != "":
			outcome, tone = "failed", "denied"
		}
		fmt.Fprintf(&b, "<tr><td>%d</td><td><code>%s</code></td><td class=\"%s\">%s</td><td>", st.N, esc(what), tone, esc(outcome))
		if st.Err != "" {
			fmt.Fprintf(&b, "%s", esc(st.Err))
		} else if st.Result != "" {
			fmt.Fprintf(&b, "<pre>%s</pre>", esc(clip(st.Result, 2000)))
		} else if !st.Allowed {
			fmt.Fprintf(&b, "<span class=\"hint\">nothing was done; the model was told</span>")
		} else {
			fmt.Fprintf(&b, "<span class=\"hint\">—</span>")
		}
		fmt.Fprintf(&b, "</td></tr>\n")
	}
	fmt.Fprintf(&b, "</table>\n")

	if len(picked) > 0 {
		fmt.Fprintf(&b, "<h2>The pictures kept with it</h2>\n<p class=\"hint\">The ones a person was asked about first, outlined in red as they were shown; then the newest of the rest.</p>\n")
		for _, f := range picked {
			pic, perr := runFramePicture(root, run, f.N)
			if perr != nil || len(pic) < 4 {
				continue
			}
			cls := ""
			if f.Asking != "" {
				cls = " class=\"ask\""
			}
			what := nonEmpty(f.Asking, "after "+f.Op)
			fmt.Fprintf(&b, "<figure style=\"margin:1rem 0\"><img%s src=\"data:image/jpeg;base64,%s\" alt=\"The page, %s\">"+
				"<figcaption class=\"hint\">%s — %s</figcaption></figure>\n",
				cls, base64.StdEncoding.EncodeToString(pic), esc(what), esc(what), esc(f.At))
		}
	}

	if rerr != nil {
		fmt.Fprintf(&b, "<h2>The proof</h2>\n<p class=\"hint\">No receipt could be built for this run (%s), so this bundle carries no proof; the steps and pictures are what the store held.</p>\n", esc(rerr.Error()))
	}
	proof, err := json.MarshalIndent(rf, "", "  ")
	if rerr == nil && err == nil {
		fmt.Fprintf(&b, "<h2>The proof</h2>\n<p class=\"hint\">The receipt this bundle carries, with each record's inclusion proof "+
			"against a head of %d signed by %s. Checking it is <code>quilzo agent verify-receipt</code> "+
			"against the public keys you were given; a file cannot verify itself, and this one does not claim to.</p>\n",
			rf.Head.Size, esc(rf.Head.KeyID))
		fmt.Fprintf(&b, "<script type=\"application/json\" id=\"receipt\">\n%s\n</script>\n", proof)
	}
	fmt.Fprintf(&b, "</body>\n</html>\n")

	// Pictures of pages a person may have been signed in to: readable by
	// whoever made the bundle, until they choose to hand it on.
	return atomicfile.Write(outPath, []byte(b.String()), 0o600)
}
