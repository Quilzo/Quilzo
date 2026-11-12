// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/assistant"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/auth"
	"github.com/quilzo/quilzo/internal/gaps"
	"github.com/quilzo/quilzo/internal/out"
)

// What visitors asked a chatbot that it could not answer (internal/gaps):
// kept by the public site when chatbot.gaps is on, grouped and closed here.

func gapsDir(root string) string { return filepath.Join(root, "gaps") }

func gapLedger(root string) gaps.Ledger { return gaps.Ledger{Dir: gapsDir(root)} }

// gapsKept is chatbot.gaps_days.
func gapsKept(root string) time.Duration {
	days := mustConfig(root).Int("chatbot.gaps_days")
	if days <= 0 {
		days = 30
	}
	return time.Duration(days) * 24 * time.Hour
}

// gapKeeper is what the public site calls with a question a chatbot could
// not answer. The setting is read each time, so turning it off stops it at
// once; the question is masked before anything is written.
func gapKeeper(root string) func(name, question string) {
	keep := gapKeep(root)
	return func(name, question string) { keep(name, question, "") }
}

// gapKeep keeps a question, masked, when chatbot.gaps is on: why is "" for
// one the chatbot could not answer, gaps.WhyUnhelpful for one whose answer
// the visitor said did not help.
func gapKeep(root string) func(name, question, why string) {
	return func(name, question, why string) {
		cfg := mustConfig(root)
		if !cfg.Bool("chatbot.gaps") {
			return
		}
		var own []string
		if u, err := url.Parse(cfg.Raw("site.base_url")); err == nil && u.Hostname() != "" {
			own = append(own, strings.TrimPrefix(u.Hostname(), "www."))
		}
		q := gaps.Clean(question, own)
		if why == gaps.WhyUnhelpful {
			_ = gapLedger(root).Unhelpful(name, q, time.Now())
			return
		}
		_ = gapLedger(root).Add(name, q, time.Now())
	}
}

// ratingKeeper counts whether answers helped, and keeps the question of
// one that did not where gapKeeper keeps unanswered ones, when the owner
// keeps those.
func ratingKeeper(root string) func(name, question string, helpful bool) {
	keep := gapKeep(root)
	return func(name, question string, helpful bool) {
		_ = gapLedger(root).Rate(name, helpful, time.Now())
		if !helpful {
			keep(name, question, gaps.WhyUnhelpful)
		}
	}
}

// gapRatings are how many answers a chatbot's visitors said helped, and
// did not, in the days gaps are kept.
func gapRatings(root, name string, now time.Time) (helped, didNot int) {
	h, d, _ := gapLedger(root).Ratings(name, now.Add(-gapsKept(root)))
	return h, d
}

// gapGroups are a chatbot's groups now, after old days are let go.
func gapGroups(root, name string, now time.Time) ([]gaps.Group, error) {
	l := gapLedger(root)
	keep := gapsKept(root)
	_, _ = l.Prune(keep, now)
	entries, err := l.Read(name, now.Add(-keep))
	if err != nil {
		return nil, err
	}
	closed, err := l.Closures(name)
	if err != nil {
		return nil, err
	}
	return gaps.Groups(entries, closed), nil
}

// MaxGapChecks is how many questions one check asks again: each may be a
// model call, and a check that runs after every publish must not be one
// that spends a day's budget.
const MaxGapChecks = 25

// gapCheck is what one check found.
type gapCheck struct {
	Asked, Closed int
	Pages         []string
}

// checkGaps asks a chatbot each open group's questions again, and closes a
// group it now answers every one of, naming the page it answered from.
func checkGaps(ctx context.Context, root, name, by string, now time.Time) (gapCheck, error) {
	var res gapCheck
	a, err := loadAssistant(root, name)
	if err != nil {
		return res, err
	}
	groups, err := gapGroups(root, name, now)
	if err != nil {
		return res, err
	}
	var open []gaps.Group
	for _, g := range groups {
		// One a visitor said was answered badly is closed by a person.
		if g.Open() && g.Answerable() {
			open = append(open, g)
		}
	}
	if len(open) == 0 {
		return res, nil
	}
	idx, err := assistantIndex(root, a)
	if err != nil {
		return res, err
	}
	m, _ := assistantModelAt(root, a)
	for _, g := range open {
		if res.Asked >= MaxGapChecks {
			break
		}
		answered, page := true, ""
		for _, q := range g.Questions[:min(len(g.Questions), 3)] {
			if res.Asked >= MaxGapChecks {
				answered = false
				break
			}
			res.Asked++
			qctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			ans, err := assistant.RespondTo(qctx, a, idx, m, q, "")
			cancel()
			if err != nil || ans.Refused {
				answered = false
				break
			}
			if page == "" {
				page = citedPage(ans)
			}
		}
		if !answered {
			continue
		}
		if err := gapLedger(root).Close(name, g.Key, gaps.Closure{At: now.UTC(), By: by, How: "answered", Page: page}); err != nil {
			return res, err
		}
		res.Closed++
		if page != "" {
			res.Pages = append(res.Pages, page)
		}
	}
	record(root, audit.Record{Action: "assistant.gaps.checked", Resource: "/ask/" + name, Outcome: audit.Success,
		Principal: "quilzo", Kind: audit.KindService, Verified: true,
		Detail: map[string]string{"assistant": name, "asked": strconv.Itoa(res.Asked), "closed": strconv.Itoa(res.Closed)}})
	return res, nil
}

// checkAllGaps checks every chatbot with open groups, after the site was
// published: the page that answers them may be the one that just went
// live.
func checkAllGaps(ctx context.Context, root string) string {
	if !mustConfig(root).Bool("chatbot.gaps") {
		return ""
	}
	set, err := assistant.Load(assistantsPath(root))
	if err != nil {
		return ""
	}
	var said []string
	for _, a := range set.Assistants {
		r, err := checkGaps(ctx, root, a.Name, "quilzo", time.Now())
		if err != nil || r.Closed == 0 {
			continue
		}
		said = append(said, fmt.Sprintf("%s answers %s it could not before", a.Name, plural2(r.Closed, "a question", "questions")))
	}
	return strings.Join(said, "; ")
}

// assistantGaps is quilzo assistant gaps NAME [--check] [--close KEY].
func assistantGaps(root string, args []string) error {
	pos, rest := leadingArgs(args, 1)
	if len(pos) != 1 {
		return fmt.Errorf("usage: quilzo assistant gaps NAME [--check] [--close KEY]")
	}
	name := pos[0]
	fs := flag.NewFlagSet("assistant gaps", flag.ContinueOnError)
	check := fs.Bool("check", false, "ask the chatbot each open group's questions again, and close those it answers")
	closeKey := fs.String("close", "", "close a group by its key: it needs no page")
	if err := parseFlags(fs, rest, &pos, 1); err != nil {
		return err
	}
	caller := resolveCaller(root, flagToken)
	// Visitors' words, masked: whoever may read the Inbox may read these.
	if err := authorise(root, caller, auth.ActEditDraft, "/"); err != nil {
		return err
	}
	if _, err := loadAssistant(root, name); err != nil {
		return err
	}
	now := time.Now()
	if *closeKey != "" {
		if err := gapLedger(root).Close(name, *closeKey, gaps.Closure{At: now.UTC(), By: caller.Name, How: "dismissed"}); err != nil {
			return err
		}
		record(root, caller.auditRecord("assistant.gaps.closed", "/ask/"+name, audit.Success,
			map[string]string{"assistant": name, "group": *closeKey}))
		w.Human("  %sclosed; it opens again if somebody asks it again%s\n", green, reset)
		return nil
	}
	if *check {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		r, err := checkGaps(ctx, root, name, caller.Name, now)
		if err != nil {
			return err
		}
		w.Human("  asked %d again; %s now answered%s\n", r.Asked, plural2(r.Closed, "one group is", "groups are"),
			map[bool]string{true: " (" + strings.Join(r.Pages, ", ") + ")", false: ""}[len(r.Pages) > 0])
	}
	groups, err := gapGroups(root, name, now)
	if err != nil {
		return err
	}
	record(root, caller.auditRecord("assistant.gaps.read", "/ask/"+name, audit.Success,
		map[string]string{"assistant": name, "groups": strconv.Itoa(len(groups))}))
	helped, didNot := gapRatings(root, name, now)
	if w.Mode == out.JSON {
		w.JSON(groups)
		return nil
	}
	if helped+didNot > 0 {
		w.Human("  visitors said %d answers helped and %d did not, in the last %d days\n\n", helped, didNot,
			int(gapsKept(root).Hours()/24))
	}
	if !mustConfig(root).Bool("chatbot.gaps") && len(groups) == 0 {
		w.Human("  %snothing is kept: unanswered questions are kept only when chatbot.gaps is on%s\n", dim, reset)
		return nil
	}
	if len(groups) == 0 {
		w.Human("  %s%s has answered everything it was asked in the last %d days%s\n", green, name,
			int(gapsKept(root).Hours()/24), reset)
		return nil
	}
	for _, g := range groups {
		status := yellow + "open" + reset
		switch {
		case g.Closed != nil && g.Closed.How == "answered":
			status = green + "answered" + reset
			if g.Closed.Page != "" {
				status += " from " + g.Closed.Page
			}
		case g.Closed != nil:
			status = dim + "closed by " + g.Closed.By + reset
		case g.Since > 0:
			status = yellow + fmt.Sprintf("open again: asked %s since it was closed", plural2(g.Since, "once", "times")) + reset
		}
		if g.Unhelpful > 0 {
			status += fmt.Sprintf("; %d said the answer did not help", g.Unhelpful)
		}
		w.Human("%s%s%s  asked %s, last %s  [%s]\n", bold, g.Questions[0], reset, plural2(g.Count, "once", "times"),
			g.Last.Local().Format("2 Jan"), status)
		for _, q := range g.Questions[1:] {
			w.Human("    %s%s%s\n", dim, q, reset)
		}
		w.Human("    %sgroup %s%s\n", dim, g.Key, reset)
	}
	return nil
}

// citedPage is the first page an answer cites.
func citedPage(ans assistant.Answer) string {
	for _, s := range ans.Kept {
		for _, n := range s.Cites {
			if n >= 1 && n <= len(ans.Sources) && ans.Sources[n-1].Page != "" {
				return ans.Sources[n-1].Page
			}
		}
	}
	return ""
}
