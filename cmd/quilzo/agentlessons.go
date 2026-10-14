// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/quilzo/quilzo/internal/atomicfile"
	"github.com/quilzo/quilzo/internal/audit"
	"github.com/quilzo/quilzo/internal/evals"
	"github.com/quilzo/quilzo/internal/lessons"
)

// An agent's lessons (internal/lessons): one file per agent, written from
// runs that went wrong, tried against its evaluations, adopted per model by
// a person.

func lessonsPath(root, name string) string {
	return filepath.Join(agentsDir(root), "lessons", name+".json")
}

type lessonFile struct {
	Agent   string           `json:"agent"`
	Lessons []lessons.Lesson `json:"lessons"`
}

func loadLessons(root, name string) ([]lessons.Lesson, error) {
	var f lessonFile
	b, err := readBounded(lessonsPath(root, name), 4<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s's lessons are unreadable: %w", name, err)
	}
	return f.Lessons, nil
}

// changeLessons loads, changes and saves an agent's lessons under a lock.
func changeLessons(root, name string, change func([]lessons.Lesson) ([]lessons.Lesson, error)) error {
	path := lessonsPath(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	unlock, err := atomicfile.Lock(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	all, err := loadLessons(root, name)
	if err != nil {
		return err
	}
	if all, err = change(all); err != nil {
		return err
	}
	b, err := json.MarshalIndent(lessonFile{Agent: name, Lessons: all}, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}

// lessonsPlaybook is what a run of an agent with this model reads.
func lessonsPlaybook(root, name, model string) ([]string, []string) {
	all, err := loadLessons(root, name)
	if err != nil {
		return nil, nil
	}
	return lessons.Playbook(all, model)
}

func findLesson(all []lessons.Lesson, id string) (int, error) {
	for i := range all {
		if all[i].ID == id {
			return i, nil
		}
	}
	return -1, fmt.Errorf("there is no lesson %s", id)
}

// agentLessons is `quilzo agent lessons NAME | reflect RUN | try NAME ID |
// adopt NAME ID | retire NAME ID`.
func agentLessons(root string, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: quilzo agent lessons NAME | reflect RUN | try NAME ID [--k N] | adopt NAME ID | retire NAME ID --why W")
	}
	caller := resolveCaller(root, flagToken)
	switch args[0] {
	case "reflect":
		if len(args) != 2 {
			return errors.New("usage: quilzo agent lessons reflect RUN")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		l, err := reflectOnRun(ctx, root, args[1], caller)
		if err != nil {
			return err
		}
		if w.JSON(l) {
			return nil
		}
		w.Human("%s%s%s  a candidate for %s: %s\n", bold, l.ID, reset, l.Agent, l.Text())
		if l.Tainted {
			w.Human("  %swritten from a run that read somebody else's words; read it before trying it%s\n", yellow, reset)
		}
		w.Human("  try it against the evaluations: quilzo agent lessons try %s %s\n", l.Agent, l.ID)
		return nil
	case "try":
		pos, flags := leadingArgs(args[1:], 2)
		fs := flag.NewFlagSet("agent lessons try", flag.ContinueOnError)
		k := fs.Int("k", 3, "how many times each case runs, each way")
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) != 2 {
			return errors.New("usage: quilzo agent lessons try NAME ID [--k N]")
		}
		t, err := tryLesson(root, pos[0], pos[1], *k, caller)
		if err != nil {
			return err
		}
		if w.JSON(t) {
			return nil
		}
		verdict := red + "not adopted" + reset
		if t.Better {
			verdict = green + "it helped" + reset
		}
		w.Human("%s with %s: %s\n", verdict, t.Model, t.Why)
		if t.Better {
			w.Human("  adopt it: quilzo agent lessons adopt %s %s\n", pos[0], pos[1])
		}
		return nil
	case "adopt":
		pos, flags := leadingArgs(args[1:], 2)
		fs := flag.NewFlagSet("agent lessons adopt", flag.ContinueOnError)
		tainted := fs.Bool("tainted-ok", false, "adopt a lesson written from a run that read somebody else's words, having read it")
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) != 2 {
			return errors.New("usage: quilzo agent lessons adopt NAME ID [--tainted-ok]")
		}
		l, err := adoptLesson(root, pos[0], pos[1], *tainted, caller)
		if err != nil {
			return err
		}
		w.Human("adopted %s for %s: runs of %s with it read “%s”\n", l.ID, strings.Join(l.AdoptedFor, ", "), l.Agent, l.Text())
		return nil
	case "retire":
		pos, flags := leadingArgs(args[1:], 2)
		fs := flag.NewFlagSet("agent lessons retire", flag.ContinueOnError)
		why := fs.String("why", "", "why it is retired")
		if err := fs.Parse(flags); err != nil {
			return err
		}
		if len(pos) != 2 {
			return errors.New("usage: quilzo agent lessons retire NAME ID --why W")
		}
		if err := retireLesson(root, pos[0], pos[1], *why, caller); err != nil {
			return err
		}
		w.Human("retired %s; no run of %s reads it\n", pos[1], pos[0])
		return nil
	}
	if len(args) != 1 {
		return errors.New("usage: quilzo agent lessons NAME")
	}
	return listLessons(root, args[0])
}

func listLessons(root, name string) error {
	all, err := loadLessons(root, name)
	if err != nil {
		return err
	}
	if w.JSON(map[string]any{"agent": name, "lessons": all}) {
		return nil
	}
	if len(all) == 0 {
		w.Human("%s has learnt nothing yet\n  %squilzo agent lessons reflect RUN writes a candidate from a run that went wrong%s\n", name, dim, reset)
		return nil
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Created.After(all[j].Created) })
	for _, l := range all {
		state := l.State
		if l.State == lessons.Adopted {
			state = green + "adopted for " + strings.Join(l.AdoptedFor, ", ") + reset
		}
		w.Human("%s%s%s  %s  %s\n    %s\n", bold, l.ID, reset, state, dim+lessons.Kinds[l.Kind]+reset, l.Text())
		if len(l.Trials) > 0 {
			w.Human("    %stried with %s: %s%s\n", dim, l.Trials[0].Model, l.Trials[0].Why, reset)
		}
	}
	return nil
}

// reflectModelSeam lets a test stand in for the reflecting model.
var reflectModelSeam func() (modelLike, string)

type modelLike interface {
	Complete(ctx context.Context, system, user string) (string, error)
	Name() string
}

// reflectOnRun writes a candidate lesson from a run that went wrong.
func reflectOnRun(ctx context.Context, root, runID string, caller *Caller) (lessons.Lesson, error) {
	var l lessons.Lesson
	rec, err := loadAgentRun(root, runID)
	if err != nil {
		return l, err
	}
	if err := manageAgent(root, caller, rec.Agent); err != nil {
		return l, fmt.Errorf("writing an agent's lessons takes managing it: %w", err)
	}
	why := lessons.WentWrong(rec.Trace)
	if why == "" {
		return l, fmt.Errorf("nothing went wrong in %s, so there is nothing to learn from it", runID)
	}
	var model modelLike
	var none string
	if reflectModelSeam != nil {
		model, none = reflectModelSeam()
	} else {
		m, n := draftModelFor(root, caller, "studio:reflect")
		if m != nil {
			model = m
		}
		none = n
	}
	if model == nil {
		return l, errors.New("writing a lesson needs a model, and " + none)
	}
	answer, err := model.Complete(ctx, lessons.ReflectPrompt, lessons.RunText(rec.Trace)+"\nWhat went wrong: "+why)
	if err != nil {
		return l, fmt.Errorf("the model did not answer: %w", err)
	}
	when, do, kind, err := lessons.ReadReflection(answer)
	if err != nil {
		return l, err
	}
	l = lessons.Lesson{ID: lessons.NewID(), Agent: rec.Agent, When: when, Do: do, Kind: kind, FromRun: rec.ID,
		FromSignal: clip(why, 500), Tainted: rec.Trace.Tainted, Created: time.Now().UTC(), By: caller.Name, State: lessons.Candidate}
	if err := l.Check(); err != nil {
		return l, err
	}
	err = changeLessons(root, rec.Agent, func(all []lessons.Lesson) ([]lessons.Lesson, error) {
		for _, o := range all {
			if strings.EqualFold(o.When, l.When) && strings.EqualFold(o.Do, l.Do) && o.State != lessons.Retired {
				l = o
				return all, nil
			}
		}
		if len(all) >= lessons.MaxPerAgent {
			return nil, fmt.Errorf("%s keeps %d lessons; retire some first", rec.Agent, lessons.MaxPerAgent)
		}
		return append(all, l), nil
	})
	if err == nil {
		record(root, caller.auditRecord("agent.lesson.written", "/", audit.Success, map[string]string{
			"agent": rec.Agent, "lesson": l.ID, "run": rec.ID, "kind": l.Kind}))
	}
	return l, err
}

// evaluateForLesson runs an agent's evaluations; a test stands in for it.
var evaluateForLesson = runEvaluationWith

// tryLesson runs an agent's evaluations with its playbook and with the
// lesson added, under the model its runs use, and records the verdict.
func tryLesson(root, name, id string, k int, caller *Caller) (lessons.Trial, error) {
	var t lessons.Trial
	if caller.Kind == audit.KindAI {
		return t, errors.New("a lesson is tried by a person")
	}
	if err := manageAgent(root, caller, name); err != nil {
		return t, fmt.Errorf("trying a lesson runs the agent's evaluations twice, which takes managing it: %w", err)
	}
	all, err := loadLessons(root, name)
	if err != nil {
		return t, err
	}
	i, err := findLesson(all, id)
	if err != nil {
		return t, err
	}
	if all[i].State == lessons.Retired {
		return t, fmt.Errorf("%s is retired", id)
	}
	if k < 1 || k > evals.MaxK {
		return t, fmt.Errorf("--k is between 1 and %d", evals.MaxK)
	}
	without, err := evaluateForLesson(root, name, evals.Options{K: k, Attempts: 1}, true, caller)
	if err != nil {
		return t, err
	}
	with, err := evaluateForLesson(root, name, evals.Options{K: k, Attempts: 1, Lesson: all[i].Text()}, true, caller)
	if err != nil {
		return t, err
	}
	t = lessons.Judge(with.Model, lessons.ScoreOf(without), lessons.ScoreOf(with), time.Now())
	err = changeLessons(root, name, func(all []lessons.Lesson) ([]lessons.Lesson, error) {
		i, err := findLesson(all, id)
		if err != nil {
			return nil, err
		}
		all[i].Trials = append([]lessons.Trial{t}, all[i].Trials...)
		if len(all[i].Trials) > 10 {
			all[i].Trials = all[i].Trials[:10]
		}
		return all, nil
	})
	record(root, caller.auditRecord("agent.lesson.tried", "/", audit.Success, map[string]string{
		"agent": name, "lesson": id, "model": t.Model, "better": fmt.Sprint(t.Better)}))
	return t, err
}

// adoptLesson adopts a lesson for the model its latest trial helped.
func adoptLesson(root, name, id string, taintedOK bool, caller *Caller) (lessons.Lesson, error) {
	var l lessons.Lesson
	if caller.Kind == audit.KindAI {
		return l, errors.New("a lesson is adopted by a person. A model may write one; it may not adopt one")
	}
	if err := manageAgent(root, caller, name); err != nil {
		return l, fmt.Errorf("adopting a lesson takes managing the agent: %w", err)
	}
	err := changeLessons(root, name, func(all []lessons.Lesson) ([]lessons.Lesson, error) {
		i, err := findLesson(all, id)
		if err != nil {
			return nil, err
		}
		x := &all[i]
		switch {
		case x.State == lessons.Retired:
			return nil, fmt.Errorf("%s is retired", id)
		case len(x.Trials) == 0:
			return nil, fmt.Errorf("%s has not been tried; quilzo agent lessons try %s %s", id, name, id)
		case !x.Trials[0].Better:
			return nil, fmt.Errorf("its latest trial did not show it helps: %s", x.Trials[0].Why)
		case x.Tainted && !taintedOK:
			return nil, fmt.Errorf("%s was written from a run that read somebody else's words; read it, then adopt with --tainted-ok", id)
		}
		model := x.Trials[0].Model
		if !slices.Contains(x.AdoptedFor, model) {
			x.AdoptedFor = append(x.AdoptedFor, model)
		}
		x.State, x.Adopted, x.AdoptedBy = lessons.Adopted, time.Now().UTC(), caller.Name
		l = *x
		return all, nil
	})
	if err == nil {
		record(root, caller.auditRecord("agent.lesson.adopted", "/", audit.Success, map[string]string{
			"agent": name, "lesson": id, "models": strings.Join(l.AdoptedFor, ","), "by": caller.Name}))
	}
	return l, err
}

func retireLesson(root, name, id, why string, caller *Caller) error {
	if caller.Kind == audit.KindAI {
		return errors.New("a lesson is retired by a person")
	}
	if err := manageAgent(root, caller, name); err != nil {
		return fmt.Errorf("retiring a lesson takes managing the agent: %w", err)
	}
	if strings.TrimSpace(why) == "" {
		return errors.New("say why it is retired with --why")
	}
	err := changeLessons(root, name, func(all []lessons.Lesson) ([]lessons.Lesson, error) {
		i, err := findLesson(all, id)
		if err != nil {
			return nil, err
		}
		all[i].State, all[i].Retired, all[i].RetiredWhy = lessons.Retired, time.Now().UTC(), clip(why, 300)
		return all, nil
	})
	if err == nil {
		record(root, caller.auditRecord("agent.lesson.retired", "/", audit.Success, map[string]string{
			"agent": name, "lesson": id, "by": caller.Name}))
	}
	return err
}
