package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/lithoform/lithoform/internal/audit"
	"github.com/lithoform/lithoform/internal/i18n"
	"github.com/lithoform/lithoform/internal/out"
	"github.com/lithoform/lithoform/internal/site"
)

func localesPath(root string) string { return filepath.Join(root, "locales.json") }

func loadLocales(root string) (*i18n.Config, error) {
	c := &i18n.Config{}
	if err := loadJSON(localesPath(root), c); err != nil {
		return nil, err
	}
	if c.Default == "" {
		return nil, nil
	}
	return c, nil
}

func cmdLang(root string, args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		return langStatus(root)
	case "init":
		return langInit(root, args[1:])
	case "add":
		return langAdd(root, args[1:])
	case "check":
		return langCheck(root)
	case "translated":
		return langTranslated(root, args[1:])
	default:
		return fmt.Errorf("unknown lang command %q; try status, init, add, "+
			"check or translated", args[0])
	}
}

func langInit(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: scrivet lang init <default-locale>")
	}
	l, err := i18n.ParseLocale(args[0])
	if err != nil {
		return err
	}
	if existing, _ := loadLocales(root); existing != nil {
		return fmt.Errorf("this site already has %s as its default language",
			existing.Default)
	}
	c := i18n.NewConfig(l)
	if err := saveJSON(localesPath(root), c); err != nil {
		return err
	}
	w.Human("default language is %s%s%s\n", bold, l, reset)
	w.Human("  %spages stay where they are; a second language is added under a "+
		"prefix%s\n", dim, reset)
	return nil
}

func langAdd(root string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: scrivet lang add <locale>")
	}
	c, err := loadLocales(root)
	if err != nil {
		return err
	}
	if c == nil {
		return fmt.Errorf("run `scrivet lang init <locale>` first, so there is " +
			"a default language for translations to be made from")
	}
	l, err := i18n.ParseLocale(args[0])
	if err != nil {
		return err
	}
	if err := c.Add(l); err != nil {
		return err
	}
	if err := saveJSON(localesPath(root), c); err != nil {
		return err
	}

	caller := resolveCaller(root, "")
	record(root, audit.Record{
		Action: "lang.add", Resource: "/", Outcome: audit.Success,
		Principal: caller.Name, Kind: caller.Kind, Verified: caller.Verified,
		Detail: map[string]string{"locale": string(l)},
	})

	w.Human("added %s%s%s\n", bold, l, reset)
	w.Human("  %spages go under %s/, and %s is %s%s\n",
		dim, l, l, l.Dir(), reset)
	w.Human("  %sscrivet lang check — which translations are missing or stale%s\n",
		dim, reset)
	return nil
}

func langCheck(root string) error {
	c, err := loadLocales(root)
	if err != nil {
		return err
	}
	if c == nil {
		return fmt.Errorf("no languages are configured; run `scrivet lang init`")
	}
	s, err := open(root)
	if err != nil {
		return err
	}

	ref := site.RefDraft
	if s.GetRef(ref) == "" {
		ref = site.RefLive
	}
	tree, err := pageHashes(s, ref)
	if err != nil {
		return err
	}

	// Sources are the pages in the default language; present is everything that
	// exists, in stored form.
	sources := map[string]string{}
	present := map[string]bool{}
	for stored, oid := range tree {
		present[stored] = true
		if l, page := c.Split(stored); l == c.Default {
			sources[page] = oid
		}
	}

	states := c.Check(sources, present)
	counts := i18n.Counts(states)

	if w.Mode == out.JSON {
		w.JSON(map[string]any{"states": states, "counts": counts})
		if counts[i18n.Stale] > 0 {
			return errBlocked{fmt.Errorf("%d stale translation(s)", counts[i18n.Stale])}
		}
		return nil
	}

	if len(states) == 0 {
		w.Human("one language (%s), so there is nothing to compare\n", c.Default)
		return nil
	}
	for _, st := range states {
		switch st.Status {
		case i18n.Current:
			w.Human("  %scurrent%s   %-20s %s\n", green, reset, st.Page, st.Locale)
		case i18n.Stale:
			w.Human("  %sstale%s     %-20s %s\n", red, reset, st.Page, st.Locale)
			w.Human("            %stranslated from %s, the source is now %s%s\n",
				dim, short(st.TranslatedFrom), short(st.SourceHash), reset)
			if st.TranslatedBy != "" {
				w.Human("            %s%s made the translation%s\n",
					dim, st.TranslatedBy, reset)
			}
		case i18n.Missing:
			w.Human("  %smissing%s   %-20s %s\n", yellow, reset, st.Page, st.Locale)
		case i18n.Untracked:
			w.Human("  %suntracked%s %-20s %s\n", dim, reset, st.Page, st.Locale)
			w.Human("            %sthis translation exists with no record of what "+
				"it was made from,%s\n", dim, reset)
			w.Human("            %sso nothing can be said about whether it is "+
				"current%s\n", dim, reset)
		}
	}
	if counts[i18n.Stale] > 0 {
		return errBlocked{fmt.Errorf(
			"%d translation(s) are of content that has since changed",
			counts[i18n.Stale])}
	}
	return nil
}

// langTranslated records that a page was translated from the source as it
// currently stands.
func langTranslated(root string, args []string) error {
	pos, flags := leadingArgs(args, 2)
	fs := flag.NewFlagSet("translated", flag.ContinueOnError)
	by := fs.String("by", "", "who made the translation")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: scrivet lang translated <page> <locale>")
	}

	c, err := loadLocales(root)
	if err != nil || c == nil {
		return fmt.Errorf("no languages are configured")
	}
	l, err := i18n.ParseLocale(pos[1])
	if err != nil {
		return err
	}
	if !c.Has(l) {
		return fmt.Errorf("%s is not a configured language", l)
	}

	s, err := open(root)
	if err != nil {
		return err
	}
	ref := site.RefDraft
	if s.GetRef(ref) == "" {
		ref = site.RefLive
	}
	tree, err := pageHashes(s, ref)
	if err != nil {
		return err
	}

	sourceStored := c.Path(pos[0], c.Default)
	sourceHash, ok := tree[sourceStored]
	if !ok {
		return fmt.Errorf("there is no %s to translate from", sourceStored)
	}
	if _, ok := tree[c.Path(pos[0], l)]; !ok {
		return fmt.Errorf("%s does not exist yet; write the translation first",
			c.Path(pos[0], l))
	}

	who := *by
	if who == "" {
		who = resolveCaller(root, "").Name
	}
	c.Record(pos[0], l, sourceHash, who, time.Now())
	if err := saveJSON(localesPath(root), c); err != nil {
		return err
	}

	w.Human("%s/%s is a translation of %s\n", l, pos[0], short(sourceHash))
	w.Human("  %sif that source changes, this will report as stale — not because\n"+
		"  anybody remembers, but because the hash stops matching%s\n", dim, reset)
	return nil
}

func langStatus(root string) error {
	c, err := loadLocales(root)
	if err != nil {
		return err
	}
	if c == nil {
		if w.JSON(map[string]any{"configured": false}) {
			return nil
		}
		w.Human("one language, unconfigured\n")
		w.Human("  %sscrivet lang init en — then `lang add fr` for a second%s\n",
			dim, reset)
		return nil
	}
	if w.JSON(c) {
		return nil
	}
	for _, l := range c.Locales {
		marker := " "
		if l == c.Default {
			marker = "*"
		}
		w.Human("  %s %-10s %s%s%s\n", marker, l, dim, l.Dir(), reset)
	}
	w.Human("\n  %s* is the default, served without a prefix%s\n", dim, reset)
	return nil
}
