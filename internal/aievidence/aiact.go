// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package aievidence

import (
	"fmt"
	"time"
)

// The EU AI Act's duties for a deployer: Regulation (EU) 2024/1689, as
// amended by Regulation (EU) 2026/1744. Article 26 binds the deployers of
// high-risk systems (from 2 December 2027 for those in Annex III); Article
// 50 binds every deployer of a system that talks to people or makes
// content, from 2 August 2026; Article 4 every deployer. The evidence is
// the same whether or not a system is high-risk, so it is given for all.

// Deployer is the duties, each with what the program shows of it.
func Deployer(in Inputs) []Item {
	f := gather(in)
	c := f.c
	period := fmt.Sprintf("%s to %s", in.From.UTC().Format("2 Jan 2006"), in.Now.UTC().Format("2 Jan 2006"))
	var out []Item
	add := func(it Item) { out = append(out, settle(it, in, "eu-ai-act")) }

	add(Item{Ref: "Art. 4", Title: "AI literacy of the people who operate and use the systems", Status: Yours,
		Evidence: []string{fmt.Sprintf("%d agents, each answered for by a named person (%d with standing here)", f.agents, f.sponsored)},
		Yours:    "the training and the measures for staff: Quilzo names who runs and answers for each agent, not what they know"})

	it := Item{Ref: "Art. 26(1)", Title: "Use in accordance with the instructions for use", Status: Shown,
		Evidence: []string{
			fmt.Sprintf("every one of the %d agents runs under a declared purpose and a manifest enforced at one gate", f.agents),
			fmt.Sprintf("%s: %d runs, %d actions, %d of them refused because the manifest did not allow them", period, c.Runs, c.Actions, c.Refused),
		}}
	if f.agents == 0 {
		it.Status, it.Evidence = Yours, []string{"no agent is declared here"}
	}
	add(it)

	it = Item{Ref: "Art. 26(2)", Title: "Human oversight by people with the competence, training and authority", Status: Shown,
		Evidence: []string{
			fmt.Sprintf("%d of %d agents are answered for by a person who still has access here; an agent whose sponsor leaves stops running", f.sponsored, f.agents),
			fmt.Sprintf("%s: people approved %d actions agents stopped at and declined %d; %d runs were canceled", period, c.Approved, c.Declined, c.Canceled),
			"publishing, and anything an agent's declaration asks first about, waits for a person; external actions need a second person",
		},
		Yours: "that the people answering for agents are competent and trained for it"}
	if len(f.unsponsored) > 0 {
		it.Status = Partly
		it.Evidence = append(it.Evidence, "nobody with standing answers for: "+list(f.unsponsored))
	}
	add(it)

	held := 0
	for _, n := range in.State.AI.HeldMemories {
		held += n
	}
	screened := 0
	for _, b := range in.Chatbots {
		if !b.KeepInstructions {
			screened++
		}
	}
	add(Item{Ref: "Art. 26(4)", Title: "Input data relevant and representative, as far as the deployer controls it", Status: Shown,
		Evidence: []string{
			fmt.Sprintf("%d chatbots answer only from what is published; %d of them leave out passages addressed to an AI, which is how a planted instruction looks", len(in.Chatbots), screened),
			"text a person could not see (invisible characters) is taken out before any model reads it",
			fmt.Sprintf("%d memories learnt after reading somebody else's words wait for a person; %d were confirmed in the period", held, c.Confirmed),
		}})

	it = Item{Ref: "Art. 26(5)", Title: "Monitoring the operation, and suspending a system that presents a risk", Status: Shown,
		Evidence: []string{
			fmt.Sprintf("%d of %d agents have been evaluated against planted instructions; %d of their cases followed one", f.evaluated, f.agents, f.steer),
			fmt.Sprintf("%s: the shield paused agents %d times, and the watchdog flagged agents %d times", period, c.Paused, c.Flagged),
			"an agent that follows a planted instruction loses the autonomy its evaluations earned, at once",
		},
		Yours: "telling the provider, and the market surveillance authority of a serious incident"}
	if len(f.unevaluated) > 0 {
		it.Status = Partly
		it.Evidence = append(it.Evidence, "never evaluated: "+list(f.unevaluated))
	}
	add(it)

	it = Item{Ref: "Art. 26(6)", Title: "Keeping the logs the system generates, for at least six months", Status: Shown,
		Evidence: []string{"every run, action, approval and model call is a record in a hash-chained log, with signed heads and inclusion proofs; nothing is deleted from it",
			fmt.Sprintf("receipts prove what any run did without the rest of the log (quilzo agent receipt)")}}
	if !c.First.IsZero() {
		it.Evidence = append(it.Evidence, "the log begins on "+c.First.UTC().Format("2 January 2006"))
		if in.Now.Sub(c.First) < 183*24*time.Hour {
			it.Evidence = append(it.Evidence, "it is younger than six months: keep it, and its copies, at least that long")
		}
	} else {
		it.Status = Partly
		it.Evidence = append(it.Evidence, "the log is empty or could not be read")
	}
	add(it)

	add(Item{Ref: "Art. 26(7)", Title: "Telling workers and their representatives before putting a system to use at work", Status: Yours,
		Yours: "the consultation and the notice; the Fleet screen lists what is in use and who answers for it"})

	add(Item{Ref: "Art. 26(9), Art. 27", Title: "Data protection and fundamental-rights impact assessments", Status: Yours,
		Evidence: []string{fmt.Sprintf("%s: prompts had personal data or credentials taken out before reaching a model %d times", period, c.Masked),
			"model routes outside the organisation that may receive personal data are a posture finding until an agreement is on record"},
		Yours: "the assessments themselves, and the records of processing"})

	add(Item{Ref: "Art. 26(11)", Title: "Telling people a high-risk system decides, or helps decide, about them", Status: Yours,
		Evidence: []string{"every person sees, on Memory, what agents remember about them, and can rewrite it or have it forgotten, with a receipt"},
		Yours:    "the notice to the people decisions are about"})

	it = Item{Ref: "Art. 50(1)", Title: "People are told they are talking to an AI system", Status: Shown,
		Evidence: []string{fmt.Sprintf("%d of %d public chatbots say they are automated on the page that serves them", len(f.disclosed), f.publicBots)}}
	if len(f.undisclosed) > 0 {
		it.Status = Partly
		it.Evidence = append(it.Evidence, "not disclosed: "+list(f.undisclosed))
	}
	if f.publicBots == 0 {
		it.Status, it.Evidence = Shown, []string{"no chatbot is public"}
	}
	add(it)

	it = Item{Ref: "Art. 50(2)", Title: "Content an AI generated or changed is marked as such", Status: Shown,
		Evidence: []string{"what an agent writes is recorded as AI-generated, which cannot be turned off, and published pages carry it"}}
	if n := len(in.State.Content.UnmarkedPages); n > 0 {
		it.Status = Partly
		it.Evidence = append(it.Evidence, fmt.Sprintf("%d published pages lack the marking", n))
	}
	add(it)

	add(Item{Ref: "Art. 86", Title: "An explanation of a decision, for the person it affects", Status: Yours,
		Evidence: []string{"each run keeps its goal, its steps, what it read and what it was refused, and a receipt proves them"},
		Yours:    "the explanation given to the person"})
	return out
}
