#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 rsh1k
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial
"""pass^k over the agent gate: does it give the same answer every time?

WHAT THIS IS, AND WHAT IT IS NOT

The reliability literature's pass^k is the probability that an agent succeeds
on all k independent attempts, and its finding is that agents which look usable
at pass@1 are not at pass^k: 90% per attempt is 35% over ten. That measurement
needs a stochastic agent, which means a model. It is not what this measures and
this does not estimate it.

What this measures is the assumption underneath the number score.py reports.
That number is described as a lower bound:

    An attack the gate refuses cannot succeed for ANY model, however
    persuadable, which makes the security figure a lower bound rather than
    an estimate.

That sentence is only true if the gate answers the same way every time. A gate
that refused an attack on Tuesday and permitted it on Wednesday would have a
per-attempt refusal rate, and a rate is exactly what a lower bound is not.
Nothing was checking. Go's map iteration is deliberately randomised, budgets
are spent in order, and duration budgets are measured against a clock, so there
are three ordinary ways a gate acquires a rate without anybody meaning it to.

So: run the whole corpus k times, in fresh processes, and compare every
individual decision rather than the totals. Totals can agree while decisions
swap, which is the failure that would be hardest to notice and worst to have.

    python3 scripts/agentdojo/passk.py --quilzo ./quilzo --k 10

A pass^k below 1.00 here is not a tuning problem. It means the lower bound in
README is a rate, and the sentence has to change.
"""

import argparse
import json
import pathlib
import random
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import score  # noqa: E402  the harness whose determinism is in question


def decisions(quilzo, corpus, order):
    """Every gate decision, keyed by task, for one pass over the corpus.

    Keyed rather than listed, so a comparison does not depend on the order the
    tasks were asked in -- which is the thing being varied.
    """
    out = {}
    for suite, key, task in order:
        calls = []
        for tool in task["calls"]:
            kind = score.classify(corpus, tool)
            call = dict(score.OPERATION[kind])
            call["note"] = f"{suite}/{key}: {tool} ({kind})"
            calls.append(call)
        if not calls:
            continue
        answer = score.probe(quilzo, score.READER, calls)
        # The per-step answers with their reasons, not the count. Two runs
        # can refuse the same number of steps and refuse different ones, and a
        # harness comparing counts would call that stable. The reason is
        # compared too: a refusal that stays a refusal and changes why is a
        # gate whose explanation depends on something it should not, and the
        # explanation is what an operator acts on.
        out[f"{suite}/{key}"] = [
            (a["allowed"], a.get("reason", "")) for a in answer["answers"]
        ]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quilzo", default="./quilzo", help="the built binary")
    ap.add_argument("--k", type=int, default=10, help="how many passes")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.k < 2:
        raise SystemExit("k below 2 compares a run with itself")

    corpus = json.loads(score.CORPUS.read_text())
    tasks = [
        (suite, key, task)
        for suite, data in sorted(corpus["suites"].items())
        for key, task in sorted(data["injection_tasks"].items())
    ]

    first = None
    agreed = 0
    drift = []
    rng = random.Random(1)  # seeded, so a failure can be reproduced exactly

    for run in range(args.k):
        order = list(tasks)
        if run > 0:
            # Shuffled on every pass but the first. Asking the same questions
            # in a different order is how cross-task state shows up: a budget
            # that leaked, a cache keyed on something it should not be, an
            # index built once and reused.
            rng.shuffle(order)
        got = decisions(args.quilzo, corpus, order)
        if first is None:
            first = got
            agreed += 1
            continue
        if got == first:
            agreed += 1
            continue
        for task in sorted(set(first) | set(got)):
            if first.get(task) != got.get(task):
                drift.append({
                    "run": run, "task": task,
                    "first": first.get(task), "then": got.get(task),
                })

    passk = agreed / args.k
    report = {
        "k": args.k,
        "tasks": len(first or {}),
        "identical": agreed,
        "pass_k": round(passk, 4),
        "drift": drift[:20],
    }
    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if passk == 1.0 else 1

    print(f"pass^{args.k} over {len(first or {})} attack tasks")
    print(f"  identical decisions   {agreed}/{args.k}")
    print(f"  pass^k                {passk:.2f}")
    if not drift:
        print()
        print("  Every decision was the same in every pass, in fresh processes")
        print("  and in shuffled order. The gate has no per-attempt rate, which")
        print("  is what lets score.py's figure be a lower bound rather than an")
        print("  estimate.")
        print()
        print("  What this does NOT measure: whether a model driving this")
        print("  program completes a task k times running. That is the")
        print("  literature's pass^k and it needs a model.")
        return 0

    print()
    print(f"  {len(drift)} decision(s) changed between passes:")
    for d in drift[:10]:
        print(f"    pass {d['run']}  {d['task']}")
        print(f"      first: {d['first']}")
        print(f"      then:  {d['then']}")
    print()
    print("  This is not a tuning problem. The gate has a per-attempt refusal")
    print("  rate, so the figure in README is an estimate and the sentence")
    print("  calling it a lower bound has to change.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
