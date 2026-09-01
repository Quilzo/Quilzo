#!/usr/bin/env python3
"""Regenerate corpus.json from a real AgentDojo install.

    python3 -m venv .venv && .venv/bin/pip install agentdojo
    .venv/bin/python scripts/agentdojo/extract.py > scripts/agentdojo/corpus.json

Why the corpus is checked in rather than fetched at score time: a benchmark whose
inputs are downloaded when it runs is one whose number nobody can reproduce
later. The file in the repository is what the published figure was measured
against, it names the AgentDojo version it came from, and this script is how to
bring it forward.

Why the tool classification is not generated: it is a judgement about what each
of AgentDojo's tools *does*, and a judgement belongs in a file people can argue
with rather than in a heuristic over names. This script preserves the existing
classes and refuses to write a corpus containing a tool nobody has classified,
which is what stops a version bump from silently dropping cases out of the
score.
"""

import json
import pathlib
import sys

HERE = pathlib.Path(__file__).parent
EXISTING = HERE / "corpus.json"

VERSION = "v1.2.1"


def main():
    try:
        from agentdojo.task_suite.load_suites import get_suites
    except ImportError:
        print("agentdojo is not installed here. pip install agentdojo in a "
              "virtual environment and run this with that interpreter.",
              file=sys.stderr)
        return 1

    classes = json.loads(EXISTING.read_text())["classes"] if EXISTING.exists() else {}
    known = {tool for names in classes.values() for tool in names}

    suites = get_suites(VERSION)
    out = {"agentdojo_version": VERSION, "classes": classes, "suites": {}}
    unclassified = set()

    for name, suite in sorted(suites.items()):
        env = suite.load_and_inject_default_environment({})

        def calls_of(task):
            # An empty list is a real answer: some tasks are scored by the
            # environment afterwards rather than by a sequence of calls, and the
            # harness reports those as excluded rather than as passes.
            try:
                return [c.function for c in task.ground_truth(env)]
            except Exception:
                return []

        injections = {}
        for key, task in sorted(suite.injection_tasks.items()):
            calls = calls_of(task)
            unclassified.update(c for c in calls if c not in known)
            injections[key] = {"goal": getattr(task, "GOAL", ""), "calls": calls}

        users = {}
        for key, task in sorted(suite.user_tasks.items()):
            calls = calls_of(task)
            unclassified.update(c for c in calls if c not in known)
            users[key] = {"prompt": getattr(task, "PROMPT", ""), "calls": calls}

        out["suites"][name] = {
            "injection_tasks": injections, "user_tasks": users}

    if unclassified:
        print("These tools are in the corpus and not in the translation table:",
              file=sys.stderr)
        for tool in sorted(unclassified):
            print("  " + tool, file=sys.stderr)
        print("Classify each one in corpus.json under read, write, publish or "
              "fetch, then run this again. A tool nobody classified would be "
              "skipped, and a score that skips what it does not understand is "
              "a score about the rest.", file=sys.stderr)
        return 1

    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
