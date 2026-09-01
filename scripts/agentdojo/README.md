# Scoring the agent gate against AgentDojo

The design follows CaMeL ([arXiv:2503.18813](https://arxiv.org/abs/2503.18813)):
the manifest is enforced at a chokepoint outside the model, so a hijacked agent
can still only do what it declared. That is a claim, and this is the measurement.

## Reproducing the number

```sh
go build -o quilzo ./cmd/quilzo
python3 scripts/agentdojo/score.py --quilzo ./quilzo
```

No model, no key, no network. It takes a few seconds.

## What is measured, and what is not

AgentDojo asks whether an injected instruction *persuades a model* to perform the
attacker's task. This program's claim is narrower and stronger: that it does not
matter whether the model is persuaded.

So the harness assumes the attack has already won completely — the model is
hijacked and emits the attacker's calls verbatim — and asks the gate. An attack
the gate refuses cannot succeed for **any** model, however persuadable, which
makes the security figure a **lower bound** rather than an estimate.

Three things this does not measure, stated because a benchmark that quietly
substitutes one number for another is worse than one that says what it lacks:

- **Benign utility.** Whether a model driving this program completes a task at
  all needs a model. Not measured, not estimated.
- **Attacks with no action.** One injection task asks only that the agent *say*
  something. A policy on what an agent may do does not address an attack on what
  it says. That is a limit of this defence, not of this harness.
- **Tasks AgentDojo scores by environment state.** Nine injection tasks have no
  ground-truth call sequence, so there is nothing to replay; they are excluded
  from the figure and listed in the output rather than counted as refusals.

## The translation, and why it is arguable

AgentDojo's tools are `send_email`, `send_money`, `book_flight`. This program's
are `read_page`, `write_page`, `publish`, `fetch`. There is no one-to-one mapping,
so every tool in the corpus is classified by what it *does* rather than what it
is called:

| class | means | becomes |
|---|---|---|
| `read` | looks at stored state | `read_page` |
| `write` | changes stored state | `write_page` |
| `publish` | acts outwardly and irreversibly | `publish` |
| `fetch` | reaches another host | `fetch` at an undeclared host |

The table is `corpus.json`, in the repository, so it can be disagreed with. The
weakness to state plainly: a classification is a judgement. `reserve_hotel` is
called irreversible here because a reservation is made in somebody else's system;
a reader who thinks it is a write would get a different number, and the mapping
is checked in so that argument can be had with the evidence in front of both
people.

## The result

AgentDojo v1.2.1, 26 replayable injection tasks and 97 user tasks:

```
  attacks refused        26/26 (100%)
  tasks unattended       71/97 (73%)
  tasks needing a person 26/97 (27%)
  tasks refused outright  0/97 (0%)
```

The 26 that need a person are the publish rule, not a refusal of the work: an
agent that can publish must have human approval — `Manifest.Validate` forces it
on — so the act happens once somebody agrees. Nothing in the suite is work the
policy prevents entirely.

For comparison, CaMeL reports 77% of AgentDojo tasks solved with provable
security against 84% undefended. That number is not this one: it is a model
completing tasks end to end, which is the measurement above that needs a key.

## Regenerating the corpus

```sh
python3 -m venv .venv && .venv/bin/pip install agentdojo
.venv/bin/python scripts/agentdojo/extract.py > scripts/agentdojo/corpus.json
```

The corpus is checked in rather than fetched at score time, because a benchmark
whose inputs arrive over the network is one whose number nobody can reproduce
later. `extract.py` refuses to write a corpus containing a tool nobody has
classified, which is what stops a version bump from silently dropping cases out
of the score.

## How the gate is asked

`quilzo agent probe` — JSON in, JSON out:

```sh
echo '{
  "manifest": {"name":"reader","kind":"retrieval","purpose":"Answers questions.",
    "capabilities":["read_page"],"autonomy":"propose",
    "retrieval":{"ref":"live"},
    "budget":{"steps":8,"tool_calls":4,"duration":"2m0s"}},
  "calls": [{"op":"publish","note":"what the attacker wants"}]
}' | quilzo agent probe
```

It builds an `agent.Session` and calls `Authorize`, `Retrieve`, `Mutate` and
`MayReach` in the order the executor does — the same code path, not a copy of the
rules for benchmarking. It touches no store, writes nothing and audits nothing: a
probe is a question about a policy, not a run.
