# Quilzo agent excellence — a researched plan

Built 11 October 2026 from four research passes: the labs' shipped products
and their architectural limits; the open-source ecosystem's top projects and
their signature mechanics; agent-product customer experience and its top
complaints; and an adversarial audit of everything this repository had built
to date (whose findings are already fixed on this branch). Numbers marked
*unverified* could not be confirmed from a primary source.

## Where Quilzo stands after this branch

The computer-use plan's P3–P5 are built and hardened: vendor dialect
adapters (a model may answer in Anthropic's, OpenAI's or Gemini's own
computer-use shapes, translated onto a closed vocabulary that widens for
nobody), the signed action cache (replays confirmed by the page that
follows, sealed inputs, replays audited), the person's take-over of a
waiting browser, the governed browser offered over MCP under
administrator-declared grants, desktop cells' host side (Firecracker and
Cloud Hypervisor over their sockets, the vsock helper protocol), the
optional deny-only action reviewer, and JSON attack numbers from
evaluations. The audit's findings — an inert cache, grant-session races, a
machine-wide lock held across page I/O, cell protocol bounds, shield gaps —
are fixed with the tests that would have caught them, and so are a second
review's: a microVM killed as it started, a vsock handshake that dropped
bytes, presses weighed only by the helper inside the cell, a cache shared
between people, a diff gate blind to a dozen kinds of widening, an
unreachable take-over, and a bundle that gave a reader the pictures.
Desktop cells stay experimental: the helper inside the image is the
operator's to build, and the microVM runs without the jailer.

Three things this branch adds beyond the original plan, each stolen
honestly from the ecosystem and done Quilzo's way:

- **Agents can ask typed questions** (the deciders, the bounded-question
  pattern with measured confidence, now performed inside runs — it
  validated, appeared on agent cards, and died at dispatch before).
- **The declaration diff gate** (OpenShell's held-for-review policy
  deltas): an amendment that widens reach is refused until the exact list
  is read, and the widening allowed is written to the log as it was read.
- **The replay bundle** (`agent receipt --bundle`): one self-contained
  file carrying steps, the pictures a person was asked about, and the
  receipt's inclusion proofs and signed head — evidence nobody else in
  the observability space produces at all.

## The industry, October 2026, in one table

| Who | Position | What they cannot do |
|---|---|---|
| OpenAI dots / Agents API | Always-on agents with their own cloud computers | The computer, the rules and the evidence live in OpenAI's tenant; no customer-held proof, no air gap |
| Anthropic Cowork / Managed Agents | Managed agent infra plus a desktop agent | The loop, approvals and audit are Anthropic product behaviour in Anthropic's cloud |
| Google Gemini auto-browse / WebMCP | The browser is the runtime; sites are MCP servers | Agent-side enforcement point is Google's Chrome context; no enterprise approval gate on the agent |
| Microsoft Agent 365 / Windows 365 for Agents | Identity + desktop + governance in one tenant | All of it is Microsoft-cloud-hosted and M365-bound; the closest competitor, and bound |
| OpenClaw (391k★) | The personal assistant that won adoption | Governance lost to adoption: ClawHavoc (341 malicious skills), sandbox escapes, then a trust-model rebuild |
| Langfuse / LangSmith / AgentOps | Traces, evals, cost dashboards | Observers of API traffic; no runtime, no approvals, no cryptographic receipts |
| Paperclip (100k★) / OpenHands (90k★) | Self-hosted agent workforce / control centre | Budgets and locks without evidence, or control without policy-as-manifest |

**The whitespace nobody owns:** a customer-hosted, air-gappable control
plane that governs any vendor's agent at the execution boundary over open
protocols, with local manifests, synchronous approvals, and signed
evidence the customer owns. Everyone either governs only their own
ecosystem, observes API traffic, or hosts the execution themselves.

**Benchmarks, honestly:** OSWorld-Verified ~86% (above the 72% human
baseline), but ClawBench — real chores on live sites — sits at **33%**,
and that gap is the truth about agents in 2026. SWE-bench Verified is
saturated and archived. Injection resistance (AgentDojo, VPI-Bench) is a
*substrate* property, not a model property — which is exactly Quilzo's
thesis, and the attack numbers Quilzo already publishes are the evidence
category the industry will be asked for when the EU AI Act's August 2027
legacy deadline arrives.

## What users complain about (and what to build for them)

The single loudest complaint class across Claude Code, Copilot agents and
Dots is **approval fatigue** — "y-mashing" through prompts, approval
queues piling up, notifications silently undelivered. The second is
**opaque cost** (Manus credits, Devin ACUs). The third is **stuck runs**
with no feedback. Trust research says the levers are evidence,
reversibility and incremental autonomy — not capability.

## The plan

### Near: the approval experience (weeks)

1. **One approval inbox** — web and mobile — grouping every waiting thing
   (held browser presses, held gateway calls, held grant presses,
   decider escalations) by agent and by what they commit to. "Approve all
   of these identical presses" for the same weighed action repeated on
   the same page; anything that writes, sends or pays stays
   one-at-a-time. *Kills the y-mashing complaint with batching that stays
   honest.*
2. **Escalations have a destination** — a decider that escalates (or a
   reviewer that refuses) lands in the same inbox, with the run's replay
   bundle attached, and answering it continues the run from its record.
   Today an escalation is a string in a log.
3. **Progressive autonomy, earned** — an action class moves from ask to
   auto after N clean, unmodified runs *and* no eval regression;
   any override or attack drops it back. Quilzo already has earned
   autonomy from evaluations; this is that machinery surfaced as the
   dial users can see moving. *Factory's Autonomy Levels, but earned by
   adversarial evidence rather than set by hand.*
4. **Confidence in the interface** — decider answers carry their measured
   confidence; low-confidence steps route to a typed question instead of
   a yes/no. No competitor surfaces calibrated confidence per action.
5. **Cost per task, in the open** — tokens and currency per run, per
   agent, per goal pattern, from what the gateway already meters; the
   run's page shows spend next to steps. *The Manus-credits complaint,
   answered structurally.*

### Mid: the evidence and identity layer (months)

6. **Agent identity at the boundary** — this program issues verifiable,
   signed agent credentials (the IETF/W3C trajectory) that any vendor's
   agent presents to use the governed browser over MCP; Entra Agent ID,
   but vendor-neutral and locally enforced. Grants become credentials.
7. **MCP Tasks as approval semantics** — implement the 2026-07-28 Tasks
   and Elicitation primitives as *enforced* approval gates with receipts,
   not passive task tracking; A2A already carries the delegation side.
8. **Provenance-first memory** — memories carry the runs and source
   digests they were learned from (Hindsight's evidence-backed
   observations, Mem0's ADD-only consolidation, done as an append-only
   superseding log); a person's memory receipt already exists — extend it
   to answer "when did you learn this about me". Standing answers become
   deterministic chatbot answers at zero model cost.
9. **Signed skills** — OpenClaw's SKILL.md format, but a skill is pinned
   by digest in the declaration, its `requires` gating evaluated by the
   checker never the model, and a skill body is untrusted-tier text that
   taints the run exactly like a page read. The ecosystem's most-loved
   extension mechanic, made governable.

### Long: the differentiators (quarters)

10. **Fit-Read** — deterministic content pruning (Crawl4AI's density
    heuristics over the stdlib parser) on every agent read, with the
    pruning ratio in the provenance record: fewer tokens, less surface
    for planted instructions, same output every run.
11. **Declaration-scheduled runs with execution locks** — Paperclip's
    atomic checkout and coalesced wakeups as declaration fields; two runs
    structurally cannot both write page X; scheduled runs default one
    autonomy notch below interactive ones.
12. **The person's own desktop (P6), when it can be verified** — the
    stdlib D-Bus client and the xdg RemoteDesktop consent are built:
    `quilzo desktop consent` shows the desktop's own dialog and gives the
    session straight back. No run may use a person's desktop until it can
    be tested against a real desktop session; macOS and Windows helpers
    need signing.

### Found already built, and better than planned

- **WebMCP publication by Quilzo's own sites** (the P5 leftover this plan
  had written off): it exists, declaratively — `site.webmcp` (on by
  default) marks the site's search, chatbots and forms as tools a
  visitor's browser agent can use, with `toolautosubmit` only for what
  reads, the visitor submitting what sends, sensitive and account forms
  not offered at all, and an origin-trial token while Chrome waits.
  Attributes on HTML the site already serves, no script, nothing for a
  page to exploit — better than the script-based registration this plan
  sketched. What remains is nothing: the admin's own pages publish no
  tools, because the admin is a person's interface and an agent's tools
  there would be the wrong direction of trust.

### Deliberately not built

- **CaMeL's full label algebra on structured tools**: Quilzo's
  taint/breaker is the practical core of it; the reviewer covers the
  judgement gap. The remaining algebra is research, not product.

## The pitch this plan earns

Every lab converges on always-on agents with their own computers, and
every one of them puts the loop in their own cloud. Gartner expects 40% of
agentic projects scrapped by 2027 over governance and trust. The product
that survives that cull is the one that can hand an auditor one file —
steps, pictures, proof, signed — and say: this is exactly what the agent
did, this is what a person approved, and here is the mathematics. That
file exists on this branch. The work above makes it the ordinary output
of an ordinary Tuesday's runs.
