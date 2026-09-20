// SPDX-FileCopyrightText: 2026 rsh1k
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package agent

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// A session is one run of one agent, and the place its manifest becomes
// binding.
//
// # Why this exists rather than checks at each call site
//
// A manifest that nothing enforces is documentation. The temptation is to check
// the capability list wherever an operation is dispatched, and that is the shape
// this project has already been burned by twice: the content-type gate was
// checked in the CLI and not the API, and the token's own limits were checked in
// three places that each did a different subset. Both were found after they were
// exploitable, not before.
//
// So there is one object, every operation goes through it, and it refuses. The
// same reasoning that put destructive-operation policy inside HttpClient rather
// than inside each scanner: a chokepoint holds for the code that has never heard
// of it.
//
// # The trust boundary, and what it is not
//
// CaMeL's insight is that the plan must be formed from the trusted request only,
// and that data flowing out of untrusted sources must never reach the decision
// about what to do next. This session marks content read out of the store as
// untrusted — because it is: a page an agent reads may have been written by
// anybody who can write a page, including a form submission or a previous
// agent — and refuses to let it widen anything.
//
// What this does NOT claim is that the model is safe. It claims something
// smaller and checkable: whatever the model is talked into asking for, the
// answer is bounded by the manifest. An agent that has been fully hijacked can
// still do everything its manifest permits, which is exactly why the templates
// default to narrow and why the retrieval archetype cannot write at all.
//
// # Budgets are refusals, not warnings
//
// A goal-seeking agent in a loop is the ordinary way an unbounded bill arrives,
// and the loop is often the injection working. Exhausting a budget stops the
// run; it does not log and continue.

// Refusal is a session refusing an operation, distinct from the operation
// failing. A caller has to be able to tell "you may not" from "it broke",
// because they need different responses and only one of them is worth retrying.
type Refusal struct {
	Agent  string
	Op     string
	Reason string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("%s: %s refused %s", r.Agent, r.Op, r.Reason)
}

// IsRefusal reports whether an error is a policy refusal.
func IsRefusal(err error) bool {
	_, ok := err.(*Refusal)
	return ok
}

// Clock is injectable so budget expiry is testable without sleeping.
type Clock func() time.Time

// Session enforces one manifest for the length of one run.
//
// Safe for concurrent use: a supervisor may run delegates in parallel, and a
// budget that is only correct single-threaded is a budget that is wrong exactly
// when the agent is being most expensive.
type Session struct {
	mu       sync.Mutex
	manifest Manifest
	// capabilities is the manifest's list as a set, built once.
	capabilities map[string]bool
	// hosts is the tool allowlist as a set, lowercased.
	hosts map[string]bool

	started  time.Time
	now      Clock
	steps    int
	toolUses int
	tokens   int

	// refusals is every refusal this session made, for the audit record. Kept
	// rather than only counted: "the agent was refused 12 times" is a number,
	// and "it tried to publish four times" is a finding.
	refusals []Refusal

	// tainted records that untrusted content has been read. Once true it stays
	// true for the life of the session — there is no sanitising step that
	// clears it, because there is no sanitiser this package would trust.
	tainted bool
	// sources is what the taint came from, and reads is how many there were
	// including any past MaxSources that are counted and not named. See
	// provenance.go: a person asked to approve a tainted run was told that it
	// had read something and not what.
	sources []Source
	seen    map[string]bool
	reads   int
	omitted int
}

// NewSession begins a run. The manifest is copied, so editing the stored
// declaration mid-run cannot widen a session already in flight.
func NewSession(m Manifest, now Clock) *Session {
	if now == nil {
		now = time.Now
	}
	caps := make(map[string]bool, len(m.Capabilities))
	for _, c := range m.Capabilities {
		caps[c] = true
	}
	hosts := make(map[string]bool, len(m.Tools))
	for _, t := range m.Tools {
		hosts[strings.ToLower(strings.TrimSpace(t.Host))] = true
	}
	copied := m
	copied.Capabilities = append([]string(nil), m.Capabilities...)
	copied.Tools = append([]Tool(nil), m.Tools...)

	return &Session{
		manifest: copied, capabilities: caps, hosts: hosts,
		started: now(), now: now,
	}
}

func (s *Session) refuse(op, reason string) error {
	r := Refusal{Agent: s.manifest.Name, Op: op, Reason: reason}
	s.refusals = append(s.refusals, r)
	return &r
}

// spend accounts for one step and checks the two budgets that bound a run.
// Caller holds the lock.
func (s *Session) spend(op string) error {
	if d := s.now().Sub(s.started); d > time.Duration(s.manifest.Budget.Duration) {
		return s.refuse(op, fmt.Sprintf(
			"the run has taken %s and the budget is %s",
			d.Round(time.Second), s.manifest.Budget.Duration))
	}
	if s.steps >= s.manifest.Budget.Steps {
		return s.refuse(op, fmt.Sprintf(
			"the step budget of %d is spent. A goal-seeking agent that keeps "+
				"going is usually a loop, and often the injection working",
			s.manifest.Budget.Steps))
	}
	s.steps++
	return nil
}

// Authorize is the chokepoint. Every operation an agent performs passes here
// first, and nothing else in this package grants anything.
//
// Authorize is Check plus the budget: it decides, and it spends a step. Call it
// once per operation, from the loop.
func (s *Session) Authorize(op string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.check(op); err != nil {
		return err
	}
	return s.spend(op)
}

// Check asks the same question as Authorize and spends nothing.
//
// # Why both exist
//
// The runner authorises, then hands the action to an executor. Until this
// existed, the executor's own safety was a comment: it ran after Authorize had
// said yes, and that held for exactly as long as every caller remembered. An
// executor is an exported type any surface can construct, and "somebody
// remembers to ask" is how the content-type gate came to be checked in the CLI
// and not in the API, and how a token's limits came to be checked in three
// places that each did a different subset. Both were found after they were
// exploitable.
//
// So the executor re-asks, and because it re-asks it must not re-charge: a
// second Authorize would spend two steps for one operation and exhaust a
// budget at half its stated size, which is the kind of bug that looks like
// the agent giving up early.
//
// Idempotent and free. Call it as often as it takes.
func (s *Session) Check(op string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.check(op)
}

// check is the policy half of Authorize. Caller holds the lock.
func (s *Session) check(op string) error {
	if !s.capabilities[op] {
		// Named in the refusal, because the useful debugging answer is which
		// capability was missing rather than that one was.
		return s.refuse(op, fmt.Sprintf(
			"%q is not in this agent's capabilities (%s)",
			op, strings.Join(s.manifest.Capabilities, ", ")))
	}
	// A write is checked against autonomy as well as against the list. The two
	// are validated to agree when the manifest is stored, and re-checked here
	// because a stored file is not a proof about the object in memory.
	if IsWrite(op) && s.manifest.Autonomy == AutonomyPropose {
		return s.refuse(op, "this agent proposes and does not write")
	}
	if op == "publish" && s.manifest.Autonomy != AutonomyPublish {
		return s.refuse(op, "this agent does not publish")
	}
	if op == "publish" {
		// The taint rule, enforced where it bites rather than only reported
		// at the end.
		//
		// Publishable() answers the same question and was, until an executor
		// existed, the only place it was asked — at the close of a run, about
		// a run that had already happened. That is a report. What CaMeL
		// actually requires is that untrusted input cannot reach the decision
		// to act, which means the refusal has to happen before the action, at
		// the gate every operation already passes through.
		if ok, why := s.publishable(); !ok {
			return s.refuse(op, why)
		}
	}
	return nil
}

// Mutate authorises writing content, and is Retrieve's counterpart.
//
// # Why an agent's scope binds its writes and not only its reads
//
// A scope reads as "this agent works on articles". Enforcing that on reads
// alone leaves the half that changes the site: an agent scoped to articles
// that can write a page bound to the legal type has the scope on the wrong
// operation. So the same three questions are asked again here.
//
// # The one place this is deliberately stricter than Retrieve
//
// Retrieve treats an empty type as in scope, because a page with no type bound
// to it is not a page of some secret type, and refusing those would stop a
// scoped agent reading an untyped store — which is most of them.
//
// Writing inverts that. An agent that declared it works on articles, writing a
// page whose type nothing asserts, is not writing an article: it is writing
// something unverifiable and calling it in scope. The permissive reading would
// make "create a page nobody typed" the way around every type scope in every
// manifest. So a declared type scope plus an untyped target is refused, and an
// agent that declares no type scope is unrestricted exactly as before — which
// keeps the untyped store working for the installations that have one.
//
// Writing does not taint. Taint tracks untrusted content coming in; a write is
// content going out, and marking the session on the way out would make every
// writing agent permanently unpublishable for having done its job.
func (s *Session) Mutate(ref, page, typeName, locale string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Never the live ref, whatever the manifest says it reads. A write that
	// lands on what the public is being served has skipped every review this
	// program has, and no manifest field should be able to ask for that.
	if strings.EqualFold(ref, RefLive) {
		return s.refuse("write", fmt.Sprintf(
			"%s was asked to write to %s directly. Agents write drafts; what "+
				"is public changes when a person says so", s.manifest.Name, ref))
	}
	if types := s.manifest.Retrieval.Types; len(types) > 0 {
		if strings.TrimSpace(typeName) == "" {
			return s.refuse("write", fmt.Sprintf(
				"this agent is scoped to the %s type(s) and that page has no "+
					"type bound to it. An untyped page is readable within a "+
					"scope and not writable within one, because nothing "+
					"asserts it is the thing the scope names",
				strings.Join(types, ", ")))
		}
		if !allowed(types, typeName) {
			return s.refuse("write", fmt.Sprintf(
				"this agent is scoped to the %s type(s) and that is a %s",
				strings.Join(types, ", "), typeName))
		}
	}
	if sub := s.manifest.Retrieval.Path; sub != "" && !within(sub, page) {
		return s.refuse("write", fmt.Sprintf(
			"this agent works in %s and %s is not under it", sub, named(page)))
	}
	if !allowedLocale(s.manifest.Retrieval.Locales, locale) {
		return s.refuse("write", fmt.Sprintf(
			"this agent is scoped to %s and that is %s",
			strings.Join(s.manifest.Retrieval.Locales, ", "), locale))
	}
	return nil
}

// RefLive is the ref an agent may never write to.
//
// Named here rather than imported from internal/site, because this package
// decides and does not reach the store — and a constant is the whole of what
// it needs to know.
const RefLive = "live"

// Retrieve authorises reading content, and is separate from Authorize because
// the scope questions only apply to reads.
//
// ref is which ref is being read; typeName and locale describe the content.
// Empty values mean "not applicable", which is allowed — an untyped page is not
// a page of some secret type.
func (s *Session) Retrieve(ref, page, typeName, locale string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	want := s.manifest.Retrieval.Ref
	if want != "" && ref != "" && !strings.EqualFold(ref, want) {
		// The one that matters most: a bot answering from the draft is a
		// disclosure with a friendly interface.
		return s.refuse("retrieve", fmt.Sprintf(
			"this agent reads %s and something asked it for %s", want, ref))
	}
	if !allowed(s.manifest.Retrieval.Types, typeName) {
		return s.refuse("retrieve", fmt.Sprintf(
			"this agent is scoped to the %s type(s) and that is a %s",
			strings.Join(s.manifest.Retrieval.Types, ", "), typeName))
	}
	if !allowedLocale(s.manifest.Retrieval.Locales, locale) {
		return s.refuse("retrieve", fmt.Sprintf(
			"this agent is scoped to %s and that is %s",
			strings.Join(s.manifest.Retrieval.Locales, ", "), locale))
	}
	if sub := s.manifest.Retrieval.Path; sub != "" && !within(sub, page) {
		return s.refuse("retrieve", fmt.Sprintf(
			"this agent reads %s and %s is not under it", sub, named(page)))
	}

	// Everything read out of the store is untrusted from here on. It may have
	// been written by a form submission, an importer, or a previous agent.
	s.tainted = true
	s.note(FromPage, page, "")
	return nil
}

// RetrieveSet authorises reading the whole published set, to narrow it here.
//
// # Why this is not Retrieve with an empty page
//
// Because a scope check that treats a missing page as permissible is a scope
// check a forgetful caller walks through, and that is the exact failure this
// package keeps producing: a field left unset reading as "unrestricted".
// Retrieve refuses a page it cannot name when a subtree is declared, and that
// refusal caught a listing the first time it ran.
//
// A listing genuinely is a different question. It reads the set and then hides
// what the agent may not see — a page the agent could not read is a page it
// should not be told exists — so refusing the read outright would break the
// operation rather than bound it. Saying so in a separate method means the
// caller has to state that it is doing the narrowing, rather than getting
// through by passing nothing.
//
// Everything else Retrieve does still happens: the ref is checked and the
// session is tainted. What is skipped is the per-page half, and the caller
// that skips it takes on Session.Inside and the type and locale filters.
func (s *Session) RetrieveSet(ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	want := s.manifest.Retrieval.Ref
	if want != "" && ref != "" && !strings.EqualFold(ref, want) {
		return s.refuse("retrieve", fmt.Sprintf(
			"this agent reads %s and something asked it for %s", want, ref))
	}
	s.tainted = true
	// The ref rather than the pages. A listing is a read of everything that
	// matched, and which pages those were is the caller's business — saying
	// "a listing of draft" is true, and naming pages this did not check would
	// be a provenance record that is confidently wrong.
	s.note(FromSet, ref, "")
	return nil
}

// MayReach authorises one outbound call to one host.
//
// The host is compared against the manifest's allowlist. It is deliberately not
// derived from a URL the model produced: the point of declaring hosts in advance
// is that a successful injection reaches an allowlist rather than the internet.
//
// This is the allowlist half only. The address-level defence — refusing loopback,
// link-local and the cloud metadata endpoint, checked after DNS resolution and
// before the socket connects so that rebinding cannot bypass it — belongs to
// internal/fetch and is not reimplemented here. Two answers to the same question
// would be worse than one.
func (s *Session) MayReach(host string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return s.refuse("fetch", "no host was given")
	}
	if len(s.hosts) == 0 {
		return s.refuse("fetch", fmt.Sprintf(
			"this agent declares no tools, so it reaches nothing outside. "+
				"Something asked it to call %s", h))
	}
	if !s.hosts[h] {
		return s.refuse("fetch", fmt.Sprintf(
			"%s is not one of this agent's declared hosts (%s)",
			h, strings.Join(s.hostList(), ", ")))
	}
	if s.toolUses >= s.manifest.Budget.Tools {
		return s.refuse("fetch", fmt.Sprintf(
			"the tool budget of %d calls is spent", s.manifest.Budget.Tools))
	}
	s.toolUses++

	// A tool call taints the run, for the reason a store read does and more
	// so.
	//
	// Retrieve's comment says everything out of the store is untrusted from
	// there on, because it may have been written by a form submission, an
	// importer, or a previous agent. A tool result is worse: it is whatever a
	// third-party host chose to return, on this request, with no review by
	// anybody here at all.
	//
	// So an agent that called out and then published without a person would
	// be publishing content somebody else wrote, through a deputy holding
	// this store's credentials. That is the confused-deputy shape the taint
	// exists to stop, and nothing was stopping it: MayReach never set this,
	// and it did not matter only because no executor performed a tool call.
	// Wiring one makes it matter, so it is set here first.
	s.tainted = true
	return s.spend("fetch")
}

// noteTool records which tool reached which host, which MayReach cannot: it
// is given a host and never the name behind it.
func (s *Session) noteTool(tool, host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note(FromTool, tool, host)
}

func (s *Session) hostList() []string {
	out := make([]string, 0, len(s.hosts))
	for h := range s.hosts {
		out = append(out, h)
	}
	return out
}

// Publishable reports whether what this session produced may go live without a
// person, and says why when it may not.
//
// Called at the end of a run rather than at the start, because the answer
// depends on what happened: an agent that only read trusted input is a different
// proposition from one that read a page anybody could have written.
func (s *Session) Publishable() (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.publishable()
}

// publishable is Publishable for a caller already holding the lock.
func (s *Session) publishable() (bool, string) {
	if s.manifest.Autonomy != AutonomyPublish {
		return false, fmt.Sprintf(
			"%s has %s autonomy, so what it produced is a draft",
			s.manifest.Name, s.manifest.Autonomy)
	}
	if s.manifest.HumanApproval {
		return false, fmt.Sprintf(
			"%s requires a person to approve before anything it did becomes "+
				"public", s.manifest.Name)
	}
	if s.tainted {
		// The CaMeL-shaped rule, and the one worth stating plainly: this run
		// read content that somebody else may have written, so its output is
		// downstream of untrusted input. That is precisely the condition under
		// which "the agent decided to publish this" stops being evidence of
		// anything.
		why := fmt.Sprintf(
			"%s read stored content during this run, so what it produced is "+
				"downstream of input somebody else may have written. A person "+
				"decides whether that goes live", s.manifest.Name)
		// And what it read. The person this sentence is addressed to is being
		// asked to make a judgement, and the judgement is not answerable from
		// "it read something" — the honest review of that is to re-read the
		// site, which nobody does.
		if p := Provenance(s.sourcesLocked(), s.omitted); p != "" {
			why += ". It read: " + p
		}
		return false, why
	}
	return true, ""
}

// Tainted reports whether untrusted content has been read this run.
func (s *Session) Tainted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tainted
}

// Tokens records what a model reported using.
//
// Reported, not measured: this package has never seen a model and cannot count
// what one consumed. The host reads the figure off the provider's response and
// hands it over, which means the number is exactly as trustworthy as that
// provider — and a receipt built from it says "reported" rather than
// pretending to have weighed anything.
//
// A local model reports nothing and costs nothing, so zero is the ordinary
// answer for the deployment that runs its own. That is worth keeping
// distinguishable from a hosted run whose usage nobody wrote down, which is
// what Metered is for.
//
// Negative is ignored rather than refused. A provider returning nonsense should
// not end a run that is otherwise going fine, and the alternative — refusing —
// would make a billing field able to stop work.
func (s *Session) Tokens(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens += n
}

// Refusals returns what this session refused, for the audit record.
func (s *Session) Refusals() []Refusal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Refusal(nil), s.refusals...)
}

// Spent reports what the run used, for the record and for a person deciding
// whether the budget is set anywhere near right.
func (s *Session) Spent() (steps, tools int, elapsed time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.steps, s.toolUses, s.now().Sub(s.started)
}

// TokensUsed is what the host reported for this run.
func (s *Session) TokensUsed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens
}

// Manifest returns a copy of what this session is enforcing.
func (s *Session) Manifest() Manifest {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.manifest
	m.Capabilities = append([]string(nil), s.manifest.Capabilities...)
	m.Tools = append([]Tool(nil), s.manifest.Tools...)
	return m
}

// allowed reports whether a value passes an allow-list, where empty means
// unrestricted and an empty value is always allowed.
//
// The empty-value rule matters: a page with no type bound to it is not a page of
// some secret type, and refusing those would mean a scoped agent cannot read an
// untyped store at all — which is most of them.
func allowed(list []string, v string) bool {
	if len(list) == 0 || v == "" {
		return true
	}
	for _, item := range list {
		if strings.EqualFold(item, v) {
			return true
		}
	}
	return false
}

// allowedLocale is allowed() with prefix matching, so a scope naming "en"
// reaches "en-GB". A scope that breaks on the first regional variant is one
// people widen to everything.
func allowedLocale(list []string, v string) bool {
	if len(list) == 0 || v == "" {
		return true
	}
	for _, item := range list {
		if strings.EqualFold(item, v) ||
			strings.HasPrefix(strings.ToLower(v), strings.ToLower(item)+"-") {
			return true
		}
	}
	return false
}

// MayCallTool authorises one tool call, by name.
//
// # Why the host does not come from the action
//
// It used to. The loop read Input["host"] — a field a model fills in — and
// checked that string against the allow-list, while the thing actually dialled
// is whatever the integration behind the tool name points at. A check on one
// string and a connection to another is the bug every SSRF filter has had, and
// the comment above MayReach already said the host must not be derived from
// what the model produced.
//
// It is not enough that the model can only name hosts on the list. The list is
// per agent; the mapping from a tool name to a host is per tool, declared by
// somebody who needed `grant` to write it. Resolving from the name means the
// model chooses which declared tool to call and nothing else — which is the
// Action-Selector pattern, and the only part of this a model is entitled to
// decide.
//
// # Why a disagreement is refused rather than ignored
//
// Because there is no legitimate reason for a model to name a host other than
// the one its tool declares, and ignoring the field would accept something
// that looks exactly like an injected page redirecting a tool call. Refusing
// is also what the previous behaviour did for an undeclared host, so the
// signal an operator was already getting does not quietly disappear.
//
// asked may be empty, which is the ordinary case: a model that names the tool
// and leaves the host alone is behaving correctly.
func (s *Session) MayCallTool(tool, asked string) error {
	declared := s.HostFor(tool)
	if asked != "" && !strings.EqualFold(
		strings.TrimSpace(asked), strings.TrimSpace(declared)) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if declared == "" {
			return s.refuse("fetch", fmt.Sprintf(
				"%q is not one of this agent's declared tools, and nothing "+
					"asked for %s may be reached on its word", tool, asked))
		}
		return s.refuse("fetch", fmt.Sprintf(
			"the tool %q reaches %s, and something asked it to reach %s "+
				"instead; a host is declared in the manifest and never "+
				"taken from a request", tool, declared, asked))
	}
	if err := s.MayReach(declared); err != nil {
		return err
	}
	// Recorded after it is permitted, and with the name: MayReach is handed a
	// host and never the tool behind it, so "reached api.example.com" would be
	// a provenance line nobody can act on without the manifest open beside it.
	s.noteTool(tool, declared)
	return nil
}

// HostFor is the host a named tool is declared to reach.
//
// An unknown tool name resolves to the empty string, which MayReach refuses
// with "no host was given". That is the right answer and the right message: a
// tool this agent does not declare has no host, rather than a host that
// happens not to be permitted. See MayCallTool for why this is resolved from
// the name at all.
func (s *Session) HostFor(tool string) string {
	name := strings.ToLower(strings.TrimSpace(tool))
	if name == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.manifest.Tools {
		if strings.ToLower(strings.TrimSpace(t.Name)) == name {
			return t.Host
		}
	}
	return ""
}

// ToolFor is the whole declaration behind a tool name.
//
// Returned by value, so a caller cannot reach into the session's copy of the
// manifest and change what it declares. The second return is false for a tool
// this agent does not hold, which a caller must treat as a refusal rather than
// as an empty declaration — a Tool zero value has no host and no secret, and
// calling with it would be calling nothing with nothing.
func (s *Session) ToolFor(tool string) (Tool, bool) {
	name := strings.ToLower(strings.TrimSpace(tool))
	if name == "" {
		return Tool{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.manifest.Tools {
		if strings.ToLower(strings.TrimSpace(t.Name)) == name {
			return t, true
		}
	}
	return Tool{}, false
}

// within reports whether a page is inside a declared subtree.
//
// # The field this is for, and why it did nothing
//
// Manifest.Retrieval.Path is documented as "limits it to a subtree", and it
// was the third field of a struct whose other two were already found to be
// decoration: the executor was built with no type or locale resolver, so the
// scope was never asked. That was fixed for Types and Locales and Path was
// left out of the repair — it appeared in exactly one place in the whole
// program, inside Narrow, where it was carefully intersected and then never
// consulted by anything.
//
// # Segments, not a string prefix
//
// A prefix test says "helpdesk" is inside "help", which is a scope that leaks
// to whoever names the next page. The comparison is on path segments, so
// "help" contains "help" and "help/billing" and not "helpdesk".
//
// An empty declaration permits everything, which is what an unset field means
// everywhere else in this struct. The sentinel Narrow produces for two
// subtrees that do not overlap permits nothing, because that is what it means.
func within(declared, page string) bool {
	d := strings.Trim(strings.TrimSpace(declared), "/")
	if d == "" {
		return true
	}
	if declared == pathNothing {
		// Two restrictions that had no page in common. Narrow says so with a
		// sentinel rather than picking one of them.
		return false
	}
	p := strings.Trim(strings.TrimSpace(page), "/")
	if p == "" {
		// A scope was declared and there is no page to judge. Refusing is the
		// safe direction: a caller that cannot say what it is reading has not
		// demonstrated it is inside the subtree.
		return false
	}
	if strings.EqualFold(p, d) {
		return true
	}
	return strings.HasPrefix(strings.ToLower(p), strings.ToLower(d)+"/")
}

// named describes a page in a refusal, without inventing one.
//
// A caller that passed no page gets "a page with no name" rather than an empty
// pair of quotes, because the refusal is read by somebody working out why
// their agent stopped.
func named(page string) string {
	if strings.TrimSpace(page) == "" {
		return "a page with no name"
	}
	return strconv.Quote(page)
}

// Inside reports whether a page is within this agent's declared subtree,
// without spending anything or recording a refusal.
//
// The quiet half of the path check, for a listing. Retrieve refuses and
// records; a listing has to narrow instead, because a page the agent could not
// read is a page it should not be told exists — the same reasoning that
// already hides pages of another type.
func (s *Session) Inside(page string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return within(s.manifest.Retrieval.Path, page)
}

// Handing work to another agent, and the two ways that becomes a hole.
//
// A supervisor exists because a pipeline has stages that genuinely differ, and
// the graph is named in the manifest rather than chosen at run time so that a
// compromised supervisor cannot invent a worker. That is the governance claim
// this program publishes on its agent card, under the heading the research
// calls delegation with accountability.
//
// It was a claim about a field nothing read. Manifest.Delegates was validated,
// copied out of an archetype and published to other systems, and no code path
// anywhere handed work to anything. A supervisor agent's whole reason for
// existing did nothing at all.
//
// Two holes have to stay shut, and they are the reason this is a gate rather
// than a lookup:
//
//   - Capability laundering. A delegate holding more than its parent means
//     the restriction on the parent was decoration: delegate, and the work
//     happens with the wider set. Narrow answers that, and this refuses to
//     delegate at all unless the caller has used it.
//   - Taint laundering, which is the subtler one. If a tainted child's result
//     came back to a clean parent, an agent could read untrusted content
//     through a delegate and publish it — the taint rule defeated by an
//     indirection the rule never looked at. So a child's taint is the
//     parent's, and Fold is how a caller says so.

// MayDelegate reports whether this agent may hand work to a named one.
//
// The name is matched against the manifest exactly the way a tool's host is:
// what a model said is a request, and what the manifest says is the answer.
// A delegate that is not on the list ends the run naming the list, because a
// supervisor choosing a worker at run time is the thing the design refuses.
func (s *Session) MayDelegate(name string) error {
	want := strings.TrimSpace(name)
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.manifest.Kind != KindSupervisor {
		return s.refuse("delegate", fmt.Sprintf(
			"this agent is a %s and only a supervisor delegates. Handing work "+
				"onward from anything else would mean any agent could reach "+
				"any other agent's capabilities", s.manifest.Kind))
	}
	if want == "" {
		return s.refuse("delegate", "no agent was named")
	}
	for _, d := range s.manifest.Delegates {
		if d == want {
			// Spent as a step of the parent's budget as well as the child's
			// own. A supervisor that could delegate without spending would
			// have an unbounded budget with extra steps, which is the ceiling
			// removed rather than moved.
			return s.spend("delegate")
		}
	}
	return s.refuse("delegate", fmt.Sprintf(
		"%q is not one of this agent's delegates. It may hand work to %s, and "+
			"the list is in the manifest so that the graph is reviewable and a "+
			"supervisor that has been talked into something cannot invent a "+
			"worker", want, delegateList(s.manifest.Delegates)))
}

// Delegates is the list this agent may hand work to.
func (s *Session) Delegates() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.manifest.Delegates...)
}

// Fold brings a finished delegate's run back into this one.
//
// Everything the child spent is spent here too. A supervisor whose children's
// costs did not land on its own budget would be a way to spend any amount by
// spreading it, and the budget is the control that stops a goal-seeking agent
// in a loop.
//
// The taint is the part that has to be right. A child that read stored content
// produced output downstream of something somebody else may have written, and
// that does not stop being true because it crossed a function boundary on the
// way back. Refusals come back as well, because "the agent was refused four
// times" is what an operator reads afterwards and a refusal that happened
// inside a delegate is still a refusal this run caused.
func (s *Session) Fold(child *Session) {
	if child == nil || child == s {
		return
	}
	steps, tools, _ := child.Spent()
	tokens := child.TokensUsed()
	tainted := child.Tainted()
	refusals := child.Refusals()

	sources := child.Sources()
	reads := child.Reads()
	name := child.Manifest().Name

	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps += steps
	s.toolUses += tools
	s.tokens += tokens
	if tainted {
		s.tainted = true
	}
	s.refusals = append(s.refusals, refusals...)
	// The child's provenance, not only its taint. A supervisor whose receipt
	// said "tainted" without saying what the delegate read would hand a
	// reviewer strictly less than the delegate's own receipt already has, so
	// the indirection would cost the person the very thing the taint is for.
	if reads > 0 {
		s.note(FromDelegate, name, "")
	}
	for _, src := range sources {
		s.note(src.Kind, src.Name, src.Where)
	}
	s.reads += reads
	// And the ones the child could not name, which stay unnamed here.
	s.omitted += child.Omitted()
}

func delegateList(names []string) string {
	if len(names) == 0 {
		return "nothing — its delegate list is empty"
	}
	return strings.Join(names, ", ")
}

// Remaining is what is left of this session's budget.
//
// A delegate is given the smaller of its own budget and what its parent still
// has, rather than the smaller of the two totals. Narrow compares the totals,
// which is right for a manifest — a child may not be declared wider than its
// parent — and wrong for a run: a supervisor with ten steps and three
// delegates declaring ten each would hand out thirty. Fold catches that
// afterwards, and afterwards is one delegate too late.
func (s *Session) Remaining() Budget {
	s.mu.Lock()
	defer s.mu.Unlock()
	steps := s.manifest.Budget.Steps - s.steps
	tools := s.manifest.Budget.Tools - s.toolUses
	left := time.Duration(s.manifest.Budget.Duration) - s.now().Sub(s.started)
	if steps < 0 {
		steps = 0
	}
	if tools < 0 {
		tools = 0
	}
	if left < 0 {
		left = 0
	}
	return Budget{Steps: steps, Tools: tools, Duration: Duration(left)}
}
