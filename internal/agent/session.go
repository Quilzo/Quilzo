package agent

import (
	"fmt"
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
func (s *Session) Mutate(ref, typeName, locale string) error {
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
func (s *Session) Retrieve(ref, typeName, locale string) error {
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

	// Everything read out of the store is untrusted from here on. It may have
	// been written by a form submission, an importer, or a previous agent.
	s.tainted = true
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
	return s.spend("fetch")
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
		return false, fmt.Sprintf(
			"%s read stored content during this run, so what it produced is "+
				"downstream of input somebody else may have written. A person "+
				"decides whether that goes live", s.manifest.Name)
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
