package collab_test

import (
	"strings"
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/collab"
)

func at() time.Time { return time.Unix(1787000100, 0) }

// kinds is a principal-to-kind lookup for these tests.
func kinds(m map[string]string) func(string) string {
	return func(who string) string {
		if k, ok := m[who]; ok {
			return k
		}
		return "human"
	}
}

func proposal(author string, approvers ...string) collab.Proposal {
	p := collab.Proposal{
		Content: "abc123", Author: author, AuthorKind: "human",
		CreatedAt: 1787000000,
	}
	for _, a := range approvers {
		p.Approvals = append(p.Approvals,
			collab.Approval{By: a, Content: "abc123"})
	}
	return p
}

// The hole two-person integrity is meant to close, and that Required alone
// leaves open.
//
// Required counts distinct approvers and does not ask what they are, so a
// policy of two is satisfied by two service accounts. A nightly import
// approved by the importer and the deploy account meets "two approvals" and
// has been seen by nobody.
func TestTwoServiceAccountsDoNotSatisfyTwoPersonIntegrity(t *testing.T) {
	who := kinds(map[string]string{
		"importer": "service", "deployer": "service", "alice": "human",
	})

	// The old policy is satisfied. This is the demonstration, not a bug.
	plain := collab.Policy{Required: 2}
	if d := plain.Evaluate(proposal("cron", "importer", "deployer"), who, at()); !d.Allowed {
		t.Fatalf("two approvals did not satisfy a policy of two: %s", d.Reason)
	}

	// The named policy is not.
	tpi := collab.TwoPersonIntegrity()
	d := tpi.Evaluate(proposal("cron", "importer", "deployer"), who, at())
	if d.Allowed {
		t.Fatal("two service accounts satisfied two-person integrity, so a " +
			"change nobody has read can publish")
	}
	// The refusal has to say a person is needed, not that another approval
	// is: another approval is what they would try, and it would not help.
	if !strings.Contains(d.Reason, "from people") {
		t.Errorf("the refusal does not say what is missing: %s", d.Reason)
	}
}

// And it is satisfied by two people.
func TestTwoPeopleSatisfyIt(t *testing.T) {
	who := kinds(map[string]string{"deployer": "service"})
	tpi := collab.TwoPersonIntegrity()

	d := tpi.Evaluate(proposal("cron", "alice", "bob"), who, at())
	if !d.Allowed {
		t.Fatalf("two people did not satisfy two-person integrity: %s", d.Reason)
	}
}

// A machine may still take part; it just cannot be one of the two.
//
// Worth allowing: a deploy account approving alongside two people is a record
// that the pipeline agreed, and refusing it would push somebody to run the
// pipeline outside the record.
func TestAMachineMayApproveAlongsidePeople(t *testing.T) {
	who := kinds(map[string]string{"deployer": "service"})
	tpi := collab.TwoPersonIntegrity()

	d := tpi.Evaluate(proposal("cron", "alice", "bob", "deployer"), who, at())
	if !d.Allowed {
		t.Fatalf("a machine approving alongside two people blocked the "+
			"publication: %s", d.Reason)
	}
}

// The author still cannot be one of the two, which is the older rule and has
// to keep applying: an author who approves their own work is one pair of eyes.
func TestTheAuthorIsStillNotOneOfTheTwo(t *testing.T) {
	tpi := collab.TwoPersonIntegrity()
	d := tpi.Evaluate(proposal("alice", "alice", "bob"), kinds(nil), at())
	if d.Allowed {
		t.Fatal("the author counted towards two-person integrity")
	}
}

// Zero leaves everything as it was, so this is not a change to any existing
// deployment.
func TestZeroChangesNothing(t *testing.T) {
	who := kinds(map[string]string{"importer": "service", "deployer": "service"})
	plain := collab.Policy{Required: 2, RequiredHumans: 0}
	if d := plain.Evaluate(proposal("cron", "importer", "deployer"), who, at()); !d.Allowed {
		t.Fatalf("a policy with no human requirement refused: %s", d.Reason)
	}
}

// The named constructor is the whole point: assembling it by hand is where it
// goes wrong, because Required: 2 reads like two-person integrity.
func TestTheNamedPolicyRequiresBoth(t *testing.T) {
	p := collab.TwoPersonIntegrity()
	if p.Required < 2 || p.RequiredHumans < 2 {
		t.Errorf("TwoPersonIntegrity is %+v, which is not two people", p)
	}
	if !p.RequireHumanForAI {
		t.Error("two-person integrity does not require a human on model work")
	}
}
