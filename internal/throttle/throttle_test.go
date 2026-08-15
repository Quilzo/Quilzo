package throttle

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

var start = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

func at(l *Limiter, t *time.Time) *Limiter {
	return l.WithClock(func() time.Time { return *t })
}

// -- the shape of the delay ---------------------------------------------------

// The first few failures are free, because people mistype and a control that
// punishes a typo is a control people route around.
func TestTheFirstFewFailuresAreNotDelayed(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	s := Subject{Principal: "dana"}

	for i := 0; i < 5; i++ {
		d, _ := l.Fail(s)
		if !d.Allowed {
			t.Fatalf("failure %d was already being delayed", i+1)
		}
	}
	if d := l.Check(s); !d.Allowed {
		t.Error("the fifth failure started a delay; the default is five free")
	}
}

// And then it doubles.
func TestTheDelayDoubles(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	s := Subject{Principal: "dana"}
	for i := 0; i < 5; i++ {
		l.Fail(s)
	}

	var seen []time.Duration
	for i := 0; i < 4; i++ {
		d, _ := l.Fail(s)
		if d.Allowed {
			t.Fatalf("failure %d was not delayed at all", 6+i)
		}
		seen = append(seen, d.RetryAfter)
		now = now.Add(d.RetryAfter) // wait it out, then fail again
	}

	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second,
		8 * time.Second}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("delay %d was %s, want %s", i+1, seen[i], want[i])
		}
	}
}

// The doubling stops, so a long attack does not produce a delay measured in
// centuries — and, more to the point, so the wait imposed on whoever is
// failing stays bounded.
func TestTheDelayIsCapped(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	s := Subject{Principal: "dana"}
	for i := 0; i < 40; i++ {
		d, _ := l.Fail(s)
		now = now.Add(d.RetryAfter)
	}
	d := l.Check(s)
	if d.RetryAfter > Default().Max {
		t.Errorf("the delay reached %s, above the %s cap", d.RetryAfter,
			Default().Max)
	}
}

// Waiting is what clears it. An attempt inside the window is refused; the same
// attempt after it is allowed through to be judged on the credential.
func TestWaitingOutTheDelayWorks(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	s := Subject{Principal: "dana"}
	for i := 0; i < 6; i++ {
		l.Fail(s)
	}
	d := l.Check(s)
	if d.Allowed {
		t.Fatal("no delay after six failures")
	}
	now = now.Add(d.RetryAfter - time.Millisecond)
	if l.Check(s).Allowed {
		t.Error("allowed a millisecond early")
	}
	now = now.Add(2 * time.Millisecond)
	if !l.Check(s).Allowed {
		t.Error("still refused after the delay elapsed")
	}
}

// -- the ceiling --------------------------------------------------------------

// ASVS 5.0 puts it at 100 failures per hour on one account.
func TestTheCeilingStopsEverything(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	// Not waiting out each delay, because waiting is how you avoid the
	// ceiling: the delays cap at fifteen minutes, so a caller who serves every
	// one of them cannot fit a hundred failures into an hour at all. Reaching
	// the ceiling means failing a hundred times inside the window, which is
	// what an attacker ignoring the Retry-After does.
	s := Subject{Principal: "dana"}
	for i := 0; i < 100; i++ {
		l.Fail(s)
	}
	d := l.Check(s)
	if d.Allowed {
		t.Fatal("attempts continued past the 100-per-hour ceiling")
	}
	if !d.Locked {
		t.Error("past the ceiling should report as locked, not as a delay")
	}
}

// -- what makes this a soft lockout ------------------------------------------

// The property ASVS 5.0 asks to be documented, stated as a test.
//
// A hard lockout is a denial of service anybody can aim at anybody else: you
// need the principal's name, not their credential, and names are not secret.
// The default must not let an attacker keep a real user out — after the delay
// elapses, the real user gets in.
func TestAnAttackerCannotLockSomebodyElseOut(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	victim := Subject{Principal: "dana"}

	// The attacker fails against dana as hard as they can for an hour.
	for i := 0; i < 99; i++ {
		d, _ := l.Fail(victim)
		now = now.Add(d.RetryAfter)
	}

	// Dana comes back the next day and must be able to authenticate.
	now = now.Add(25 * time.Hour)
	if d := l.Check(victim); !d.Allowed {
		t.Fatalf("dana is still locked out a day later: %s", d.Why)
	}

	// And within the window, the wait is bounded by the cap rather than open
	// ended, so even mid-attack the real user gets in by waiting minutes.
	if d := l.Check(victim); d.RetryAfter > Default().Max {
		t.Errorf("the victim would wait %s, which is longer than the cap",
			d.RetryAfter)
	}
}

// Hard lockout is available because compliance regimes name it, and it behaves
// as named: the window restarts on every attempt, so a subject under continuous
// attack stays locked. That is the DoS this is off by default to avoid, and the
// test says so out loud rather than leaving it implied.
func TestHardLockoutIsAvailableAndIsTheDenialOfServiceItSoundsLike(t *testing.T) {
	p := Default()
	p.Hard = true
	p.Ceiling = 10
	now := start
	l := at(New(p), &now)
	victim := Subject{Principal: "dana"}

	for i := 0; i < 10; i++ {
		l.Fail(victim)
		now = now.Add(time.Minute)
	}
	if l.Check(victim).Allowed {
		t.Fatal("hard lockout did not lock")
	}
	// The attacker keeps failing once an hour; the victim never gets back in.
	for i := 0; i < 5; i++ {
		now = now.Add(59 * time.Minute)
		l.Fail(victim)
	}
	if l.Check(victim).Allowed {
		t.Error("hard lockout released while the attack continued, which " +
			"means it is not doing what the setting claims")
	}
	// Which is exactly why the default is off.
	if Default().Hard {
		t.Error("hard lockout is the default; it is a denial of service " +
			"anybody can aim at anybody else")
	}
}

// -- not an oracle ------------------------------------------------------------

// Failing against a principal that does not exist must look exactly like
// failing against one that does. Otherwise the throttle answers the question
// "is dana a real account?", which is the question it was supposed to make
// expensive.
func TestThrottlingDoesNotRevealWhetherAPrincipalExists(t *testing.T) {
	now := start
	l := at(New(Default()), &now)

	real := Subject{Principal: "dana"}
	fake := Subject{Principal: "not-a-real-account-at-all"}

	var realD, fakeD Decision
	for i := 0; i < 8; i++ {
		realD, _ = l.Fail(real)
		fakeD, _ = l.Fail(fake)
	}
	if realD.Allowed != fakeD.Allowed || realD.RetryAfter != fakeD.RetryAfter {
		t.Errorf("a real principal is throttled differently from an invented "+
			"one: %v vs %v", realD, fakeD)
	}
}

// -- both dimensions ----------------------------------------------------------

// One attacker working through many principals from one address is caught by
// the source counter, which the principal counter alone would miss entirely.
func TestManyPrincipalsFromOneSourceAreCaught(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	for i := 0; i < 20; i++ {
		l.Fail(Subject{Principal: fmt.Sprintf("user%d", i), Source: "10.0.0.9"})
	}
	d := l.Check(Subject{Principal: "user999", Source: "10.0.0.9"})
	if d.Allowed {
		t.Error("twenty principals tried from one address and the next " +
			"attempt from that address was not slowed at all")
	}
}

// And one principal attacked from many addresses is caught by the principal
// counter, which the source counter alone would miss.
func TestOnePrincipalFromManySourcesIsCaught(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	for i := 0; i < 20; i++ {
		l.Fail(Subject{Principal: "dana", Source: fmt.Sprintf("10.0.0.%d", i)})
	}
	if l.Check(Subject{Principal: "dana", Source: "203.0.113.7"}).Allowed {
		t.Error("dana was attacked from twenty addresses and an attempt from " +
			"a twenty-first was not slowed")
	}
}

// -- decay and success --------------------------------------------------------

// Success clears the principal's record. Somebody who mistyped four times and
// then got it right is not still being delayed tomorrow.
func TestSuccessClearsTheRecord(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	s := Subject{Principal: "dana"}
	for i := 0; i < 7; i++ {
		l.Fail(s)
	}
	l.Succeed(s)
	if d := l.Check(s); !d.Allowed {
		t.Errorf("still throttled after a successful authentication: %s", d.Why)
	}
	if n := l.Failures(s); n != 0 {
		t.Errorf("%d failures still on record after success", n)
	}
}

// Failures decay, so a handful of typos spread over a month never accumulate
// into a lockout.
func TestFailuresDecayWithTime(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	s := Subject{Principal: "dana"}
	for i := 0; i < 4; i++ {
		l.Fail(s)
		now = now.Add(2 * time.Hour) // each one outside the previous window
	}
	if n := l.Failures(s); n > 1 {
		t.Errorf("%d failures accumulated across four separate hours", n)
	}
}

// -- alerting -----------------------------------------------------------------

// ASVS 5.0 asks for a reaction above five failures in an hour.
func TestCrossingTheAlertThresholdIsReportedOnce(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	s := Subject{Principal: "dana"}

	alerts := 0
	for i := 0; i < 20; i++ {
		d, alert := l.Fail(s)
		if alert {
			alerts++
		}
		now = now.Add(d.RetryAfter)
	}
	if alerts == 0 {
		t.Fatal("twenty failures in an hour raised no alert")
	}
	if alerts > 1 {
		t.Errorf("one attack produced %d alerts; the threshold crossing is "+
			"the event and the attempts after it are the same event", alerts)
	}
}

// -- it must not become the denial of service ---------------------------------

// The delay is reported, never slept. A throttle that sleeps inside a request
// handler lets an attacker exhaust the server's workers by failing
// authentication in parallel — the control becomes the outage.
func TestCheckingIsImmediate(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	s := Subject{Principal: "dana"}
	for i := 0; i < 30; i++ {
		l.Fail(s)
	}
	began := time.Now()
	for i := 0; i < 1000; i++ {
		l.Check(s)
	}
	if elapsed := time.Since(began); elapsed > time.Second {
		t.Errorf("a thousand throttled checks took %s; this must not sleep",
			elapsed)
	}
}

// The map is bounded by the number of subjects failing inside one window,
// rather than growing for the life of the process.
func TestTheStateDoesNotGrowWithoutBound(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	for i := 0; i < 5000; i++ {
		l.Fail(Subject{Principal: fmt.Sprintf("user%d", i)})
		now = now.Add(time.Second)
	}
	// Two hours of one-per-second failures; the window is an hour, so roughly
	// half should have been swept.
	if n := l.Tracked(); n > 4000 {
		t.Errorf("%d subjects tracked after 5000 spread over 83 minutes; "+
			"expired records are not being dropped", n)
	}
}

// It is used from HTTP handlers, so it has to survive being used from several
// at once.
func TestConcurrentUseIsSafe(t *testing.T) {
	l := New(Default())
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := Subject{Principal: fmt.Sprintf("u%d", i%7), Source: "10.0.0.1"}
			for j := 0; j < 50; j++ {
				l.Fail(s)
				l.Check(s)
				if j%10 == 0 {
					l.Succeed(s)
				}
			}
		}(i)
	}
	wg.Wait()
}

// -- switched off -------------------------------------------------------------

// Off means off, and it has to actually mean it: a customer who turns this off
// has accepted a risk, and half-applying their setting would be worse than
// either answer.
func TestTurningItOffAllowsEverything(t *testing.T) {
	p := Default()
	p.On = false
	l := New(p)
	s := Subject{Principal: "dana"}
	for i := 0; i < 500; i++ {
		if d, _ := l.Fail(s); !d.Allowed {
			t.Fatalf("attempt %d was refused with throttling off", i)
		}
	}
}

// -- what success does not clear ---------------------------------------------

// A success must not clear the source's failures, and a live run is what
// showed why. An address is shared — a NAT, an office, a CI runner — so
// clearing it would let an attacker's budget be refilled every time somebody
// behind the same address signed in successfully.
func TestASuccessDoesNotClearTheAddressItCameFrom(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	src := "203.0.113.7"

	// An attacker guesses from that address.
	for i := 0; i < 8; i++ {
		l.Fail(Subject{Source: src})
	}
	if l.Check(Subject{Source: src}).Allowed {
		t.Fatal("eight failures from one address and it is not being slowed")
	}

	// A colleague behind the same address signs in successfully.
	l.Succeed(Subject{Principal: "dana"})

	if l.Check(Subject{Source: src}).Allowed {
		t.Error("a successful sign-in by somebody else refilled the " +
			"attacker's budget for that address")
	}
}

// And the legitimate holder still gets in while that address is throttled,
// which is the property the servers rely on: they authenticate a throttled
// request anyway and let a valid credential through. Checked here as the
// throttle's own contract — the principal's bucket is what governs them.
func TestAPrincipalWithNoFailuresIsNotThrottledByTheirNeighbours(t *testing.T) {
	now := start
	l := at(New(Default()), &now)
	src := "203.0.113.7"
	for i := 0; i < 20; i++ {
		l.Fail(Subject{Source: src})
	}
	if !l.Check(Subject{Principal: "dana"}).Allowed {
		t.Error("dana, who has failed nothing, is throttled because somebody " +
			"else shares her address")
	}
}
