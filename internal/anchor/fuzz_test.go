package anchor

import "testing"

// A binary format parsed from bytes a calendar server sent. The walk is
// recursive, length-prefixed and attacker-influenced, which is the combination
// that produces stack exhaustion, unbounded allocation and infinite loops.
func FuzzWalk(f *testing.F) {
	f.Add(make([]byte, 32), []byte{})
	var x build
	x.op(opAppend).arg([]byte("xy")).op(opSHA256).bitcoin(800000)
	f.Add(make([]byte, 32), x.b)
	var y build
	y.op(opFork).op(opSHA256).pending("https://a.example")
	f.Add(make([]byte, 32), y.b)
	f.Add(make([]byte, 32), []byte{0xff, 0xff, 0xff, 0xff})
	f.Add(make([]byte, 32), []byte{0xf0, 0xff, 0xff, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, digest, proof []byte) {
		// Must not panic, must terminate, must not allocate without bound.
		_, _ = Walk(digest, proof)
	})
}
