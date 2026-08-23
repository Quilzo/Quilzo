package main

import (
	"reflect"
	"testing"
)

// A negative length is a value, not a flag.
//
// tracking-display is documented as "negative tightens", and every useful value
// for it starts with a minus. Splitting arguments at the first dash sent that
// value to the flag package, which refused it: the one token that wants a
// negative number was the one token that could not be set.
func TestANegativeValueIsNotMistakenForAFlag(t *testing.T) {
	cases := []struct {
		args, pos, flags []string
	}{
		{
			args:  []string{"tracking-display", "-0.02em"},
			pos:   []string{"tracking-display", "-0.02em"},
			flags: nil,
		},
		{
			args:  []string{"tracking-display", "-0.02em", "--dir", "templates"},
			pos:   []string{"tracking-display", "-0.02em"},
			flags: []string{"--dir", "templates"},
		},
		{
			args:  []string{"radius", "10px", "-force"},
			pos:   []string{"radius", "10px"},
			flags: []string{"-force"},
		},
	}
	for _, c := range cases {
		pos, flags := splitThemeArgs(c.args)
		if !reflect.DeepEqual(pos, c.pos) || !reflect.DeepEqual(flags, c.flags) {
			t.Errorf("splitThemeArgs(%q)\n got pos %q flags %q\nwant pos %q flags %q",
				c.args, pos, flags, c.pos, c.flags)
		}
	}
}
