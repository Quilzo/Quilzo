// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package main

import (
	"testing"
	"time"

	"github.com/quilzo/quilzo/internal/personalise"
)

func TestARuleFromTheCommandLineAppliesToTheVisitorItDescribes(t *testing.T) {
	root := publishedShop(t)
	if err := cmdPersonalise(root, []string{"add", "de", "--page", "returns", "--variant", "delivery",
		"--when", "language=de", "--when", "device=phone"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdPersonalise(root, []string{"enable", "de"}); err != nil {
		t.Fatal(err)
	}
	set, err := personalise.Load(personalisePath(root))
	if err != nil {
		t.Fatal(err)
	}
	req, when, _ := simulated("", "", "de-AT", "phone", "")
	if r, ok := set.For("returns", req, when); !ok || r.Name != "de" {
		t.Fatal("a German phone visitor did not get the rule")
	}
	req, _, _ = simulated("", "", "de-AT", "desktop", "")
	if _, ok := set.For("returns", req, time.Now()); ok {
		t.Fatal("a desktop visitor got a phone rule")
	}
	if err := cmdPersonalise(root, []string{"test", "returns", "--language", "de", "--device", "phone"}); err != nil {
		t.Fatal(err)
	}
}
