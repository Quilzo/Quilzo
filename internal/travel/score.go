// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package travel

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The score: how unlike its person a sign-in is, in bits.
//
// LinkedIn's model (Freeman, Jain, Dürmuth, Biggio and Giacinto, "Who Are
// You? A Statistical Approach to Measuring User Authenticity", NDSS 2016),
// as the risk-based authentication studies that followed implement it:
//
//	S = Π_k p(x_k) / p(x_k | u)  ×  p(u | attack) / p(u | legitimate)
//
// p(x_k) is how often the value of feature k is seen across everybody's
// sign-ins, p(x_k | u) how often in this person's own; a value common for
// everybody and rare for them is surprising, and one they use all the time
// is not. p(u | attack) is taken as even across people, and p(u |
// legitimate) is their share of all sign-ins. The features are the
// address, its network (ASN), the country and the kind of device — the
// address and the device being the pair the studies found gives most
// security for least friction.
//
// A person's probability is smoothed towards everybody's, so a value they
// have never used is unusual rather than infinitely so. The score is the
// base-2 logarithm of S: every extra bit is twice as unlikely to be them.

// Stats are how often each value has been seen across everybody.
type Stats struct {
	Total, People int
	Counts        map[string]map[string]int // feature -> value -> count
	at            time.Time
}

func featureValues(in SignIn) map[string]string {
	asn := ""
	if in.ASN != 0 {
		asn = fmt.Sprint(in.ASN)
	}
	return map[string]string{"ip": in.IP, "asn": asn, "country": in.Place.Country, "device": in.Device}
}

func (g *Stats) add(in SignIn) {
	g.Total++
	for k, v := range featureValues(in) {
		if v == "" {
			continue
		}
		if g.Counts[k] == nil {
			g.Counts[k] = map[string]int{}
		}
		g.Counts[k][v]++
	}
}

// Score is the model's surprise at a sign-in, in bits; zero with no
// history to compare.
func Score(before []SignIn, cur SignIn, g Stats) float64 {
	if len(before) == 0 || g.Total == 0 {
		return 0
	}
	const alpha = 1.0
	logS := 0.0
	mine := map[string]map[string]int{}
	for _, in := range before {
		for k, v := range featureValues(in) {
			if v == "" {
				continue
			}
			if mine[k] == nil {
				mine[k] = map[string]int{}
			}
			mine[k][v]++
		}
	}
	n := float64(len(before))
	for k, v := range featureValues(cur) {
		if v == "" {
			continue
		}
		distinct := float64(len(g.Counts[k]) + 1)
		pGlobal := (float64(g.Counts[k][v]) + 1) / (float64(g.Total) + distinct)
		pMine := (float64(mine[k][v]) + alpha*pGlobal) / (n + alpha)
		logS += math.Log2(pGlobal / pMine)
	}
	people := float64(max(g.People, 1))
	pAttack := 1 / people
	pLegit := (n + 1) / (float64(g.Total) + people)
	logS += math.Log2(pAttack / pLegit)
	return math.Round(logS*10) / 10
}

// statsTTL is how long everybody's frequencies are reused before they are
// counted again: a sign-in must not read every person's history.
const statsTTL = 10 * time.Minute

// stats counts everybody's kept sign-ins, cached. Called with s.mu held.
func (s *Store) stats() Stats {
	if s.cache.Total > 0 && s.now().Sub(s.cache.at) < statsTTL {
		return s.cache
	}
	g := Stats{Counts: map[string]map[string]int{}, at: s.now()}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return g
	}
	for _, en := range entries {
		if en.IsDir() || !strings.HasSuffix(en.Name(), ".json") {
			continue
		}
		f, err := s.read(filepath.Join(s.Dir, en.Name()))
		if err != nil {
			continue
		}
		list := s.kept(f.SignIns)
		if len(list) > 0 {
			g.People++
		}
		for _, in := range list {
			g.add(in)
		}
	}
	s.cache = g
	return g
}
