// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Quilzo-Commercial

package public

import (
	"net/http"
	"time"

	"github.com/quilzo/quilzo/internal/experiment"
	"github.com/quilzo/quilzo/internal/personalise"
)

// A/B tests, served. See internal/experiment for the design and its limits.

// variantFor returns the page to serve at name for this visitor when an
// experiment is running on it: the variant's name and body. Recording that
// the visitor was shown it happens here too, once a day per visitor. A
// variant whose page is not published falls back to the control and records
// nothing, so a missing page cannot pass as a variant nobody converts on.
func (st *Site) variantFor(r *http.Request, name string, pages map[string]any) (string, any, bool) {
	if st.Experiments == nil || st.Analytics == nil {
		return "", nil, false
	}
	set, err := st.Experiments()
	if err != nil {
		return "", nil, false
	}
	e, running := set.RunningOn(name)
	if !running {
		return "", nil, false
	}
	v := e.Variants[st.Analytics.Bucket(r, e.Name, e.Weights())]
	body, published := pages[v.Page]
	if !published {
		return "", nil, false
	}
	st.Analytics.Convert(r, experiment.SeenKey(e.Name, v.Name))
	return v.Page, body, true
}

// convert records a goal, and credits it to the variant of every running
// experiment with that goal that this visitor was shown today.
func (st *Site) convert(r *http.Request, goal string) {
	if st.Analytics == nil {
		return
	}
	st.Analytics.Convert(r, goal)
	if st.Experiments == nil {
		return
	}
	set, err := st.Experiments()
	if err != nil {
		return
	}
	for _, e := range set.Experiments {
		if !e.Running || e.Goal != goal {
			continue
		}
		v := e.Variants[st.Analytics.Bucket(r, e.Name, e.Weights())]
		if st.Analytics.Reached(r, experiment.SeenKey(e.Name, v.Name)) {
			st.Analytics.Convert(r, experiment.WonKey(e.Name, v.Name))
		}
	}
}

// convertPage records reaching a page, for experiments whose goal is it.
// Only those: a goal per page for every page would fill the day's goals with
// what the page counts already say.
func (st *Site) convertPage(r *http.Request, path string) {
	if st.Experiments == nil || st.Analytics == nil {
		return
	}
	set, err := st.Experiments()
	if err != nil {
		return
	}
	for _, e := range set.Experiments {
		if e.Running && e.Goal == "page:"+path {
			st.convert(r, e.Goal)
			return
		}
	}
}

// personalFor returns the page a personalisation rule serves at name for this
// request, if one matches and its page is published. See
// internal/personalise: only what the request says is looked at.
func (st *Site) personalFor(r *http.Request, name string, pages map[string]any) (string, any, bool) {
	if st.Personalise == nil {
		return "", nil, false
	}
	set, err := st.Personalise()
	if err != nil {
		return "", nil, false
	}
	rule, ok := set.For(name, r, time.Now())
	if !ok {
		return "", nil, false
	}
	body, published := pages[rule.Variant]
	if !published {
		return "", nil, false
	}
	if st.Analytics != nil {
		st.Analytics.Convert(r, personalise.SeenKey(rule.Name))
	}
	return rule.Variant, body, true
}
