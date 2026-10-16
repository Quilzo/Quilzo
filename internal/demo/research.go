// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package demo

// ResearchProject is a research project the demonstration starts: a
// question, an analysis plan not yet registered, and the files a
// computation needs, by their path in the project.
type ResearchProject struct {
	Name, Question, Plan string
	Files                map[string]string
}

// repeatOrders is the shop's own question about its customers, with forty
// first orders to answer it from. Small enough to read in full, and enough
// for the parts of a research project to be tried in order: run the
// analysis, pin its numbers as claims, ask a model for ideas worth testing
// next, and record a verdict on one once a computation has run it.
var repeatOrders = ResearchProject{
	Name: "repeat-orders",
	Question: "Do customers whose first order is from the desk range come back for a second " +
		"order within 90 days more often than those whose first order is correspondence?",
	Plan: "Compare the share of customers with a second order within 90 days, between first " +
		"orders from the desk range and from the correspondence range, in data/orders.csv. " +
		"Report each share and the difference in percentage points.",
	Files: map[string]string{
		"data/orders.csv": `customer,first_range,second_order_within_90_days
c-001,desk,no
c-002,desk,no
c-003,desk,no
c-004,desk,no
c-005,desk,yes
c-006,desk,yes
c-007,desk,no
c-008,desk,yes
c-009,desk,no
c-010,desk,yes
c-011,desk,yes
c-012,desk,yes
c-013,desk,no
c-014,desk,yes
c-015,desk,no
c-016,desk,yes
c-017,desk,yes
c-018,desk,no
c-019,desk,yes
c-020,desk,yes
c-021,correspondence,yes
c-022,correspondence,no
c-023,correspondence,no
c-024,correspondence,no
c-025,correspondence,yes
c-026,correspondence,no
c-027,correspondence,no
c-028,correspondence,no
c-029,correspondence,yes
c-030,correspondence,no
c-031,correspondence,yes
c-032,correspondence,no
c-033,correspondence,no
c-034,correspondence,no
c-035,correspondence,no
c-036,correspondence,yes
c-037,correspondence,yes
c-038,correspondence,no
c-039,correspondence,no
c-040,correspondence,yes
`,
		"analysis.py": `import csv, json

rows = list(csv.DictReader(open("data/orders.csv")))
def share(rng):
    first = [r for r in rows if r["first_range"] == rng]
    back = [r for r in first if r["second_order_within_90_days"] == "yes"]
    return 100 * len(back) / len(first)

desk, letters = share("desk"), share("correspondence")
json.dump({
    "desk_repeat": {"value": round(desk, 1), "unit": "%"},
    "correspondence_repeat": {"value": round(letters, 1), "unit": "%"},
    "difference": {"value": round(desk - letters, 1), "unit": "percentage points"},
    "customers": {"value": len(rows), "unit": "customers"},
}, open("values.json", "w"))
`,
	},
}
