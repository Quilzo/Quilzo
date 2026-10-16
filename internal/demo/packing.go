// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package demo

// The shop's packing bench, for trying evolve: a program that packs a
// day's orders into parcels, the judge that checks a packing and counts its
// parcels, and a second day's orders kept aside as the test set.
//
// Small and checkable on purpose. First fit, in the order the orders came,
// takes six parcels for Monday where five will do, so a search has
// something real to find, and the judge is short enough to read before
// trusting its numbers. The judge never runs what a packer wrote: it reads
// the packing as data, which is what keeps the seal a seal.
var packingExample = map[string]string{
	"evolve/README.txt": `A program search, with a judge the programs cannot reach.

  quilzo evolve run --program examples/evolve/pack.py \
    --evaluator examples/evolve/judge.py \
    --input examples/evolve/orders.json --eval-input examples/evolve/orders.json \
    --test-input examples/evolve/test/orders.json \
    --test-eval-input examples/evolve/test/orders.json \
    --weight parcels=-1 --generations 10 \
    --task "Pack the orders into as few 2 kg parcels as possible"

pack.py packs Monday's orders first fit, in the order they came: six
parcels. judge.py checks every order is packed once and no parcel is over
2 kg, and counts the parcels; --weight parcels=-1 asks for fewer. Tuesday's
orders, in test/, are scored once at the end and never used to choose.
A search needs a model: set one up on the Models screen first.
`,
	"evolve/pack.py": `# Pack the day's orders into as few parcels as possible.
import json

orders = json.load(open("orders.json"))
limit = orders["limit_grams"]
items = orders["items"]

# EVOLVE-BLOCK-START
def pack(items, limit):
    parcels = []
    for item in items:
        for parcel in parcels:
            if sum(i["grams"] for i in parcel) + item["grams"] <= limit:
                parcel.append(item)
                break
        else:
            parcels.append([item])
    return parcels
# EVOLVE-BLOCK-END

parcels = pack(items, limit)
json.dump([[i["id"] for i in p] for p in parcels], open("output/parcels.json", "w"))
`,
	"evolve/judge.py": `# Check a packing and count its parcels. Reads the packing as data and
# never runs anything the packer wrote.
import json, sys

orders = json.load(open("orders.json"))
weight = {i["id"]: i["grams"] for i in orders["items"]}
parcels = json.load(open("candidate/parcels.json"))

packed = [i for p in parcels for i in p]
if sorted(packed) != sorted(weight):
    sys.exit("every order must be packed exactly once")
for p in parcels:
    if not p or sum(weight[i] for i in p) > orders["limit_grams"]:
        sys.exit("a parcel is empty or over the limit")

json.dump({"parcels": len(parcels)}, open("output/metrics.json", "w"))
`,
	"evolve/orders.json": `{
 "limit_grams": 2000,
 "items": [
  {
   "id": "mon-01-brass-pen",
   "grams": 450
  },
  {
   "id": "mon-02-linen-notebook",
   "grams": 380
  },
  {
   "id": "mon-03-glass-inkwell",
   "grams": 620
  },
  {
   "id": "mon-04-desk-blotter",
   "grams": 1200
  },
  {
   "id": "mon-05-letter-rack",
   "grams": 300
  },
  {
   "id": "mon-06-copper-tray",
   "grams": 950
  },
  {
   "id": "mon-07-writing-set",
   "grams": 1100
  },
  {
   "id": "mon-08-ink-refills",
   "grams": 540
  },
  {
   "id": "mon-09-index-cards",
   "grams": 700
  },
  {
   "id": "mon-10-paper-weight",
   "grams": 260
  },
  {
   "id": "mon-11-journal",
   "grams": 880
  },
  {
   "id": "mon-12-archive-box",
   "grams": 1300
  },
  {
   "id": "mon-13-envelopes",
   "grams": 420
  },
  {
   "id": "mon-14-pen-case",
   "grams": 760
  }
 ]
}
`,
	"evolve/test/orders.json": `{
 "limit_grams": 2000,
 "items": [
  {
   "id": "tue-01-brass-pen",
   "grams": 500
  },
  {
   "id": "tue-02-linen-notebook",
   "grams": 700
  },
  {
   "id": "tue-03-glass-inkwell",
   "grams": 640
  },
  {
   "id": "tue-04-desk-blotter",
   "grams": 1300
  },
  {
   "id": "tue-05-letter-rack",
   "grams": 520
  },
  {
   "id": "tue-06-copper-tray",
   "grams": 980
  },
  {
   "id": "tue-07-writing-set",
   "grams": 410
  },
  {
   "id": "tue-08-ink-refills",
   "grams": 1150
  },
  {
   "id": "tue-09-index-cards",
   "grams": 330
  },
  {
   "id": "tue-10-paper-weight",
   "grams": 860
  },
  {
   "id": "tue-11-journal",
   "grams": 590
  },
  {
   "id": "tue-12-archive-box",
   "grams": 1020
  },
  {
   "id": "tue-13-envelopes",
   "grams": 350
  }
 ]
}
`,
}
