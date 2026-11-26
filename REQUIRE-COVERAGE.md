# Require coverage and the 0.3.0 slowdown

Two questions a reader should be able to answer without running the scanner: which
`require` forms 0.3.0 resolves on real places, and where the extra runtime goes.

## What was run

- 506 Roblox places, read from `.rbxlx` files.
- 129,524 scripts, 1,408 of which hit a parser fallback.
- Same machine, same order, one after the other: 0.2.2 is the released wheel, 0.3.0 is
the candidate source.
- 0.2.2: 278.9 s total. 0.3.0: 872.5 s total (3.13x). Neither run hit the 120 s
per-place budget.

Scope, stated plainly: this is a sample of places, not every place. It says which forms
the scanner resolves on this sample; it is not a claim that the same forms resolve
everywhere, and it is not a measured rate for the cross-file rule.

## Which `require` forms resolve

Every one-hop `require` call in the sample, grouped by the shape of its argument
(20,068 calls in total). "Resolved" means the scanner followed the one hop to a
ModuleScript instance and read its function summaries. "Unresolved" is counted, never
silently ignored, and the report says so.

| shape | resolved | unresolved | total | resolved |
|---|---:|---:|---:|---:|
| `script.<path>` | 7,082 | 121 | 7,203 | 98.3% |
| `game.<path>` | 5,459 | 979 | 6,438 | 84.8% |
| `local alias.<path>` | 3,452 | 2,790 | 6,242 | 55.3% |
| numeric asset id | 0 | 159 | 159 | 0.0% |
| string asset id | 0 | 19 | 19 | 0.0% |
| other | 6 | 1 | 7 | 85.7% |
| **total** | **15,999** | **4,069** | **20,068** | **79.7%** |

The ten most common shapes, which is where most of the resolved calls live:

| shape | resolved | unresolved | resolved |
|---|---:|---:|---:|
| `script.Parent.child` | 1,959 | 5 | 99.7% |
| `game.child.child` | 1,869 | 7 | 99.6% |
| `game.child.child.child.child` | 1,404 | 0 | 100% |
| `script.child` | 1,425 | 1 | 99.9% |
| `local alias:WaitForChild` | 1,529 | 377 | 80.2% |
| `game.child.child.child` | 1,341 | 3 | 99.8% |
| `local alias.child` | 746 | 636 | 54.0% |
| `script.Parent.Parent.child` | 733 | 2 | 99.7% |
| `script:WaitForChild` | 702 | 34 | 95.4% |
| `script.Parent:WaitForChild` | 497 | 3 | 99.4% |

Reading the table:

- Paths that start at `script` resolve almost always: the script instance is known, so
`script.Parent...` is a lookup in the place tree.
- `game...` paths resolve well but not completely: a service or child that the place
model does not contain (dynamic content, an asset that was not saved) is unresolved.
- **`local alias...` is the weak family.** A require argument that starts with a local
variable name only resolves if the scanner saw that variable bound to an instance
earlier in the same script. Aliases built by a function call, or bound in another scope,
are unresolved. Deep chains past one hop (`local alias.child.child.child`, 6.6% resolved)
are unresolved by design.
- Asset ids are unresolved by design: `require(123)` or `rbxassetid://...` points outside
the place tree.
- Coverage reports these counts as `require_by_pattern`, so a report can say which shapes
it followed instead of printing a single unresolved number.

## Where the 3.13x goes

A stratified sample of 60 places (the 20 slowest plus 40 random), 35,609 scripts and 3.16
million lines, with per-phase timers:

| phase | wall time | share | scaled to the recorded 0.3.0 time | share of the added time |
|---|---:|---:|---:|---:|
| existing token rules (0.2.2 work) | 125.0 s | 30.9% | 111.3 s | 0% |
| place load (XML and Rojo) | 5.8 s | 1.4% | 5.2 s | 0% |
| Luau AST tokenizer | 74.4 s | 18.4% | 66.2 s | 26.8% |
| Luau AST parser | 51.3 s | 12.7% | 45.7 s | 18.5% |
| require graph (bindings + def-use walks + summaries) | 147.9 s | 36.6% | 131.7 s | 53.3% |

On this sample 0.2.2 took 112.9 s and 0.3.0 took 360.0 s: +247.1 s. The three new AST
phases account for 243.6 s of that, about 98.6% of the added time; the existing token path
did not get slower. Per script the added cost is about 6.9 ms (whole sample: 4.6 ms per
script over 129,524 scripts).

So the slowdown is not the token rules: it is that every analyzed script is now tokenized
a second time and parsed into nodes, and then walked two more times to build require
bindings and function summaries (one walk per function body on top of that). That is the
price of resolving cross-module calls at all; the 0.2.2 engine never read the AST.

## Why it was not optimised before release

Ideas that would cut the 3x, and why each was left alone:

- **Parse only scripts that contain a `require`.** Cheap in principle, but the graph also
learns which modules write state; a text pre-filter on `require` would miss a module
reached by an alias defined in another script, and miss summaries needed for a later hop.
A false negative here reads as "clean", which is the failure mode this release is trying
to remove.
- **Cache parses between places.** Places in the sample are mostly different scripts; a
cache would complicate memory bounds for a small win.
- **Skip the summary walk and only resolve the edge.** The cross-file rule needs the
summary (which function writes which state, and at which parameter), so dropping it drops
the finding.
- **A faster parser.** Worth doing eventually; it does not change the order of magnitude.

The honest position: 3.13x on this sample, dominated by AST construction and the graph
walks, with zero change to the findings on the same sample (see the 0.2.2 differential:
3,012 findings, 0 added, 0 removed, 0 changed).

## Reproduce

```sh
# require shapes, one row per shape (also printed in the scan report's coverage)
python -c "
from onyx.scan import scan_file
report = scan_file('examples/rojo_demo')
print(report['coverage']['require_by_pattern'])"

# per-place timing and coverage on your own place
python -m onyx.cli scan <place> --json report.json
python -c "import json; print(json.load(open('report.json'))['coverage'])"
```
