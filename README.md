# onyx-scan

A static scanner for Roblox/Luau place files, plus an executing emulator that can replay a
finding's handler under a mock of the documented Roblox API.

It is a linter for a narrow class of bug where a client can reach something on the server.
It is **source-available, not open source** (FSL-1.1-Apache-2.0): read, run and modify it freely,
including on commercial games; no resale or competing hosted service. It is **not** a security
audit and not a guarantee.

```console
$ onyx scan examples/demo_addcash_before.rbxlx

  1 critical issue found in 1 scripts
  1 scripts · 17 lines · 1 client-reachable remotes

  [CRITICAL] ONYX-L001  game.ServerScriptService.AddCash:14
           Remote handler writes a client-chosen value into a currency value
           Any client can fire this remote with arbitrary arguments. The handler writes a currency value, and the value written comes from the client argument, so a player chooses it.
           check      Fire the remote from a client with a wrong type and an extreme value. The value must not move; then repeat with the minimum and maximum you consider legal.
           precision  91.7% (22/24; 95% CI 74.2–97.7%) — Right 22 times out of 24 when a human checked; two did not hold up.

  [INFO    ] ONYX-L016  game.ServerScriptService.AddCash:14
           Client-supplied `amount` is used without a clamp
           `amount` arrives from the client and is never bounded; a client can send a negative or absurd value (e.g. -1e9). Whether that inverts an economy depends on what the write feeds, which this finding names in the snippet.
           check      Send NaN, infinity, a negative number and a very large number. The clamp must hold on all four.
           precision  no measured rate (not a claim class) — No rate is claimed for this rule.

  1 critical, 1 info

  Precision is the author's own measurement (onyx-scan 0.2.0), not an external audit — how to read it, with intervals:
  https://github.com/onyxstaticrbx/onyx-scan#precision
```

Every finding also carries a paste-ready fix prompt (`onyx scan --prompt`), the measured
precision of its rule with the counts and interval, and the check that proves it is closed.

Your path, line and rule will differ. A scan is local and makes no network calls; nothing is
changed, patched, or uploaded.

## Install

The package installs from PyPI; the two example fixtures live in the repository, so a clone is the
shortest path to a runnable example:

```
git clone https://github.com/onyxstaticrbx/onyx-scan
cd onyx-scan
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: . .venv/bin/activate
pip install .
onyx scan examples/demo_addcash_before.rbxlx
```

The two fixtures are small example places, one vulnerable and one fixed, so every command
below runs against them in a clean virtualenv. If you already have a place file, `pip install
onyx-scan` alone is enough and `onyx scan your-place.rbxlx` works from any directory.

Python 3.10 or newer. The static scan needs only Python.

`onyx verify` needs a [Luau](https://github.com/luau-lang/luau/releases) interpreter — prebuilt
releases exist for Windows, macOS and Linux. Put it on `PATH` as `luau`, pass `--luau /path/to/luau`,
or set `ONYX_LUAU`. Without it, `onyx scan` still works and `onyx verify` stops with a clear install
message instead of pretending to have executed anything.

## What it catches

Specific shapes where a client can reach server state: a value written into currency or
attributes, an external module loaded by a numeric asset id, purchase and remote handling that
trusts the wrong side, and saved-data key handling. Every finding names the file and line and
says what the client controls.

Where there is enough evidence, the report carries the measured precision of the rule **with its
counts and 95% interval** (for example `63.6% (7/11; 95% CI 35.4–84.8%)`, marked a lead, not a
conclusion); where there is not, it says `underpowered — N checked` or `no measured rate` rather
than quoting a number. The rule id on every finding is stable, so a finding can be matched across
runs and reports; the labels are frozen for `onyx-scan 0.2.0`: this is the author's own
self-assessment, not an external audit, and the Precision section below shows how to read them.

Some findings are informational notes for rules the precision table does not measure; those print
`no measured rate` in the same line rather than silently omitting it.

## Precision

The measured labels are the author's self-assessment — findings read by hand, not an external
audit. Each measured rate shows the checked count and its 95% interval; no point estimate is
printed alone. A rule with too few checked findings says `underpowered — N checked`; a rule with
none says `no measured rate`. A finding's `ONYX-L***` code identifies the rule whose
measured label applies.

## What it does not catch

- duplication and race-condition bugs (two players acting on the same tick);
- client-trusted combat, damage or position;
- movement exploits, and anything that lives only inside Roblox's own client;
- anything outside those rule classes.

**Zero findings means those shapes were searched for and not found — it is not a statement
that your game is secure.**

## Verify (optional)

```
onyx verify examples/demo_addcash_before.rbxlx
onyx verify examples/demo_addcash_before.rbxlx --fail-on-confirmed   # exits 2 if confirmed
```

Runs the handlers under a mock of the documented Roblox API and records evidence: how many
client-shaped payloads were fired (counted by the engine, not typed in), and every before/after
move of the state a handler wrote. It is a mock, not a live game server, and the report says so.
`onyx verify --fail-on-confirmed` exits 2 when an exploit is confirmed, for CI.

## CI and baselines

```
onyx scan examples/demo_addcash_before.rbxlx --json out.json     # machine-readable report
onyx baseline examples/demo_addcash_before.rbxlx -o .onyx-baseline.json
onyx scan examples/demo_addcash_before.rbxlx --baseline .onyx-baseline.json --fail-on-new
onyx scan examples/demo_addcash_before.rbxlx --prompt             # paste-ready fix prompts
```

`--fail-on-critical` is also available for a quick gate. `onyx verify --fail-on-confirmed`
exits 2 when it confirms an exploit, so both halves can gate CI.

## Formats

`.rbxlx` (place) and `.rbxmx` (model) are the supported formats. A file saved as XML but named
`.rbxl` or `.rbxm` is read too. A **binary** `.rbxl` cannot be read; export it in Studio via
*File → Save to File As…*, then pick **Roblox XML Place Files (`*.rbxlx`)** under *Save as type*.
In Team Create, save **File → Download a Copy** first, open that copy, then save it as XML. Rojo
project folders of plain `.lua`/`.luau` files are not scanned.

## FAQ

**Does it change my game?** No. It reads a file and prints findings. Nothing is applied.

**Does my file leave my computer?** No. The tool makes no network calls, and the file never
leaves your computer.

**What does "0 findings" mean?** Those specific shapes were searched for and not found. It
does not mean secure.

**`onyx rules`?** Lists every rule id and what it catches, so a finding's `ONYX-L***` code can be
matched to the page.

**What if a finding is wrong?** Open a *wrong finding* issue with the rule id, path:line and
one sentence. That is how the rules get better. Please don't post your place file or any
credentials.

**Windows?** Not tested by the maintainer yet. The package is pure Python, so it should install
with Python 3.10+ from python.org; if it does not, open an issue with the exact error. The
commands would be:

```
py -m pip install onyx-scan
py -m onyx.cli scan place.rbxlx
```

`onyx verify` also needs the Windows Luau build from the releases page; it prints that link
itself if it cannot find one.

## Licence

**Functional Source License 1.1, Apache 2.0 Future License (FSL-1.1-Apache-2.0).** Source-available,
not open source. You may read, run, modify and share the code for any purpose except a competing
use — commercially scanning your own games is allowed. After two years from each version's release,
that version becomes available under Apache 2.0. The full canonical text is in `LICENSE`.
