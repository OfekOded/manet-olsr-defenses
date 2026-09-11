# Running simulations

Reference for producing datasets. If you just want output, [QUICKSTART.md](QUICKSTART.md)
is shorter.

There are two layers:

| Layer | File | Use it when |
|---|---|---|
| Entry point | `tools/olsr-research.sh` | Almost always. Reads the branch manifest and applies the right flags. |
| Batch runner | `tools/run_simulations.sh` | You need an option the entry point does not expose (calibration, mixed-fraction orchestration, a non-standard binary). |

---

## The TRUST default-flags trap

**Read this before interpreting any TRUST result.**

The TRUST harness's command-line defaults are:

```
--enableForwardMonitor=true      (Formula 10, the forward monitor)
--enableConsistencyRules=false   (Formulas 6, 7, 8, 9a, 9b, 11/12)
--enableAlertDistribution=false  (§7 alert re-broadcast)
```

With those defaults, only *one* of the paper's three detection mechanisms is
live. Measured detection in the 2026-08-30 batches came out at **0.12% (static)
and 0.48% (mobile)** — which reads like the defense does not work, when in fact
it was mostly switched off. A faithful run needs:

```
--enableConsistencyRules=1 --enableAlertDistribution=1
```

`tools/olsr-research.sh` applies these automatically from
`tools/defense.manifest`, so every run through the entry point is correct. You
can only hit the trap by invoking the harness or `run_simulations.sh` directly.
The `trust_static` / `trust_mobile` batches in [DATASETS.md](DATASETS.md) were
generated before this was understood; `trust_static_v2` / `trust_mobile_v2`
supersede them.

Provable identity (§6) stays off deliberately — the harness hard-sets
`EnableProvableIdentity=false`. At this scale it costs more than it gives.

FPNT has no equivalent trap: its harness defaults already reproduce
Tan et al. (2015).

---

## What one run actually does

Each run is a 50-node OLSR network with one attacker (node 2 by default) that
spoofs links to win MPR selection and then drops the traffic routed through it.
A run is measured in **four 40-second windows**, a 2×2 design over
defense × attack:

| Window | Time | Scenario | `defense_enabled` | `attack_enabled` |
|---|---|---|---|---|
| 1 | 60–100 s | `baseline` | 0 | 0 |
| 2 | 160–200 s | `attack_only` | 0 | 1 |
| 3 | 260–300 s | `defense_only` | 1 | 0 |
| 4 | 360–400 s | `defense_vs_attack` | 1 | 1 |

So one accepted run yields **four labelled feature rows**, all from the same
topology and the same RNG stream. That is what makes the comparison within a
run meaningful.

Measurements come from a **single listening radio** (schema LISTENER/SL-2) —
one node in promiscuous mode, never a network-wide oracle. See
[SCHEMA.md](SCHEMA.md).

`--mixed` / `--random-window-order` shuffles the order of the four windows,
seeded per run. The canonical batches all used the fixed order above, which
confounds slot position with scenario; the mixed batches exist to let you
measure that effect.

Not every attempt is accepted: runs where the topology does not produce a usable
flow are rejected and a new seed is tried. The measured yield is around 0.46,
so 2000 accepted runs take roughly 4400 attempts.

---

## `tools/olsr-research.sh`

```
doctor                     toolchain, branch, manifest, build, self-test
use <trust|fpnt> [JOBS]    switch branch, reconfigure, build, self-test
build [JOBS]               reconfigure and build the current branch
smoke                      5 runs; prints the resulting CSV header
run [options]              one dataset batch
batch [options]            the canonical batches for this branch
help
```

### How long a switch takes

Measured on the development machine (19 cores), from an already-built tree:

| Switch | Elapsed |
|---|---|
| `use fpnt` (from `trust-defense`) | ~1 min 40 s |
| `use trust` (from `fpnt-defense`) | ~15 min |

The asymmetry is real and reproducible. TRUST adds a whole module directory
(`src/olsr/model/defense/`, eight translation units) on top of
`olsr-trust-defense.cc`, where FPNT adds one file; switching *to* TRUST
therefore compiles considerably more, and everything that includes the OLSR
headers relinks. Budget for it rather than assuming the command hung.

A `build` with no branch change, after touching one file, is well under a
minute.

### `run` options

| Option | Default | Meaning |
|---|---|---|
| `-n N` | 2000 | Accepted runs to collect |
| `-j J` | `nproc` | Parallel workers |
| `-o DIR` | `datasets/<name>` | Output directory |
| `--mobile` | off | `--bMobility=true` |
| `--mixed` | off | Randomize the four windows per run |
| `--start-seed S` | from manifest | Override the seed range |
| `--extra "ARGS"` | — | Extra harness arguments |

### `batch` options

`-n`, `-j`, `-o` as above (`-o` is the output *root*), plus:

| Option | Meaning |
|---|---|
| `--mixed` | Run the randomized-window-order pair instead of the canonical pair |
| `--detach` | Run in the background (`setsid nohup`), safe to close the terminal |

`batch` runs static then mobile for the **current branch's defense only** — the
two defenses cannot be built in one working tree, so reproducing everything
means running it once per branch.

It fails fast: if a batch fails, the next one is not started, because the usual
cause (a stale build, a full disk) would break it too.

---

## `tools/run_simulations.sh`

The resumable parallel runner. Everything above ultimately calls this.

```
-n, --num-accepted N     required: target accepted runs
-j, --jobs J             parallel workers (default 1)
-o, --output-dir DIR     default ./simulations/features
    --ns3-dir DIR        default: the git root
    --defense NAME       trust | fpnt  (default: from tools/defense.manifest)
    --scratch NAME       scratch program directly; conflicts with --defense
    --start-seed S       default 1
    --max-attempts M     default: from --calibrate, else 5x target
    --calibrate [N]      measure yield over N attempts (default 200), then
                         set max-attempts = ceil(target / yield * 1.3)
    --fresh              DESTRUCTIVE: wipe runstate and CSVs first
    --yes                confirm --fresh without a prompt (required when
                         stdin is not a terminal)
    --skip-smoke         skip the pre-flight smoke run (not recommended)
    --extra "ARGS"       extra harness arguments
    --direct             call build/scratch/<binary> instead of './ns3 run'
    --random-window-order
    --mixed-fraction F   orchestrator mode: split the target into a canonical
                         batch and a randomized batch in $OUT_DIR/{normal,mixed}
    --mixed-seed-offset N  seed gap between them (default 100000000)
```

### `--direct`

Calls the built binary instead of `./ns3 run`. About 20% faster per attempt and,
more importantly, it stops N parallel workers from driving cmake against one
build directory at the same time. **Every dataset in [DATASETS.md](DATASETS.md)
was produced with `--direct`**, and `olsr-research.sh` always passes it.

The trade-off is that nothing rebuilds for you, so the script refuses to start
if the binary is older than `scratch/*.cc` or any `scratch/*.h`. That guard
matters: a stale binary emits the *previous* revision's schema and writes rows
that look entirely plausible.

### Startup sequence

1. `bash >= 4.3` guard (needs `wait -n` and associative arrays).
2. `$NS3_DIR/ns3` must be executable; the harness source must exist on this branch.
3. **Header check** — runs `--emit-header` and compares against the first line of
   any existing CSV. A mismatch exits with code 3 rather than appending rows in a
   different schema to an existing file.
4. **Pre-flight smoke run** — one sequential attempt; aborts on an unexpected
   return code (exit 4).
5. **Calibration** (optional; automatic when `-n >= 500` and `--max-attempts` is
   unset) — 200 attempts to measure yield, then sets the attempt cap.
6. **Main loop** — saturates `JOBS` workers, skipping any seed already in the
   ledger.

Exit codes: `0` target met, `1` target not met, `3` header mismatch, `4` smoke
failure, `5` calibration failure.

### Resumability

State lives in `$OUT_DIR/.runstate/`:

```
seeds.ledger      <seed> <status> <reason> <timestamp>
accepted / rejected / errors    counters
attempts.tsv      every attempt
calibration.json  measured yield
smoke.ok          pre-flight marker
```

The runner appends by default and skips seeds already in the ledger, so
re-running the same command after an interruption continues rather than
restarting. `--fresh` is the opt-in destructive wipe.

With `J` workers you may get up to `J-1` accepted runs beyond the target,
because each worker is mid-simulation when the loop stops. Those extra runs are
kept.

---

## Output layout

```
$OUT_DIR/
  runs.csv               one row per accepted run: full configuration
  windows_features.csv   the ML X-matrix (see SCHEMA.md)
  windows_labels.csv     the ML y-vector
  windows_oracle.csv     ground truth / diagnostics — NEVER an ML input
  probe.csv              per-attempt topology probe
  defense_params.txt     defense parameters actually in effect
  defense_flags.txt      branch, commit, flags, seed range, window order
  runner.config          the runner's configuration snapshot
  runner.summary         final counts
  logs/seed_NNNNN.log    one log per attempt (accepted or not)
  .runstate/             see above
```

`logs/` holds one file per *attempt*, so a 2000-run batch leaves about 4400 log
files. That is intentional — a rejected run's log is how you find out why — but
it dominates the directory's file count and inode usage.

---

## Harness flags

Shared by both harnesses:

| Flag | Default | Meaning |
|---|---|---|
| `--nNodes` | 50 | Node count |
| `--nMaxGridX` / `--nMaxGridY` | 750.0 / 1000.0 | Grid size (m) |
| `--bMobility` | false | RandomWalk2D mobility |
| `--bHighRange` | false | 250 m radio range instead of 190 m |
| `--txGain` | 0.0 | Wifi PHY TX gain (dB) |
| `--run` | 1 | `RngSeedManager::SetRun()` — **this is the per-attempt seed** |
| `--seed` | 1 | `RngSeedManager::SetSeed()` — the runner holds this at 1 |
| `--maliciousNodes` | `"2"` | Comma-separated attacker node IDs |
| `--spoofCount` | 5 | Spoofed links per attacker |
| `--attackerJitter` | 25.0 | Random placement offset (m) around the centre |
| `--listenerNode` | -1 | The single listening node; -1 means the first attacker's id |
| `--randomWindowOrder` | false | Shuffle the four windows, seeded by `--run` |
| `--verbose` | false | Info logging |
| `--emit-header` | false | Print CSV headers and exit |
| `--self-test` | false | Run the cycle-counter self-test and exit (expects `ALL PASS`) |
| `--debugDefenseState` | false | Print defense-state container sizes per window |
| `--runsFile` … `--outputDir` | — | Output paths; the runner sets all of these |

TRUST only (`trust-defense`):

| Flag | Default | Meaning |
|---|---|---|
| `--enableForwardMonitor` | **true** | Formula 10, the blackhole forward monitor |
| `--enableConsistencyRules` | **false** | Formulas 6/7/8/9a/9b/11/12 — *turn this on* |
| `--enableAlertDistribution` | **false** | §7 alert bus — *turn this on* |
| `--forwardTimeout` | 3.0 s | Awaiting period to overhear an MPR re-forward |
| `--checkInterval` | 0.25 s | Forward-failure expiry sweep granularity |
| `--monitorData` / `--monitorTc` | true / true | Watch DATA forwarding / TC re-flood |
| `--monitorRelayedData` | false | Also watch relayed DATA (generalized watchdog) |
| `--strictMacAttribution` | false | Require a MAC↔IP match to clear a DATA record |
| `--minForwardFailures` | 3 | Consecutive failures before mistrust |
| `--mistrustPermanent` | false | Permanent vs rehabilitatable mistrust |
| `--mistrustDuration` | 60.0 s | Rehab window when not permanent |

FPNT only (`fpnt-defense`):

| Flag | Default | Meaning |
|---|---|---|
| `--redundantMpr` | false | Enable the FPNT-OLSR(R) variant (§5.3) |
| `--maliciousThreshold` | 0.2 | Trust threshold T\* |
| `--uncertaintyBeta` | 0.6 | β, Eq. (4) |
| `--fadingFactor` | 0.7 | λ, Eq. (5) |
| `--maxLoad` | 1.0e6 | Load normalizer (bit/s) |
| `--maxDelay` | 0.5 | Delay normalizer (s) |
| `--cheatThreshold` | 2 | δ, deviation flag threshold (§5.1.D) |
| `--trustUpdateInterval` | 5.0 s | Trust reasoning period |

---

## Running the ns-3 test suites

`olsr-research.sh build` configures with `--enable-examples` only — the same
configuration that generated every dataset, and the faster one. The ns-3 test
suites are therefore **not built**, and `./test.py` will quietly rebuild
without them and then find nothing.

To run them, reconfigure once:

```bash
./ns3 configure --enable-examples --enable-tests
```

```bash
./ns3 build
```

```bash
./test.py -s routing-olsr-regression
```

The three suites that exercise this module are `routing-olsr-regression`
(system), `routing-olsr` and `routing-olsr-header` (unit). All three pass on
both defense branches.

This is worth doing after any change to `src/olsr/`. It is how the
`Config::Connect` fault described in [HANDOFF.md](HANDOFF.md#provenance-of-the-tooling)
was found: `routing-olsr-regression` crashed outright on `trust-defense`,
and because the project only ever configured with `--enable-examples`, nothing
ever ran it.

Once enabled, tests stay enabled. ns-3 keeps its configure options in the CMake
cache, so the `./ns3 configure --enable-examples` that `build` and `use` run
does **not** turn them off again — `NS3_TESTS:BOOL=ON` survives untouched.
Turning them off is an explicit act:

```bash
./ns3 configure --disable-tests
```

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `no such target scratch_olsr-...` | cmake was not reconfigured after a branch switch. Run `./tools/olsr-research.sh build`. |
| `--direct: ... is OLDER than ...` | Stale binary. Rebuild. This guard is doing its job — do not work around it. |
| `doctor` says `stale build: ... is newer than the binary`, right after a `git checkout` | Expected. Checking out a branch rewrites the source files and their timestamps, so the existing binary no longer matches. Run `./tools/olsr-research.sh build`. Using `use <defense>` instead of a bare `git checkout` does this for you. |
| Exit code 3, header mismatch | The schema changed since the existing CSVs were written. Write to a new directory, or `--fresh --yes` to discard. |
| `--fresh needs confirmation but stdin is not a terminal` | You are detached or piped. Add `--yes` if you really mean to delete the data. |
| `scratch/X.cc does not exist on this branch` | Wrong branch for that defense. `./tools/olsr-research.sh use trust` (or `fpnt`). |
| Working tree dirty, refuses to switch | Commit or stash. Switching with a dirty tree is how you silently mix two defenses' code. |
