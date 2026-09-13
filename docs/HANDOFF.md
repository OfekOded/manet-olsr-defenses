# Project status and handoff notes

Written when the original authors finished, for whoever continues the work.
The intent is that nothing here is a surprise later.

## Where things stand

All four defenses are implemented and instrumented, and all four branches build
and pass `--self-test`. TRUST and FPNT are fully evaluated with complete dataset
batches; DCFM and Watchdog have working, verified harnesses but no full batches
yet ([DATASETS.md](DATASETS.md)).

| | TRUST-OLSR | FPNT-OLSR | DCFM-OLSR | Watchdog-OLSR |
|---|---|---|---|---|
| Paper | Adnane et al., 2013 | Tan et al., 2015 | Schweitzer et al., 2024 | Baiad et al., 2014 |
| Author | Oded Ofek | Oded Ofek | Hananel Kahana | Hananel Kahana |
| Branch | `trust-defense` | `fpnt-defense` | `dcfm-defense` | `watchdog-defense` |
| Implementation | complete | complete | complete | complete |
| Builds + self-test | ✅ | ✅ | ✅ | ✅ |
| Canonical datasets | `trust_*_v2` | `fpnt_static`, `fpnt_mobile` | **none yet** | **none yet** |
| Randomized-window datasets | **missing** | `fpnt_*_mixed` | **missing** | **missing** |

DCFM and Watchdog were imported from the partner's repository on 2026-09-11 —
see [PARTNER-IMPORT.md](PARTNER-IMPORT.md) for exactly what came from where.

## Verified at handoff

All four branches, 2026-09-11. Every item below was run, not assumed.

**Per branch:** `doctor` reports **0 failures**; `--self-test` prints
`ALL PASS`; the harness builds from a clean `use <defense>`.

**End-to-end generation sweep — 20 accepted runs requested on each defense:**

| | accepted | feature rows | rejected | errors |
|---|---|---|---|---|
| TRUST | 31 | 124 | 41 | 0 |
| FPNT | 29 | 116 | 47 | 0 |
| DCFM | 31 | 124 | 19 | 0 |
| Watchdog | 30 | 120 | 27 | 0 |

(Accepted exceeds 20 because parallel workers finish runs already in flight when
the target is reached; the overshoot is kept, as documented in
[RUNNING.md](RUNNING.md#resumability).)

Every batch passed a structural validation, not just an "a file appeared" check:

- feature header exactly the 5 identity + 17 LISTENER columns; no ragged rows
- feature rows == label rows == oracle rows == 4 × accepted runs
- every run carries all four scenarios exactly once
- `defense_enabled` **and** `attack_enabled` each take both values, and all four
  combinations appear — the 2×2 design demonstrably varied
- all feature values numeric; **no NaN in any batch**
- no all-zero rows; 15 of 17 features vary (the two that do not are
  `MidMessageRate` and `HnaMessageRate`, structurally zero for this topology —
  see [SCHEMA.md](SCHEMA.md#two-features-are-always-zero-in-this-experiment))
- `(run_id, scenario)` keys join exactly between features and labels, no duplicates
- provenance sidecars name the right branch, commit, seed range and
  `defense_variant`

**Cross-defense:** all four batches share one byte-identical feature header and
one label header, and their seed ranges are disjoint by construction
(TRUST 4 000 021…, FPNT 9…, DCFM 20 000 001…, Watchdog 24 000 001…). That is
what makes the four datasets comparable.

The verification batches were deleted afterwards; they existed only to prove the
pipeline runs end to end.

**ns-3 test suites:** `routing-olsr` and `routing-olsr-header` pass on all four
branches. `routing-olsr-regression` passes on `trust-defense` and `fpnt-defense`
and **crashes on `dcfm-defense` and `watchdog-defense`** — see known issue 0.

Two results from that pass are worth recording, because both were latent
problems that would have surfaced for you rather than for us.

**`routing-olsr-regression` used to crash on `trust-defense`.** The cause was
`Config::Connect` where `Config::ConnectFailSafe` was needed — a node with no
`WifiNetDevice` matches the trace path nothing, and `Config::Connect` treats no
match as fatal. Demonstrated both ways: reverting the one line makes the suite
`CRASH`, restoring it makes it `PASS`. `fpnt-defense` already had the fix. The
fault went unnoticed for as long as it did because the project only ever
configured with `--enable-examples`, so the test suites were never built — see
[RUNNING.md](RUNNING.md#running-the-ns-3-test-suites).

**The TRUST flags are now applied automatically, and it is verifiable.** A
plain `smoke` run on `trust-defense`, with no flags typed by hand, produces
`enable_consistency_rules=1` and `enable_alert_distribution=1` in
`defense_params.txt` — which is the harness reporting its own effective
configuration, not the wrapper reporting what it passed.

## Remotes

```
origin     https://github.com/OfekOded/manet-olsr-defenses.git   this project
upstream   https://gitlab.com/nsnam/ns-3-dev.git                 ns-3, for pulling releases
hananel    https://github.com/hananelk26/manet-olsr-project.git  the partner's original repo
```

`hananel` is kept configured so the provenance of DCFM and Watchdog stays
inspectable — `git log hananel/master`, `git show hananel/master:<path>`. See
[PARTNER-IMPORT.md](PARTNER-IMPORT.md).

Only this project's five branches and nine `handoff-*` / `restore-*` tags were
pushed to `origin`. The ~100 upstream `ns-3.*` tags stay on `upstream` where
they belong, so `git tag` in a clone lists only tags that mean something here.

## Tags

| Tag | Meaning |
|---|---|
| `trust-defense-verified-2026-08-18` | TRUST after merging ns-3.47 and the QA round |
| `trust-defense-paper-complete-2026-08-20` | TRUST implementation complete against Adnane et al. |
| `handoff-2026-09-11-{trust,fpnt,dcfm,watchdog}` | the state handed over on each defense branch |
| `restore-2026-09-11-{master,trust,fpnt,dcfm,watchdog}` | restore points on every branch |

Only the tags above are published to `origin`. Older local tags —
`trust-defense-verified-2026-08-18`, `trust-defense-paper-complete-2026-08-20`,
`v1.0-stable`, `v1.1-stable` — and the upstream `ns-3.*` release tags were not
pushed.

The defense branches are based on ns-3.47 and several hundred commits behind
current upstream ns-3. Rebasing onto a newer ns-3 is possible but would
invalidate the datasets, which are tied to ns-3.47 behaviour.

## Known issues

### 0. Two issues introduced by the four-defense merge

**`dcfm-defense` and `watchdog-defense` crash `routing-olsr-regression`.** Both
carry `Config::Connect` where `Config::ConnectFailSafe` is needed — the same
fault `trust-defense` had and that was fixed there. The partner's code was
imported verbatim by decision, so it was left in place. One line in each file;
the fix is visible in `trust-defense`'s history if you want it.

**`master` is on a different ns-3 release than the four defense branches.** It
is `3-dev`; all four defense branches are `3.47`. `master` also still carries the
pre-LISTENER-17 feature collector and the old TRUST harness. It works fine as the
home for shared tooling and docs, and `doctor` refuses to generate data there,
but the name invites the mistake. Either merge `ns-3.47` into it or rename it to
something like `shared-base`.

Listed honestly, in rough order of how likely they are to cost you time.

### 1. TRUST's defense timer ignores its own `CheckInterval`

`olsr-routing-protocol.cc` on `trust-defense` schedules the defense timer with a
hardcoded `Seconds(1.0)`:

```cpp
m_defenseTimer.Schedule(Seconds(1.0));
```

but `OlsrTrustDefense`'s `CheckInterval` attribute defaults to 0.25 s and is
documented as the forward-failure expiry sweep granularity. FPNT does this
correctly via `GetDefenseCheckInterval()`.

**This was left unchanged on purpose.** Fixing it changes TRUST's runtime
behaviour and would make the existing `trust_*_v2` datasets non-comparable with
anything produced afterwards. If you fix it, regenerate the TRUST batches and
say so in the manifest.

### 2. `olsr-repositories.h` exists twice on `trust-defense` — *fixed 2026-09-13*

`src/olsr/model/olsr-repositories.h` and
`src/olsr/model/defense/olsr-repositories.h` are byte-identical. Nothing includes
the `defense/` copy directly; it existed only as the source CMake installed as
`ns3/olsr-repositories.h`.

This was listed here as harmless. **It was not.** A verification run on a fresh
clone from GitHub, following QUICKSTART's order, built `trust-defense` cleanly —
and then `use fpnt`, `use dcfm` and `use watchdog` all failed to compile:

```
build/include/ns3/olsr-repositories.h: fatal error:
  src/olsr/model/defense/olsr-repositories.h: No such file or directory
```

ns-3 publishes each header as a one-line forwarding stub in
`build/include/ns3/`, and configure never rewrites a stub that already exists. The
stub created on `trust-defense` pointed into `defense/`, which the other three
branches do not have. The original development tree never showed it only because
its stub had been created from a branch that installs `model/`.

Fixed twice over, neither affecting simulation behaviour: `trust-defense` now
installs the `model/` copy (identical bytes), and `olsr-research.sh build` deletes
any forwarding stub whose target no longer exists before it configures. The
duplicate file itself is still on `trust-defense`, unused; removing it is safe.

### 3. Parity references are not in this repository

[SCHEMA.md](SCHEMA.md) documents the feature collector as a deliberate
re-implementation of `iolsr-tests-corrected.cc`, with feature 8 defined by
`arm_spec.py`. **Neither file is in this repo.** Parity therefore cannot be
re-verified from here alone. If you can obtain them, commit them under
`docs/reference/` — they are the only external dependency of the schema.

### 4. `blackhole-animation.xml` is committed

135 KB of generated NetAnim output, at the repository root, on all three
branches since the initial commit. Harmless but wrong: it is output, not source.
Removing it from the tip is easy; removing it from history is a rewrite and was
not done.

### 5. No TRUST mixed-window batches

All four canonical batches ran with `random_window_order = 0`, which perfectly
confounds measurement-window slot position with scenario. The FPNT `_mixed`
batches were added to quantify that effect; the TRUST equivalent was never run.
See "next steps" below.

### 6. `master` is not a clean pre-defense base

It already carries `scratch/olsr-trust-eval-mitigation.cc` and the FPNT trust
mechanism commit. It is the shared base of the defense branches, not a neutral
stock-ns-3 checkout. Its `scratch/olsr_window_features.h` also predates
the LISTENER-17 schema, so do not use `master` to generate anything.

## Suggested next steps

Roughly in order of value per unit of effort.

1. **Run the TRUST mixed-window batches** to close the asymmetry in issue 5.
   Two commands, no code changes:
   ```bash
   ./tools/olsr-research.sh use trust
   ```
   ```bash
   ./tools/olsr-research.sh batch -n 2000 -j 12 --mixed --detach
   ```

2. **Train and report the detection models.** The dataset is the point of the
   project and is complete; nothing in this repository consumes it yet. There is
   no analysis code here at all — that work lives outside the repo, and adding it
   under `analysis/` would make the pipeline end-to-end reproducible.

3. **Decide about `MonitorTcForwarding`** on FPNT. It is in the paper but
   defaults to off here. Whether turning it on changes the results is unmeasured.

4. **Consider the FPNT-OLSR(R) variant** (`--redundantMpr`). Implemented, never
   evaluated.

5. **Unify defenses onto fewer branches**, if side-by-side comparison within a
   single run ever becomes important.
   [ARCHITECTURE.md](ARCHITECTURE.md#why-four-branches) sets out exactly what
   conflicts. TRUST/FPNT is the easier pair — the `olsr-header.h` divergence is
   mechanical and the strategy interfaces union cleanly, leaving only the HELLO
   re-flooding rule as a real design decision. DCFM/Watchdog conflict in six
   regions, including opposite responses to a suspected next hop. Any merge breaks
   comparability with existing datasets unless it reproduces every defense
   bit-for-bit.

## Things not to break

- **`scratch/olsr_window_features.h` must stay byte-identical on all four defense
  branches.** It is what makes the four datasets comparable. Change it on all
  four in the same commit, bump `HEADER_VERSION`, and write a new
  `docs/DATASETS.md` row.
- **`tools/` and `docs/` must stay identical across branches.** Edit them on
  `master` and merge `master` into each defense branch; never edit them on a
  defense branch directly. `tools/defense.manifest` is the one exception.
- **Seed ranges in `tools/defense.manifest`** are what let a regenerated batch
  reproduce the original run-for-run. Do not renumber them casually.
- **The stale-binary guard in `--direct` mode.** It looks like an obstacle; it is
  the only thing standing between you and a dataset silently generated by the
  previous revision's code. Rebuild rather than work around it.
- **`windows_oracle.csv` is not a feature source.** It contains ground truth an
  attacker-detecting model cannot legitimately observe.

## Provenance of the tooling

`tools/run_simulations.sh` and `tools/olsr-research.sh` consolidate what used to
be five untracked scripts in a home directory outside the repository
(`run_simulations_direct.sh`, `drive_all.sh`, `drive_trust_v2.sh`,
`drive_fpnt_mixed.sh`, `launch.sh`). The runner is the audited `--direct`
version that actually produced every dataset in [DATASETS.md](DATASETS.md); the
repo previously tracked an older copy without `--direct` that had never
generated any of the shipped data.

Changes made during consolidation, all in `tools/run_simulations.sh`:

- the default harness now comes from `tools/defense.manifest` instead of being
  hardcoded to FPNT — which was wrong on two of the three branches;
- `--defense watchdog` and `--defense dcfm` were removed; no such harness was
  ever written, so those selectors could only fail;
- a clear error when the requested harness does not exist on the current branch;
- `--fresh` no longer blocks on an interactive prompt when stdin is not a
  terminal — it used to hang or silently abort under `nohup`. Use `--yes`;
- output paths are quoted in the `./ns3 run` argument string, which previously
  broke on any path containing a space;
- `runner.config` now records the branch, the commit and whether `--direct` was
  used, and every batch gets a `defense_flags.txt` provenance sidecar.

None of this changes simulation behaviour; the numbers a run produces are
unaffected.
