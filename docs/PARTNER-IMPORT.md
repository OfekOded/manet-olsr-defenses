# Where DCFM and Watchdog came from

Two of the four defenses were implemented by **Hananel Kahana** in a separate
repository, [`github.com/hananelk26/manet-olsr-project`](https://github.com/hananelk26/manet-olsr-project),
and imported here on 2026-09-11. This page records exactly what was taken, from
where, and what was left behind.

## How his repository worked

It is a full ns-3 tree at VERSION 3.47 — the same release this project uses —
with **no branches**. Both defenses were present and compiled simultaneously;
switching between them meant **hand-copying
`src/olsr/model/olsr-routing-protocol.{h,cc}`** over itself and committing the
swap. His history alternates between the two states:

| Commit | Date | State |
|---|---|---|
| `1f55b70b8` | 2026-09-03 | DCFM (his `master`) |
| `96ec44ed7` | 2026-08-31 | Watchdog |
| `34af923e9` | 2026-07-10 | DCFM |
| `b2032c9eb` | 2026-06-25 | Watchdog |
| … | | alternating back to 2026-04-15 |

The two switch commits are exact inverses (`+531/−87` and `+87/−531`) and touch
only those two files, so the DCFM-vs-Watchdog difference really is a single
two-file delta on an otherwise fixed base.

## What was imported

His repository is configured as a git remote, so his authorship and full history
stay inspectable:

```bash
git log hananel/master
```

```bash
git show hananel/master:src/olsr/model/olsr-defense-gcop.h
```

| Branch | File | Source revision |
|---|---|---|
| `dcfm-defense` | `src/olsr/model/olsr-routing-protocol.{h,cc}` | `hananel/master` (`1f55b70b8`) |
| `dcfm-defense` | `olsr-defense-gcop.{h,cc}`, `olsr-defense-strategy.{h,cc}`, `scratch/olsr-dcfm-eval-mitigation.cc` | `hananel/master` |
| `watchdog-defense` | `src/olsr/model/olsr-routing-protocol.{h,cc}` | `96ec44ed7` |
| `watchdog-defense` | `olsr-watchdog-defense.{h,cc}`, `olsr-defense-strategy.{h,cc}`, `scratch/olsr-watchdog-eval-mitigation.cc` | `hananel/master` |

Both routing-protocol pairs were verified byte-identical (MD5) to the files sent
over directly, and an automated fingerprint confirms each branch got the right
variant — DCFM must contain `fictitious`, Watchdog must contain zero
occurrences of `fictitious` or `promisc`.

**The code is imported verbatim.** No bug fixes were applied to it; see
[HANDOFF.md](HANDOFF.md#known-issues) for what that implies.

## What was deliberately left behind

| Not imported | Why |
|---|---|
| `out_*/` — five directories, ~12 MB of committed CSVs | Generated with an older ~88-column schema, superseded by LISTENER-17 |
| `files for all defenses/` | His staging area for the manual swap. Its `DCFM/` and `Watchdog/` copies are byte-identical to the live files (so nothing unique is lost), while its `FPNT/` and `Trust/` copies are stale duplicates of *our* work |
| `results/`, `results_spoof*.csv`, `watchdog-results.csv` | Earlier, simpler output formats |
| His `run_simulations.sh`, `multi-seed-eval*.sh`, `variance-test.sh`, the two Python multi-seed drivers | Superseded by `tools/` here |
| Seven other scratch programs (`gcopBaseSimulation.cc`, `bridge_attack.cc`, …) | Exploratory; the two `*-eval-mitigation.cc` harnesses are the ones that produce the dataset |

Fetching his history cost **4.1 MiB** (197.98 → 202.10 MiB) because both trees
descend from the same upstream ns-3 commits and share nearly all objects.

## Why the import was straightforward

Three things had already converged independently, which is what made a merge
possible at all rather than a rewrite:

- **`scratch/olsr_window_features.h` is byte-identical** between his tree and
  ours (`59662ed01`). Both emit LISTENER-17 schema v6.
- **Both harnesses are `HARNESS_VERSION 3.0.0`, `HEADER_VERSION 8`** — the same
  lineage as ours. All four binaries emit an identical 22-column feature header,
  verified by comparing `--emit-header` output across all four.
- **The attacker is literally the same code.** `BuildSpoofTargets` is
  byte-identical across all five routing-protocol variants, as are the
  willingness manipulation, ANSN poisoning, HELLO/TC link spoofing and the
  `RouteInput` blackhole drop. Detection results are therefore comparable
  across all four defenses.
- **His `OlsrDefenseStrategy` is a strict subset of ours.** Every hook his
  defenses call already existed in our interface, so they compile against it
  unmodified.

## Naming: GCOP and DCFM are the same thing

The class and its files are called **GCOP** — `src/olsr/model/olsr-defense-gcop.{h,cc}`,
`class OlsrDefenseGcop`, TypeId `ns3::olsr::OlsrDefenseGcop` — while everything
user-facing says **DCFM**: the branch, the manifest, the harness
(`olsr-dcfm-eval-mitigation.cc`) and the `defense_variant=DCFM-OLSR` recorded in
every output directory.

They are one defense. GCOP (the depth-2 BFS fictitious-node placement,
Algorithm 1 of the paper) is the mechanism at its core; DCFM is the name of the
overall approach. Nothing was renamed, because renaming the class would change
its TypeId string and break his harness.

## Per-branch trimming

His tree compiled both his defenses at once, since he only ever swapped the
routing protocol. Here each branch carries **only its own defense**: the other
defenses' sources are removed and `src/olsr/CMakeLists.txt` lists just the
strategy interface plus the one defense. That was verified safe — each harness
references only its own class (the single `OlsrWatchdogDefense` mention in the
DCFM harness is a changelog comment).

A side effect worth knowing: on these two branches `src/olsr/model/defense/` is
gone, so CMake installs `model/olsr-repositories.h` — the copy the code actually
includes — instead of the duplicate under `defense/` that `trust-defense` still
has. See [HANDOFF.md](HANDOFF.md#known-issues).
