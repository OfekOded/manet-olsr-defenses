# Defenses against blackhole attacks in OLSR

An ns-3 research fork that implements, instruments and evaluates **four published
defenses** for OLSR against an attacker that spoofs links to win MPR selection
and then drops the traffic routed through it.

It also produces a labelled **machine-learning dataset**: per-window network
observations collected from a single listening radio, labelled with whether an
attack was active and whether the attacker was on the path. All four defenses
emit the **same 22-column schema** and run against **the same attacker code**,
so their results are directly comparable.

| | Defense | Paper | Branch | Author |
|---|---|---|---|---|
| 1 | **TRUST-OLSR** | Adnane, Bidan & de Sousa — *Trust-based security for the OLSR routing protocol*, Computer Communications 36 (2013) | `trust-defense` | Oded Ofek |
| 2 | **FPNT-OLSR** | Tan, Li & Dong — *Trust based routing mechanism for securing OLSR-based MANET*, Ad Hoc Networks 30 (2015), pp. 84–98 | `fpnt-defense` | Oded Ofek |
| 3 | **DCFM-OLSR** | Schweitzer, Cohen, Hirst, Dvir & Stulman — *Achieving MANET protection without the use of superfluous fictitious nodes*, Computer Communications 229 (2025), 107978 | `dcfm-defense` | Hananel Kadron |
| 4 | **Watchdog-OLSR** | Baiad, Otrok, Muhaidat & Bentahar — *Cooperative Cross Layer Detection for Blackhole Attack in VANET-OLSR*, IEEE IWCMC (2014); journal extension in Vehicular Communications 5 (2016) | `watchdog-defense` | Hananel Kadron |

---

## The three repositories

This project is split across three public repositories. Each one's README carries this same table.

| Repository | What it holds | Start with |
|---|---|---|
| [**OfekOded/Documentation**](https://github.com/OfekOded/Documentation) | The project report — 50 chronological steps, from the kick-off meeting to the handover — and its build system | [`HANDOFF.md`](https://github.com/OfekOded/Documentation/blob/main/HANDOFF.md) |
| [**OfekOded/manet-olsr-defenses**](https://github.com/OfekOded/manet-olsr-defenses) | The ns-3.47 code: the black-hole attacker, the four defenses (one branch each), the simulation harnesses and the dataset generator | [`docs/QUICKSTART.md`](https://github.com/OfekOded/manet-olsr-defenses/blob/master/docs/QUICKSTART.md) |
| [**hananelk26/ML-for-NS3**](https://github.com/hananelk26/ML-for-NS3) | The learning pipelines, the committed datasets, and every result the report quotes | [`README.md` §8 — the first run](https://github.com/hananelk26/ML-for-NS3#8-how-to-run-it) |

This repository is the middle row: it produces the data. Everything that learns from it is
in the ML repository, and the report records what was found and how.

---

## Getting the code

```bash
git clone https://github.com/OfekOded/manet-olsr-defenses.git
```

```bash
cd manet-olsr-defenses
```

You land on `master`, which holds the shared tooling and this documentation. The
four defenses live on their own branches — the `use` command below switches and
builds in one step, so you never need to check one out by hand.

## Start here

```bash
./tools/olsr-research.sh doctor
```

Pick a defense and produce real output:

```bash
./tools/olsr-research.sh use trust
```

```bash
./tools/olsr-research.sh smoke
```

That is the whole loop. `use` switches branch, reconfigures and builds; `smoke`
runs five simulations and prints the resulting CSV header. Switching defense is
`./tools/olsr-research.sh use <trust|fpnt|dcfm|watchdog>` — nothing else to
remember, and **no files to copy by hand**.

> **Worth knowing before you run anything.** The TRUST harness's own
> command-line defaults leave two of the paper's three detection mechanisms
> switched off, which drops detection to roughly 0.1%. `olsr-research.sh`
> applies the correct flags automatically from `tools/defense.manifest`, so you
> only hit this by invoking the harness by hand. See
> [docs/RUNNING.md](docs/RUNNING.md#the-trust-default-flags-trap).

## What the experiment measures

Fifty OLSR nodes in a 750×1000 m field. One node is malicious: it advertises
`WILL_ALWAYS` willingness, claims symmetric links to real nodes it is not
actually connected to, inflates its ANSN so its bogus topology wins — and then,
having earned a place on other nodes' routes, drops the data traffic.

Each run is measured in **four 40-second windows**, a 2×2 design over
defense × attack:

| Window | Scenario | defense | attack |
|---|---|---|---|
| 60–100 s | `baseline` | off | off |
| 160–200 s | `attack_only` | off | on |
| 260–300 s | `defense_only` | on | off |
| 360–400 s | `defense_vs_attack` | on | on |

So one accepted run yields four labelled feature rows from one topology and one
RNG stream — which is what makes the within-run comparison meaningful.
Measurements come from a **single radio in promiscuous mode**, never a
network-wide oracle. See [docs/SCHEMA.md](docs/SCHEMA.md).

## Common tasks

| I want to… | Command |
|---|---|
| Check my setup | `./tools/olsr-research.sh doctor` |
| Switch defense | `./tools/olsr-research.sh use dcfm` |
| Rebuild after an edit | `./tools/olsr-research.sh build` |
| Prove it works (~2 min) | `./tools/olsr-research.sh smoke` |
| One dataset batch | `./tools/olsr-research.sh run -n 2000 -j 12` |
| …with node mobility | `./tools/olsr-research.sh run --mobile -n 2000 -j 12` |
| Both canonical batches, in the background | `./tools/olsr-research.sh batch -n 2000 -j 12 --detach` |
| Run the ns-3 test suites | see [docs/RUNNING.md](docs/RUNNING.md#running-the-ns-3-test-suites) |
| See every option | `./tools/olsr-research.sh help` |

Batches are **resumable** — the runner keeps a seed ledger and appends, so
re-running the same command after an interruption continues where it stopped.

## Documentation

| Document | What is in it |
|---|---|
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Clone to first dataset, copy-pasteable. Read this first. |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How each of the four defenses is built, the attacker model, what was changed in stock OLSR, and why the defenses live on separate branches. |
| [docs/RUNNING.md](docs/RUNNING.md) | Full reference for the runner and all four harnesses: every flag, the output layout, resumability, the TRUST flags trap. |
| [docs/SCHEMA.md](docs/SCHEMA.md) | The 22-column feature schema, column by column, with its documented caveats. |
| [docs/DATASETS.md](docs/DATASETS.md) | Which batches exist, which do not, and the exact command that reproduces each. |
| [docs/PARTNER-IMPORT.md](docs/PARTNER-IMPORT.md) | Where DCFM and Watchdog came from, which commits, and what was deliberately left behind. |
| [docs/HANDOFF.md](docs/HANDOFF.md) | Project status, verified results, known issues, and suggested next steps. |
| [README-ns3.md](README-ns3.md) | The upstream ns-3 README (build system, general ns-3 usage). |

## Branches

```
                     tooling + docs (shared)
master ──●──────────────────┐
   (ns-3 3-dev)             │
                            │
ns-3.47 merge ──●───────────┼──●── trust-defense      TRUST-OLSR
                            ├──●── fpnt-defense       FPNT-OLSR
                            ├──●── dcfm-defense       DCFM-OLSR
                            └──●── watchdog-defense   Watchdog-OLSR
```

- **`master`** — shared base: the tooling and this documentation. It still
  carries an early TRUST defense and its pre-LISTENER-17 harness, and is **not a
  branch to generate data from** (see the warning below).
- **`trust-defense`** — adds `src/olsr/model/olsr-trust-defense.*` and the
  `src/olsr/model/defense/` module set.
- **`fpnt-defense`** — adds `src/olsr/model/olsr-defense-fpnt.*`.
- **`dcfm-defense`** — adds `src/olsr/model/olsr-defense-gcop.*`.
- **`watchdog-defense`** — adds `src/olsr/model/olsr-watchdog-defense.*`.

Each defense branch carries **only its own defense**, and each modifies the core
OLSR files in ways the others contradict, so they cannot coexist in one working
tree — hence one branch each.
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#why-four-branches) sets out exactly
what conflicts.

**The design rule:** `tools/` and `docs/` are byte-identical on all four defense
branches; the only per-branch file is `tools/defense.manifest`, which declares
the defense, its paper, its build target, the flags a faithful run needs and its
seed ranges. Shared changes are made on `master` and merged down — never edited
per-branch, or that invariant breaks.

> **`master` is on a different ns-3 release than the four defense branches.**
> It is ns-3 `3-dev`; the defense branches are all `3.47`, which is what the code
> was written and measured against. `master` also still carries an early TRUST
> defense, its harness (`HARNESS_VERSION 2.4.0`) and the obsolete pre-LISTENER-17
> feature collector. It is fine as the home for shared tooling
> and docs, and `doctor` refuses to generate data there, but do not build
> experiments on it. See [docs/HANDOFF.md](docs/HANDOFF.md#known-issues).

## Layout

```
tools/
  olsr-research.sh        the entry point — doctor / use / build / smoke / run / batch
  run_simulations.sh      the low-level resumable batch runner
  defense.manifest        per-branch: which defense, which flags, which seeds
docs/                     everything in the table above
scratch/
  olsr-*-eval-mitigation.cc   the evaluation harness (one per defense branch)
  olsr_window_features.h      the feature collector — byte-identical on all four
                              branches, which is what makes the four datasets
                              comparable
src/olsr/                 the protocol, the attacker, and this branch's defense
```

Generated datasets are **not** in this repository. Their inputs are committed to
[`hananelk26/ML-for-NS3`](https://github.com/hananelk26/ML-for-NS3), under
`defense_ml/defense_ml_project/dataset_final/`;
[docs/DATASETS.md](docs/DATASETS.md) says which batch is where and how to
regenerate each one.

## Status

All four defenses are implemented and build cleanly. TRUST and FPNT have full
batches generated from their branches here. The DCFM and Watchdog LISTENER-17
data the report uses was generated in the partner's original repository, before
the import; their harnesses here are verified, and full batches from these
branches have not been generated —
[docs/DATASETS.md](docs/DATASETS.md#what-is-missing) has the commands and the
reserved seed ranges.

Known issues, including two that will bite on day one, are listed honestly in
[docs/HANDOFF.md](docs/HANDOFF.md#known-issues). Read that before drawing
conclusions from anything here.

## Requirements

An ns-3.47 build environment (g++ or clang++, cmake, python3), plus
`bash >= 4.3` and `flock` for the batch runner. `./tools/olsr-research.sh doctor`
checks all of it and names whatever is missing.

## Credits

Final project at the Jerusalem College of Technology by **Oded Ofek**
(TRUST-OLSR, FPNT-OLSR) and **Hananel Kadron** (DCFM-OLSR, Watchdog-OLSR),
supervised by Nadav Schweitzer and Dror Mughaz. Built on [ns-3](https://www.nsnam.org/) 3.47; the
OLSR module derives from the implementation by Francisco J. Ros and
Gustavo J. A. M. Carneiro. Licensed GPL-2.0-only, as ns-3 is.
