# Defenses against blackhole attacks in OLSR

An ns-3 research fork that implements, instruments and evaluates **four published
defenses** for OLSR against an attacker that spoofs links to win MPR selection
and then drops the traffic routed through it.

The work also produces a labelled **machine-learning dataset**: per-window
network observations collected from a single listening radio, labelled with
whether an attack was active and whether the attacker was on the path. All four
defenses emit the **same 22-column schema**, so their datasets are directly
comparable.

| | Defense | Paper | Branch | Author |
|---|---|---|---|---|
| 1 | **TRUST-OLSR** | Adnane, Bidan & de Sousa — *Trust-based security for the OLSR routing protocol*, Computer Communications 36 (2013) | [`trust-defense`](#branches) | Oded Ofek |
| 2 | **FPNT-OLSR** | Tan, Li & Dong — *Trust based routing mechanism for securing OLSR-based MANET*, Ad Hoc Networks 30 (2015), pp. 84–98 | [`fpnt-defense`](#branches) | Oded Ofek |
| 3 | **DCFM-OLSR** | Schweitzer et al. — *Achieving MANET protection without the use of superfluous fictitious nodes*, Computer Communications (2024) | [`dcfm-defense`](#branches) | Hananel Kahana |
| 4 | **Watchdog-OLSR** | Baiad, Otrok, Muhaidat & Bentahar — *Cooperative Cross Layer Detection for Blackhole Attack in VANET-OLSR*, IEEE IWCMC (2014) | [`watchdog-defense`](#branches) | Hananel Kahana |

---

## Start here

```bash
./tools/olsr-research.sh doctor
```

Then pick a defense and produce real output:

```bash
./tools/olsr-research.sh use trust
```

```bash
./tools/olsr-research.sh smoke
```

That is the whole loop. `use` switches branch, reconfigures and builds; `smoke`
runs five simulations and prints the resulting CSV header. Swapping defense is
`./tools/olsr-research.sh use <trust|fpnt|dcfm|watchdog>` — nothing else to
remember, and no files to copy by hand.

> **One thing worth knowing before you run anything.** The TRUST harness's own
> command-line defaults leave two of the paper's three detection mechanisms
> switched off, which drops detection to roughly 0.1%. `olsr-research.sh`
> applies the correct flags automatically from `tools/defense.manifest`, so you
> only hit this if you invoke the harness by hand. See
> [docs/RUNNING.md](docs/RUNNING.md#the-trust-default-flags-trap).

## Documentation

| Document | What is in it |
|---|---|
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Clone to first dataset, copy-pasteable. Read this first. |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How each of the four defenses is built, the attacker model, what was changed in stock OLSR, and why the defenses live on separate branches. |
| [docs/RUNNING.md](docs/RUNNING.md) | Full reference for the runner and all four harnesses: every flag, the output layout, resumability, the TRUST flags trap. |
| [docs/SCHEMA.md](docs/SCHEMA.md) | The LISTENER-17 feature schema, column by column, with its documented caveats. |
| [docs/DATASETS.md](docs/DATASETS.md) | Manifest of the generated batches and the exact command that reproduces each. |
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

- **`master`** — the shared base: the attacker model, the tooling and this
  documentation. No defense harness, and **not a branch to generate data from**
  (see below).
- **`trust-defense`** — adds `src/olsr/model/olsr-trust-defense.*` and the
  `src/olsr/model/defense/` module set.
- **`fpnt-defense`** — adds `src/olsr/model/olsr-defense-fpnt.*`.
- **`dcfm-defense`** — adds `src/olsr/model/olsr-defense-gcop.*`.
- **`watchdog-defense`** — adds `src/olsr/model/olsr-watchdog-defense.*`.

Each defense branch carries **only its own defense**, and each modifies the core
OLSR files in ways the others contradict, so they cannot coexist in one working
tree — hence one branch each.
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#why-four-branches) sets out exactly
what conflicts. `tools/` and `docs/` are byte-identical on all four defense
branches — the only per-branch file is `tools/defense.manifest` — so the
commands above work wherever you are.

> **`master` is on a different ns-3 release than the four defense branches.**
> It is ns-3 `3-dev`; the defense branches are all `3.47`, which is what the
> code was written and measured against. `master` also still carries the
> obsolete pre-LISTENER-17 feature collector. It is fine as the home for shared
> tooling and docs, and `doctor` refuses to run datasets there, but do not build
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
  olsr_window_features.h      the LISTENER-17 feature collector
                              (byte-identical on all four branches -- this is
                              what makes the four datasets comparable)
src/olsr/                 the protocol, the attacker, and this branch's defense
```

Generated datasets are **not** in git — they are hundreds of megabytes. See
[docs/DATASETS.md](docs/DATASETS.md) for what exists and how to regenerate it.

## Requirements

A working ns-3.47 build environment (g++ or clang++, cmake, python3), plus
`bash >= 4.3` and `flock` for the batch runner. `./tools/olsr-research.sh doctor`
checks all of it and tells you what is missing.
