# Trust-based defenses against blackhole attacks in OLSR

An ns-3 research fork that implements, instruments and evaluates **two published
trust-based defenses** for OLSR against an attacker that spoofs links to win MPR
selection and then drops the traffic routed through it.

The work also produces a labelled **machine-learning dataset**: per-window
network observations collected from a single listening radio, labelled with
whether an attack was active and whether the attacker was on the path.

| | Defense | Paper | Branch |
|---|---|---|---|
| 1 | **TRUST-OLSR** | Adnane, Bidan & de Sousa — *Trust-based security for the OLSR routing protocol*, Computer Communications 36 (2013) | [`trust-defense`](#branches) |
| 2 | **FPNT-OLSR** | Tan, Li & Dong — *Trust based routing mechanism for securing OLSR-based MANET*, Ad Hoc Networks 30 (2015), pp. 84–98 | [`fpnt-defense`](#branches) |

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
runs five simulations and prints the resulting CSV header. Swapping to the other
defense is `./tools/olsr-research.sh use fpnt`.

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
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How the two defenses are built, the attacker model, what was changed in stock OLSR, and why the defenses live on separate branches. |
| [docs/RUNNING.md](docs/RUNNING.md) | Full reference for the runner and both harnesses: every flag, the output layout, resumability, the TRUST flags trap. |
| [docs/SCHEMA.md](docs/SCHEMA.md) | The LISTENER-17 feature schema, column by column, with its documented caveats. |
| [docs/DATASETS.md](docs/DATASETS.md) | Manifest of the eight generated batches and the exact command that reproduces each. |
| [docs/HANDOFF.md](docs/HANDOFF.md) | Project status, verified results, known issues, and suggested next steps. |
| [README-ns3.md](README-ns3.md) | The upstream ns-3 README (build system, general ns-3 usage). |

## Branches

```
                       tooling + docs (shared)
master  ───────●─────────────────┬──────────────────
                                 ├──●── trust-defense   TRUST-OLSR
                                 └──●── fpnt-defense    FPNT-OLSR
```

- **`master`** — the shared base: stock ns-3.47, the attacker model, the
  tooling and this documentation. No defense harness.
- **`trust-defense`** — TRUST-OLSR. Adds `src/olsr/model/olsr-trust-defense.*`
  and the `src/olsr/model/defense/` module set.
- **`fpnt-defense`** — FPNT-OLSR. Adds `src/olsr/model/olsr-defense-fpnt.*`.

The two defenses modify the same core OLSR files in incompatible ways, so they
cannot coexist in one working tree — hence one branch each.
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#why-two-branches) explains exactly
what conflicts. `tools/` and `docs/` are identical on all three branches, so the
commands above work wherever you are.

## Layout

```
tools/
  olsr-research.sh        the entry point — doctor / use / build / smoke / run / batch
  run_simulations.sh      the low-level resumable batch runner
  defense.manifest        per-branch: which defense, which flags, which seeds
docs/                     everything in the table above
scratch/
  olsr-*-eval-mitigation.cc   the evaluation harness (one per defense branch)
  olsr_window_features.h      the LISTENER-17 feature collector (identical on both)
src/olsr/                 the protocol, the attacker, and the defenses
```

Generated datasets are **not** in git — they are hundreds of megabytes. See
[docs/DATASETS.md](docs/DATASETS.md) for what exists and how to regenerate it.

## Requirements

A working ns-3.47 build environment (g++ or clang++, cmake, python3), plus
`bash >= 4.3` and `flock` for the batch runner. `./tools/olsr-research.sh doctor`
checks all of it and tells you what is missing.
