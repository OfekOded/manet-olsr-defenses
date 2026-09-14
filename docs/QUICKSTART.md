# Quickstart

From a fresh clone to a labelled dataset. Everything here is copy-pasteable.

## 0. Clone

```bash
git clone https://github.com/OfekOded/manet-olsr-defenses.git
```

```bash
cd manet-olsr-defenses
```

The clone lands on `master` — shared tooling and documentation, not a defense
branch. Do not generate data from `master`; `use` (step 1) moves you to a defense
branch.

This repository produces the data. The learning code and the committed datasets
are in [`hananelk26/ML-for-NS3`](https://github.com/hananelk26/ML-for-NS3), and
the project report is in
[`OfekOded/Documentation`](https://github.com/OfekOded/Documentation).

## 0b. Prerequisites

The stock ns-3.47 build requirements (g++ or clang++, cmake, python3), plus
`bash >= 4.3` and `flock`, which the batch runner needs. On Debian/Ubuntu:

```bash
sudo apt install g++ cmake python3 ninja-build
```

Check everything at once:

```bash
./tools/olsr-research.sh doctor
```

`doctor` reports the toolchain, the branch, the manifest, the build state, and
runs the harness self-test. Run it whenever something behaves oddly — it is the
fastest way to find out that you are on the wrong branch or looking at a stale
binary.

## 1. Pick a defense

Each defense lives on its own branch because they compile different `src/olsr`
code. One command switches, reconfigures and builds:

```bash
./tools/olsr-research.sh use trust
```

The four choices are `trust`, `fpnt`, `dcfm` and `watchdog`.

This takes a few minutes the first time. It refuses to run if you have
uncommitted changes, so commit or stash first.

> The `./ns3 configure` step inside `use` is **not** optional and not a
> formality: the set of files in `scratch/` differs between the branches, and
> cmake will not discover a target that did not exist when it last configured.
> If you switch branches by hand, run `./tools/olsr-research.sh build`
> afterwards.

## 2. Prove the chain works

```bash
./tools/olsr-research.sh smoke
```

Five accepted runs, a couple of minutes. It writes to `datasets/smoke_<defense>/`
and then prints the feature-CSV header so you can see the 17 LISTENER columns
immediately. If this passes, everything downstream will work.

## 3. Generate a dataset

One batch — 2000 accepted runs, static topology:

```bash
./tools/olsr-research.sh run -n 2000
```

With node mobility:

```bash
./tools/olsr-research.sh run --mobile -n 2000
```

Both canonical batches for the current defense, one after the other:

```bash
./tools/olsr-research.sh batch -n 2000 -j 8
```

Long runs should go in the background. This is safe to close your terminal on:

```bash
./tools/olsr-research.sh batch -n 2000 -j 8 --detach
```

Output lands in `datasets/<defense>_<static|mobile>/`. Expect roughly 4 feature
rows per accepted run (one per measurement window) — about 8000 rows per batch.

**Runs are resumable.** The runner keeps a seed ledger and appends. If a batch
is interrupted, re-run the same command and it continues from where it stopped
rather than starting over.

## 4. What you get

```
datasets/trust_static/
  windows_features.csv   the ML X-matrix: 17 observable features per window
  windows_labels.csv     the ML y-vector: attack_enabled, attacker_on_path, ...
  windows_oracle.csv     ground truth and diagnostics — NEVER an ML input
  runs.csv               one row per accepted run: full configuration
  probe.csv              per-attempt topology probe
  defense_params.txt     the defense parameters actually in effect
  defense_flags.txt      branch, commit, flags and seed range of this batch
  runner.summary         final counts
  logs/seed_NNNNN.log    one log per attempt
  .runstate/             seed ledger and counters (this is what makes it resumable)
```

`windows_oracle.csv` contains ground truth that an attacker-detecting model
cannot legitimately see. Keep it out of your feature matrix.

Column-by-column meaning: [SCHEMA.md](SCHEMA.md).

## Next

- [RUNNING.md](RUNNING.md) — every flag, and the TRUST default-flags trap
- [DATASETS.md](DATASETS.md) — which batches exist and how to generate the rest
- [ARCHITECTURE.md](ARCHITECTURE.md) — how the code is organised
- [HANDOFF.md](HANDOFF.md) — project status and known issues
