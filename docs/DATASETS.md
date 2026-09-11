# Generated datasets

Datasets are **not stored in git** — the eight batches below are ~198 MB of
CSV plus ~35 000 per-attempt log files. This page is the manifest: what exists,
under exactly which configuration, and the command that regenerates it.

All eight batches completed (`STATUS: ALL BATCHES DONE`,
`BOTH MIXED BATCHES DONE`, `TRUST V2 ALL DONE`).

Schema `header_version=8`, harness `3.0.0`, collector schema v6
(LISTENER-17) — identical across every batch, so all of them are directly
comparable. See [SCHEMA.md](SCHEMA.md).

## The eight batches

| Batch | Defense | Branch | Mobility | Window order | Start seed | Accepted | Feature rows |
|---|---|---|---|---|---|---|---|
| `fpnt_static` | FPNT | `fpnt-defense` | no | canonical | 1 | 2005 | 8020 |
| `fpnt_mobile` | FPNT | `fpnt-defense` | yes | canonical | 2 000 001 | 2010 | 8040 |
| `fpnt_static_mixed` | FPNT | `fpnt-defense` | no | randomized | 10 000 001 | 2010 | 8040 |
| `fpnt_mobile_mixed` | FPNT | `fpnt-defense` | yes | randomized | 12 000 001 | 2009 | 8036 |
| `trust_static` ⚠ | TRUST | `trust-defense` | no | canonical | 4 000 001 | 2010 | 8040 |
| `trust_mobile` ⚠ | TRUST | `trust-defense` | yes | canonical | 6 000 001 | 2009 | 8036 |
| **`trust_static_v2`** | TRUST | `trust-defense` | no | canonical | 4 000 001 | 2012 | 8048 |
| **`trust_mobile_v2`** | TRUST | `trust-defense` | yes | canonical | 6 000 001 | 2009 | 8036 |

All batches: `-n 2000`, `--max-attempts 8000`, `--direct`, 50 nodes,
750×1000 m grid, one attacker (node 2), `spoofCount=5`, 190 m radio range.

### ⚠ `trust_static` and `trust_mobile` are superseded

They were generated with `enable_consistency_rules=0` and
`enable_alert_distribution=0` — the harness CLI defaults — so only Formula 10
was live and detection came out at 0.12% / 0.48%. See
[RUNNING.md](RUNNING.md#the-trust-default-flags-trap).

`trust_static_v2` and `trust_mobile_v2` re-ran them with
`--enableConsistencyRules=1 --enableAlertDistribution=1` and **the same seed
ranges on purpose**, so the defense-off windows come out bit-identical and the
two datasets are comparable window-for-window. Use the `_v2` pair for anything
about TRUST's performance; the originals are only useful as an ablation showing
what the forward monitor achieves alone.

This trap is now closed: `tools/defense.manifest` on `trust-defense` carries
those flags and `tools/olsr-research.sh` applies them automatically.

### The FPNT/TRUST asymmetry

There are `_mixed` (randomized window order) batches for FPNT but **not** for
TRUST. The four canonical batches all used `random_window_order = 0`, which
perfectly confounds window slot position with scenario; the mixed FPNT batches
exist to measure that effect. The equivalent TRUST pair was never run — see
[HANDOFF.md](HANDOFF.md#suggested-next-steps).

## Effective defense parameters

Recorded in each batch's `defense_params.txt`.

**FPNT** (all four batches, i.e. the paper defaults):

```
defense_variant=FPNT-OLSR   redundant_mpr=0          malicious_threshold=0.2
uncertainty_beta=0.6        fading_factor=0.7        max_load=1e+06
max_delay=0.5               cheat_threshold=2        trust_update_interval_s=5
```

**TRUST v2** (`trust_*_v2`):

```
defense_variant=Trust-OLSR      enable_forward_monitor=1
enable_consistency_rules=1      enable_alert_distribution=1
forward_timeout_s=3             check_interval_s=0.25
monitor_data=1                  monitor_tc=1          monitor_relayed_data=0
strict_mac_attribution=0        min_forward_failures=3
mistrust_permanent=0            mistrust_duration_s=60
```

**TRUST v1** (`trust_static`, `trust_mobile`): identical except
`enable_consistency_rules=0` and `enable_alert_distribution=0`.

Generated at commit `f9a2e9702` on `trust-defense`.

## Regenerating

Each batch takes several hours at `-j 12`; the yield is about 0.46 accepted per
attempt, so 2000 accepted runs means roughly 4400 simulations.

```bash
./tools/olsr-research.sh use fpnt
```

```bash
./tools/olsr-research.sh batch -n 2000 -j 12 --detach
```

```bash
./tools/olsr-research.sh batch -n 2000 -j 12 --mixed --detach
```

Then the same for TRUST:

```bash
./tools/olsr-research.sh use trust
```

```bash
./tools/olsr-research.sh batch -n 2000 -j 12 --detach
```

Output goes to `datasets/<batch name>/`, which is git-ignored. Seed ranges come
from `tools/defense.manifest` and match the table above, so a regenerated batch
reproduces the original run-for-run.

Everything is resumable — re-running the same command after an interruption
continues from the seed ledger rather than starting over.

Note that `batch` reproduces the **v2** TRUST configuration, because the
manifest now carries the correct flags. To reproduce the superseded v1 batches
for comparison, bypass the manifest:

```bash
./tools/run_simulations.sh -n 2000 -j 12 --direct --defense trust -o datasets/trust_static_v1 --start-seed 4000001 --max-attempts 8000
```

## Superseded output directories

Two large directories may still exist in a working tree from earlier phases of
the project. Both are git-ignored and **neither should be used**:

| Directory | Size | Why not |
|---|---|---|
| `dataset_final/` | ~444 MB | FPNT only, June 2026, pre-LISTENER-17 schema. The name is misleading — it is neither final nor complete. |
| `simulations/` | ~224 MB | Six batches, May–August 2026, older schema (128- and 69-column collectors). Not comparable to anything current. |

They are safe to delete. Nothing in this repository reads them.
