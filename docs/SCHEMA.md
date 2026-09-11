# The LISTENER-17 dataset schema

The authoritative specification is the 94-line comment block at the top of
[`scratch/olsr_window_features.h`](../scratch/olsr_window_features.h) (schema
v6, `HEADER_VERSION 8`). That file is **byte-identical on `trust-defense` and
`fpnt-defense`**, which is what makes the two defenses' datasets directly
comparable. This page summarises it; where the two disagree, the header wins.

## The defining constraint

> Every value is computable by ONE node with a radio in promiscuous mode.
> Nothing reads another node's internal state.

This is the point of the schema. Features are what a single passive listener
can actually measure, not what the simulator knows. Anything privileged lives
in `windows_oracle.csv` and must never enter a feature matrix.

Which node listens is set by `--listenerNode`; the default (-1) means "the first
attacker's node id".

## Four files per batch

| File | Role |
|---|---|
| `windows_features.csv` | **X** — 5 identity columns + the 17 features |
| `windows_labels.csv` | **y** — what was actually happening in that window |
| `windows_oracle.csv` | ground truth and diagnostics. **Never an ML input.** |
| `runs.csv` | one row per accepted run: the full configuration it ran under |

One accepted run produces four feature rows, one per measurement window
(see [RUNNING.md](RUNNING.md#what-one-run-actually-does)).

### `windows_features.csv`

```
run_id, scenario, window_start, window_end, window_duration_s,
TcMessageRate, AverageAdvertisedLinksPerTCMessage, AverageMprCount,
AverageHopCount, MidMessageRate, HnaMessageRate, RoutingOverheadBytesRatio,
NormalizedRoutingLoad, DataPacketRate, Throughput, AvgTxPacketSize,
AvgFlowDuration, FlowDurationStd, AvgFlowThroughput, FlowThroughputStd,
AvgTxBytesPerFlow, AvgTxPacketsPerFlow
```

Join to the labels on `(run_id, scenario, window_start, window_end)`.

### `windows_labels.csv`

```
run_id, scenario, window_start, window_end,
defense_enabled, attack_enabled, attacker_on_path, num_attackers_label
```

`scenario` is one of `baseline`, `attack_only`, `defense_only`,
`defense_vs_attack` — the 2×2 of `defense_enabled` × `attack_enabled`.

## The 17 features

| # | Column | Formula |
|---|---|---|
| | **Control plane — OLSR** | |
| 1 | `TcMessageRate` | `tcUniqueCount / Duration` |
| 2 | `AverageAdvertisedLinksPerTCMessage` | `tcRows / tcCount` |
| 3 | `AverageMprCount` | `SumAdvertisedLinks / \|addrsSeen\|` |
| 4 | `AverageHopCount` | `tcHopSum / tcCount` |
| 5 | `MidMessageRate` | `midCount / Duration` |
| 6 | `HnaMessageRate` | `hnaCount / Duration` |
| | **Load and overhead** | |
| 7 | `RoutingOverheadBytesRatio` | `olsrBytes / dataBytes` |
| 8 | `NormalizedRoutingLoad` | `olsrFrames / dataFrames` |
| | **Data plane** | |
| 9 | `DataPacketRate` | `frames / Duration` |
| 10 | `Throughput` | `dataBytes * 8 / Duration` |
| 11 | `AvgTxPacketSize` | `bytes / frames` |
| | **Per perceived source** | |
| 12 | `AvgFlowDuration` | mean over sources of `(last − first)` |
| 13 | `FlowDurationStd` | population std of the same |
| 14 | `AvgFlowThroughput` | `(dataBytes / nSrc) * 8 / Duration` |
| 15 | `FlowThroughputStd` | population std of per-source bit rates |
| 16 | `AvgTxBytesPerFlow` | `dataBytes / nSrc` |
| 17 | `AvgTxPacketsPerFlow` | `dataFrames / nSrc` |

## Seven things that will mislead you

These are properties of the schema's **parity target** — a reference harness,
`iolsr-tests-corrected.cc`, that this collector deliberately reproduces. Several
of them are counter-intuitive. They are reproduced *on purpose*: diverging would
make these rows incomparable to the reference's. Do not "fix" them without
understanding that consequence.

**(a) HELLO is counted.** A frame enters `frames`/`bytes` before any filtering,
and any UDP/698 frame — HELLO included — lands in `olsrFrames`/`olsrBytes`.

**(b) RTS/CTS/ACK are counted** in `frames`/`bytes`, added before the `IsData()`
test. So feature 9 is a *MAC frame* rate, and feature 11 is pulled down by tiny
control frames.

**(c) "Source" means the IPv4 source address of every IPv4 frame,** including
OLSR broadcasts. Every node broadcasts HELLO/TC under its own address, so every
audible neighbour is a distinct "source". **Features 12–17 measure neighbour
visibility, not application flows** — despite their names.

**(d) `dataBytes`/`dataFrames` count all IPv4 traffic, OLSR included.** Feature
10 is called `Throughput` but is really the IP-layer air bitrate, and in a
typical window it is dominated by control traffic.

**(e) Features 2 and 4 are not de-duplicated; feature 1 is.** `tcRows`,
`tcCount` and `tcHopSum` accumulate over every heard copy of every TC. Only
`tcUniqueCount` dedupes by `(originator, msgSeq)`.

**(f) `SumAdvertisedLinks` is not `tcRows`.** It is the sum, over each
originator heard, of the advertised-link count of that originator's *most
recent* TC.

**(g) Feature 8 is a share, not a ratio.** `NormalizedRoutingLoad` is
`olsrFrames / dataFrames` — OLSR frames as a fraction of all IPv4-carrying
frames. The earlier definition divided by `dataFrames − olsrFrames`, which is
zero whenever the listener heard no non-OLSR data frame (64.3% of static and
51.1% of mobile reference rows). The pipeline caught the `ZeroDivisionError` and
stored `0.0`, making "all control, no data" indistinguishable from its exact
opposite. The share form is bounded in [0,1] and strictly monotone in the old
ratio (`s = r/(1+r)`), so row ordering is preserved and the collapsed rows now
take `1.0`.

## Two features are always zero in this experiment

`MidMessageRate` (5) and `HnaMessageRate` (6) are **structurally zero** in every
row of every batch, for all four defenses.

That is not a fault. MID messages are only generated by nodes with more than one
interface, and HNA messages only by nodes acting as gateways to an external
network. The topology used here — 50 single-interface nodes, no host-network
associations — produces neither, so the listener never hears one.

The columns are kept so the schema stays identical to its parity reference and
so a topology that *does* use MID or HNA drops straight in. **For model
training on the current batches they carry no information and should be
dropped**, along with any other zero-variance column your split happens to
produce. Measured on a 121-run verification sweep (2026-09-11): 15 of the 17
features vary, these two do not.

## NaN

Feature 8 is `NaN` when the listener heard no IPv4-carrying frame at all in the
window — genuinely undefined, as opposed to `0.0`, which is a legal measured
value.

**Drop those rows in analysis; do not impute them.** The reference measured them
at 0.000% of static and 0.068% of mobile rows. The 121-run verification sweep
produced no NaN at all.

## Versioning

Three version markers travel with every batch, all in `defense_params.txt`:

```
harness_version=3.0.0      the evaluation harness
header_version=8           the CSV schema
defense_variant=Trust-OLSR the defense that produced it
```

`tools/run_simulations.sh` refuses to append to a CSV whose header does not
match what the current binary emits (exit code 3), so a schema change cannot
silently corrupt an existing dataset. To see the current headers:

```bash
./build/scratch/*olsr-trust-eval-mitigation* --emit-header
```

## Not in this repository

The comment block references two external artifacts that were never committed
here:

- `iolsr-tests-corrected.cc` — the parity reference
- `arm_spec.py` — the specification that defined feature 8, corrected 2026-08-28

Parity against the reference therefore **cannot be re-verified from this repo
alone**. See [HANDOFF.md](HANDOFF.md#known-issues).
