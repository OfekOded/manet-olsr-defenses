# Architecture

How this fork is put together: the attacker, the defense abstraction, the two
defense implementations, and why they cannot share a branch.

## The experiment

A 50-node OLSR network in a 750×1000 m grid. One node (node 2 by default) is
malicious. It does not simply drop packets — it first makes itself attractive:

1. **Willingness manipulation** — advertises `WILL_ALWAYS` so neighbours prefer
   it as MPR.
2. **Link spoofing** — claims symmetric links to nodes it has heard of but is
   not actually connected to, in both HELLO and TC messages. The targets are
   real addresses learned passively, not fabricated ones, which makes the claim
   hard to reject locally.
3. **Topology poisoning** — inflates its ANSN so its bogus topology wins over
   legitimate updates.
4. **Blackhole** — having won a place on other nodes' routes, it drops the data
   plane traffic in `RouteInput`.

A single node listens in promiscuous mode and records what it can observe. The
run is measured across four windows covering defense × attack (see
[RUNNING.md](RUNNING.md#what-one-run-actually-does)); the result is a labelled
dataset (see [SCHEMA.md](SCHEMA.md)) plus per-run detection metrics.

The attacker lives in `src/olsr/model/olsr-routing-protocol.cc` behind twenty
`// SECURITY RESEARCH EXTENSION:` banners — grep for that string to find every
place stock OLSR was touched. Attacker behaviour is identical on both defense
branches, which is what makes the two defenses comparable.

Key attacker entry points:

| Location | What it does |
|---|---|
| `GetTypeId` (~:234) | `IsMalicious`, `SpoofedLinksCount` attributes |
| `BuildSpoofTargets` (~:1923) | picks real learned addresses to spoof links to |
| `SendHello` (~:2036, ~:2138) | willingness manipulation, HELLO link spoofing |
| `SendTc` (~:2231, ~:2286) | ANSN poisoning, TC-level link spoofing |
| `RouteInput` (~:3496) | the blackhole drop itself |
| `~:2322` | self-topology monitoring, for ground truth only |

## The defense abstraction

`src/olsr/model/olsr-defense-strategy.h` declares `OlsrDefenseStrategy`, an
ns-3 `Object` that `RoutingProtocol` holds one of
(`Ptr<OlsrDefenseStrategy> m_defenseStrategy`, selected by the `DefenseStrategy`
attribute). A no-op `OlsrDefenseNull` is the default, which is how the harness
turns the defense off for half the measurement windows without rebuilding.

The routing protocol calls into the strategy at fixed points — packet
forwarded, HELLO received, TC received, periodic timer — and asks it questions,
principally "is this node mistrusted?". Detection and response are deliberately
separate: the strategy decides *who* is untrustworthy; the routing protocol
decides what to do about it.

Most of the interface is **non-pure virtual with a safe default**, so a defense
that does not participate in some mechanism needs no code for it at all.

## TRUST-OLSR (`trust-defense`)

Adnane, Bidan & de Sousa, *Computer Communications* 36 (2013).

```
src/olsr/model/olsr-trust-defense.{h,cc}      the strategy: 24 attributes, hook dispatch
src/olsr/model/defense/
  olsr-trust-config.h        one config struct; every field documented
  olsr-forward-monitor.*     Formula (10) — the blackhole core: wait to overhear
                             an MPR re-forward, and notice when it never comes
  olsr-consistency-rules.*   Formulas (6), (7), (8), (9a), (9b), (12)
  olsr-trust-state.*         the mistrusted-node set MN_x; Formula (15) verdict
  olsr-provable-identity.*   §6 / Formulas (13), (14): signed PROOF messages
  olsr-alert-distributor.*   §7 alert re-broadcast
  olsr-repositories.h        (a duplicate of the stock file — see HANDOFF.md)
```

Two modelling shortcuts are documented in the source and worth knowing:

- The §7 alert bus is **idealized** — a process-wide `OlsrTrustBus` under an
  idealized-authentication assumption, not a real protocol exchange.
- The §6 RSA keys are **simulation-grade**: the modulus is small. They are not
  secure and are not meant to be.

Provable identity is off by default and the harness keeps it off; at this scale
it costs more than it gives.

Detection and response are separated in a way worth preserving: the paper
reports *exact* and *partial* detection separately (Table 3), so the interface
has both `GetMistrusted()` and `GetPartialMistrusted()`.

## FPNT-OLSR (`fpnt-defense`)

Tan, Li & Dong, *Ad Hoc Networks* 30 (2015), pp. 84–98.

```
src/olsr/model/olsr-defense-fpnt.{h,cc}    ~1950 lines, one class
```

A fuzzy Petri net. Fifteen places and eleven transitions encode the paper's
seven fuzzy rules; the `W_T` and `U_MAT` matrices at the top of the `.cc` are
annotated column by column against the paper's Fig. 2. The `.cc` is organised
into banner-delimited sections that map onto the paper: metric collection
(§5.1), the trust reasoning cycle (Algorithm 1, Eqs. 1–5), deviation rules D1
and D2, normalization (Definition 10), the slander filter, and the matrix
operators (Definitions 5–7).

It also replaces route computation: `RunTrustDijkstra()` (Algorithm 2)
implements the paper's principle that **trust routing never removes a node from
the topology — it only makes paths through it unattractive** (§2.3). This is a
real behavioural difference from TRUST, which excludes mistrusted nodes.

Thirteen ns-3 attributes expose the tunables. Four of them are explicitly
marked *"NOT in the paper"* (`StickyEvidence`, `DemoteUnverifiedNodes`,
`RollbackOnMacFailure`, and the `MaliciousThreshold` accessor), all defaulting
to the paper's behaviour. The file states the rule it follows:

> Deviations from the paper are never silent: every behavior this class adds
> beyond the paper's text sits behind an ns-3 attribute whose default value
> reproduces the paper.

`FPNT-OLSR(R)` — the redundant-MPR-coverage variant of §5.3 — is available via
`--redundantMpr` and is off by default.

## Why two branches

The two defenses are not merely different classes. They make **incompatible
edits to the same core OLSR files**, so they cannot be built into one binary as
things stand.

**1. `olsr-header.h` — the message format.** TRUST adds a fifth OLSR message
type and a payload for it:

```cpp
PROOF_MESSAGE = 5,     // §6.2 signed neighbourhood declaration, never flooded
struct Proof { ... };  // plus a member in MessageHeader's anonymous union
```

FPNT deletes all of that and instead extends the TC message:

```cpp
struct EvaluationVector { uint8_t trust, distrust, uncertain, reserved; };
// ... std::vector<EvaluationVector> evaluationVectors;  inside struct Tc
bool CarriesEvaluationVectors() const;   // Serialize/GetSerializedSize must agree
```

These are textually conflicting but **semantically orthogonal** — a new message
type and a TC payload extension do not compete for the same bytes. Merging them
is hand-resolvable, not a redesign.

**2. HELLO forwarding — a genuine behavioural conflict.** TRUST permits HELLO
re-flooding (gated on hop count) so §7 alerts can propagate. FPNT restores RFC
3626's rule that a HELLO is never forwarded. Both branches would need that gate
made conditional on which strategy is loaded.

**3. The strategy interface diverged, but only additively.** FPNT added
`GetEvaluationVectors()`, `OnRecvEvaluationVectors()`, `GetNodeTrust()`,
`IsTrustRoutingEnabled()` and a 4-argument `OnDataPacketForwarded` overload;
TRUST added `GetPartialMistrusted()`, `OnHelloGenerated()` and `OnRecvProof()`.
Every one of those is non-pure with a safe default, so unioning the two
interfaces would compile and neither defense would need changing.

So unification is feasible — items 1 and 3 are mechanical, item 2 needs a design
decision — but it was not attempted, because it would put the comparability of
the existing datasets at risk for no scientific gain. The branches are the
record of what was actually run. What the tooling does instead is make switching
between them a single command that cannot be misconfigured.

`master` is the shared base: stock ns-3.47 plus the attacker model, plus `tools/`
and `docs/`, and no defense. `tools/` and `docs/` are byte-identical on all three
branches; only `tools/defense.manifest` differs.

## The harness

`scratch/olsr-trust-eval-mitigation.cc` and
`scratch/olsr-fpnt-eval-mitigation.cc` are the evaluation programs — one per
branch, about 2700 lines each, and largely a copy of one another. They build the
topology, install the attacker and the defense, drive the four measurement
windows, and emit the CSVs.

They share `scratch/olsr_window_features.h`, the feature collector, which is
**byte-identical on both branches**. That is deliberate and load-bearing: it is
what lets the two defenses' datasets be compared at all. If you change it,
change it on both branches in the same commit.

Both harnesses accept `--self-test` (a cycle-counter self-check that must print
`ALL PASS`; the tooling runs it after every build) and `--emit-header` (prints
the CSV headers and exits, which is how the runner detects schema drift).

The top of each harness carries a long changelog of audit ticket IDs
(`LEAK-001`, `OBS-004`, `WIN-003`, `SL-2`, `DIR-001`, …). It is history, not
instructions — the "how to run" block is above it.
