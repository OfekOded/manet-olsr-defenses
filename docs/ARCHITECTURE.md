# Architecture

How this fork is put together: the attacker, the defense abstraction, the four
defense implementations, and why each needs its own branch.

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

The attacker lives in `src/olsr/model/olsr-routing-protocol.cc` behind
`// SECURITY RESEARCH EXTENSION:` banners (18 to 20 in the `.cc`, depending on the
branch) — grep for that string to find every place stock OLSR was touched. Attacker behaviour is identical on all four
defense branches — `BuildSpoofTargets` and the rest of the attack code are
byte-identical across every routing-protocol variant — which is what makes the
four defenses comparable.

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

Each branch carries its own copy of `olsr-defense-strategy.{h,cc}`. They are not
identical: TRUST and FPNT each added hooks their own mechanism needs. The two
imported defenses call only the original common set, which is why they compiled
here unmodified. Keeping the interface per-branch was a deliberate choice — an
early attempt at one shared interface for every defense did not survive contact
with what the papers actually require.

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

Twelve ns-3 attributes expose the tunables. Four sit in a block headed "Beyond
the paper": `StickyEvidence`, `DemoteUnverifiedNodes` and
`RollbackOnMacFailure` are marked *"NOT in the paper"* and default off, so the
defaults reproduce the paper; `MonitorTcForwarding` *is* in the paper (§5.1.B)
but also defaults off, because its obligation has to be inferred — see
[HANDOFF.md](HANDOFF.md#suggested-next-steps). The file states the rule it follows:

> Deviations from the paper are never silent: every behavior this class adds
> beyond the paper's text sits behind an ns-3 attribute whose default value
> reproduces the paper.

`FPNT-OLSR(R)` — the redundant-MPR-coverage variant of §5.3 — is available via
`--redundantMpr` and is off by default.

## DCFM-OLSR (`dcfm-defense`)

Schweitzer, Cohen, Hirst, Dvir & Stulman, *Achieving MANET protection without the
use of superfluous fictitious nodes*, Computer Communications 229 (2025), 107978.
Implemented by Hananel Kadron as a port of the supervisor's reference
implementation; see [PARTNER-IMPORT.md](PARTNER-IMPORT.md).

```
src/olsr/model/olsr-defense-gcop.{h,cc}    class OlsrDefenseGcop, ~1040 lines
```

> **Naming.** The class and files say **GCOP**; the branch, manifest, harness and
> every `defense_variant=DCFM-OLSR` record say **DCFM**. Same defense. GCOP is
> the paper's fictitious-node placement algorithm, which gave the class its
> name. Nothing was renamed because the TypeId string
> `ns3::olsr::OlsrDefenseGcop` is what the harness looks up.

The mechanisms:

- **C-Rules** (paper §3.5.1) — three contradiction tests over received HELLO/TC,
  plus a Rule-1 "bait" extension.
- **GCOHP** (Algorithm 2, §5.2) — hexagon-topology detection, which decides
  *whether* this node needs to advertise a fictitious neighbour at all. The point
  of the paper is avoiding superfluous fictitious nodes, so most nodes decide no.
  **This is the only decision on the live path.**
- **GCOP** (Algorithm 1, §5.1) — the depth-2 BFS colouring. It is implemented
  (`RunGcopAlgorithm`) but deliberately not consulted: the port matches the
  supervisor's reference implementation, whose live decision is the hexagon test
  alone, with its GCOP commented out. `RequiresFictitiousNode()` in
  `olsr-defense-gcop.cc` says so, and every DCFM batch records
  `fictitious_decision=gcohp_only` in `defense_params.txt`. The comment block in
  `olsr-defense-gcop.h` still describes GCOHP as a fallback; the `.cc` is
  authoritative.

Only two attributes: `Enabled` (default false — the harness owns this toggle,
see below) and `UseFictitiousNodes` (default true; setting it false degrades the
defense to the paper's C-Rules alone, a built-in ablation).

Its routing-protocol variant adds the **IMP enforcement path**: a secondary
routing table `m_tableAvoidingSuspects`, computed by excluding every currently
blacklisted node, consulted *only at forward time*. The main table is never
poisoned in response to a suspicion — which is also why this variant deliberately
does **not** filter a suspected node's control messages, with the source noting
that doing so was the strongest ML leakage signal in earlier revisions.

## Watchdog-OLSR (`watchdog-defense`)

Baiad, Otrok, Muhaidat & Bentahar, *Cooperative Cross Layer Detection for
Blackhole Attack in VANET-OLSR*, IEEE IWCMC (2014), with its journal extension —
Baiad, Alhussein, Otrok & Muhaidat, Vehicular Communications 5 (2016), 9–17 —
which supplies the detection-accuracy formula all four harnesses report
("Baiad et al. 2016, eq. 16"). Implemented by Hananel Kadron.

```
src/olsr/model/olsr-watchdog-defense.{h,cc}   class OlsrWatchdogDefense, ~1590 lines
```

**This is not the classic Marti et al. watchdog**, and the difference matters
when reading results. It is *cross-layer*: forwarding observations are
corroborated with RTS/CTS evidence and MAC-layer failures, per node, with no
inter-node cooperation messages. Sixteen attributes; three of them the source
itself marks `"INERT."` — heuristics removed from the decision path but kept so
older scripts still parse.

Its routing-protocol variant is the odd one out: it contains **no
promiscuous-monitoring code at all**. That looks like something went missing
until you check where the evidence comes from. `OlsrWatchdogDefense` schedules
its own periodic check (`m_periodicEvent`), and **attaches its own PHY sniffer**
in `Setup()` — `MonitorSnifferRx` for overheard forwards and RTS/CTS, `PhyRxDrop`
for local reception failures — alongside the forwarding and MAC-failure hooks
the routing protocol still calls. The monitoring did not go missing; it moved
into the defense object. So the empty `HandleDefenseTimer()` in its routing
protocol is correct here.

DCFM is the mirror image: `OlsrDefenseGcop` does *not* self-schedule, and its
routing-protocol variant supplies the full periodic timer body. Each pairing is
internally consistent; neither is a bug.

## Why four branches

The defenses are not merely different classes. They make **incompatible edits
to the same core OLSR files**, so they cannot be built into one binary as things
stand. TRUST and FPNT conflict in three ways:

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
3626's rule that a HELLO is never forwarded. A merged build would need that gate
made conditional on which strategy is loaded.

**3. The strategy interface diverged, but only additively.** FPNT added
`GetEvaluationVectors()`, `OnRecvEvaluationVectors()`, `GetNodeTrust()`,
`IsTrustRoutingEnabled()` and a 4-argument `OnDataPacketForwarded` overload;
TRUST added `GetPartialMistrusted()`, `OnHelloGenerated()` and `OnRecvProof()`.
Every one of those is non-pure with a safe default, so unioning those two
interfaces would compile and neither defense would need changing.

### DCFM and Watchdog conflict too

The same pattern holds for the two imported defenses, which are **not** a
subset/superset pair despite sharing an author. `diff` between their
routing-protocol variants is `+66 / −418` across six regions that cannot be
reconciled by simply taking the union:

1. **Control-message filtering in `RecvOlsr`.** Watchdog drops a suspected
   node's HELLO/TC; DCFM deliberately removed that, citing ML leakage.
2. **MPR candidate exclusion.** Watchdog skips suspected 1-hop and 2-hop
   neighbours; DCFM explicitly does not (paper §3.4).
3. **MPR selection tie-break.** DCFM only — adds one clean MPR when all
   candidates are suspect, rather than removing suspects.
4. **Routing-table computation.** Watchdog filters inline; DCFM split the
   function to build the suspect-avoiding table.
5. **The `RouteInput` response to a suspected next hop.** Watchdog: nothing.
   DCFM: reroute, never drop. TRUST: drop. FPNT: drop unless trust routing is
   active.
6. **Fictitious-node injection.** DCFM has it in HELLO and TC; Watchdog has
   neither.

So all four are genuinely independent edits of the same base, and one branch per
defense is the correct shape rather than a compromise. Unification of TRUST and
FPNT is feasible on paper — items 1 and 3 above are mechanical, item 2 needs a
design decision — but it was not attempted, because it would put the
comparability of the existing datasets at risk for no scientific gain. The
branches are the record of what was actually run. What the tooling does instead
is make switching between them a single command that cannot be misconfigured.

`master` holds the shared tooling and documentation, plus an early TRUST defense
that predates the branch split — it is not a branch to run experiments on.
`tools/`, `docs/` and `README.md` are byte-identical on all five branches; only
`tools/defense.manifest` differs. Note that `master` is still ns-3 `3-dev` while
all four defense branches are `3.47` — see
[HANDOFF.md](HANDOFF.md#known-issues).

## The harness

`scratch/olsr-{trust,fpnt,dcfm,watchdog}-eval-mitigation.cc` are the evaluation
programs — one per branch, roughly 2,700 to 2,900 lines each, and largely copies of one
another (all four are `HARNESS_VERSION 3.0.0`, `HEADER_VERSION 8`). They build the
topology, install the attacker and the defense, drive the four measurement
windows, and emit the CSVs.

They share `scratch/olsr_window_features.h`, the feature collector, which is
**byte-identical on all four branches** (`59662ed01`). That is deliberate and
load-bearing: it is what lets the four defenses' datasets be compared at all.
Verified end to end — all four compiled binaries emit the same 22-column header
from `--emit-header`. If you change the collector, change it on all four
branches in the same commit and regenerate everything.

All four harnesses accept `--self-test` (a schema self-check that must print
`ALL PASS`; the tooling runs it after every build) and `--emit-header` (prints
the CSV headers and exits, which is how the runner detects schema drift).

The DCFM and Watchdog harnesses also accept FPNT's flags (`--maliciousThreshold`,
`--fadingFactor`, `--redundantMpr`, …). They are **parsed and never read** — each
appears exactly once, on its `AddValue` line — and are kept on purpose so the
command-line interface is identical across harnesses. Do not expect them to tune
DCFM or Watchdog. Those two defenses take their parameters from hardcoded
`SetAttribute` calls in the harness's install block instead.

The top of each harness carries a long changelog of audit ticket IDs
(`LEAK-001`, `OBS-004`, `WIN-003`, `SL-2`, `DIR-001`, …). It is history, not
instructions — the "how to run" block is above it.
