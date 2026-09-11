/*
 * Trust-based OLSR defense (Adnane, Bidan, de Sousa, Computer Communications 36, 2013)
 *
 * olsr-trust-config.h -- THE single configuration location for the whole
 * trust defense. Every tunable knob of every sub-module lives here. The
 * OlsrTrustDefense object exposes each field as an ns-3 TypeId Attribute and
 * packs them into one OlsrTrustDefenseConfig that is handed to the sub-modules.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef OLSR_TRUST_CONFIG_H
#define OLSR_TRUST_CONFIG_H

#include "ns3/nstime.h"

namespace ns3
{
namespace olsr
{

/**
 * \ingroup olsr
 * \brief Single, central configuration for the trust-based OLSR defense.
 *
 * Defaults below are the canonical values; the OlsrTrustDefense TypeId mirrors
 * them as Attributes so a scenario can override any of them via SetAttribute.
 * Grouped by sub-module so the mapping to the paper stays obvious.
 */
struct OlsrTrustDefenseConfig
{
    // ----- per-sub-module enables (each defense component is independently toggleable) -----
    bool enableForwardMonitor = true;   //!< Formula (10): black-hole forward monitoring (priority 1).
    bool enableConsistencyRules = false; //!< Formulas (6),(7),(8),(9),(12): complementary checks.
    bool enableProvableIdentity = false; //!< Section 6 / Formula (13): SOLSR identity (crypto, off by default).
    bool enableAlertDistribution = false; //!< Section 7: propagate consistency-detections network-wide
                                          //!< (idealized bus; only falsifiable Formulas 6/7/8/12, NOT
                                          //!< the black-hole Formula 10, which has no provable artifact).

    // ----- forward monitor (Formula 10) -----
    // Awaiting period: time after sending TC/DATA to overhear the MPR retransmit.
    // Must cover OLSR's worst-case forwarding latency: x's own transmit jitter
    // (<= OLSR_MAXJITTER = helloInterval/4 ~ 0.5 s, because OnTcGenerated arms the
    // record BEFORE QueueMessage(msg, JITTER)) + the MPR's own reflood jitter
    // (<= 0.5 s) + aggregation/backoff. A 1 s window expired before a compliant
    // MPR could be observed, mass-accusing legitimate neighbours; 3 s is safely
    // above the worst case while still far below any plausible black-hole patience.
    Time forwardTimeout = Seconds(3.0);  //!< Awaiting period to overhear an MPR re-forward a TC/DATA.
    Time checkInterval = Seconds(0.25);  //!< Granularity of the expiry sweep that raises the internal forward-failure.
    bool monitorData = true;             //!< Watch DATA forwarding (DATAx branch of Formula 10).
    bool monitorTc = true;               //!< Watch TC forwarding   (TCx branch of Formula 10).
    bool monitorRelayedData = false;     //!< If true, also watch data x merely RELAYS (generalized watchdog);
                                         //!< default false == faithful Formula 10 (only DATAx originated by x).
    bool strictMacAttribution = false;   //!< If true, only clear a DATA record when the overheard transmitter's
                                         //!< MAC resolves to the expected MPR; default lenient (clear on packet
                                         //!< identity, which is sound for drop detection -- see
                                         //!< docs/ARCHITECTURE.md).
    uint32_t minForwardFailures = 3;     //!< Consecutive observed forward-failures before mistrust fires.
                                         //!< A single awaiting-period miss is indistinguishable from a
                                         //!< transient wireless loss (broadcast TC re-floods are not MAC-
                                         //!< ACKed), so requiring sustained, consecutive non-forwarding
                                         //!< (a success resets the per-MPR counter) suppresses false
                                         //!< positives while a true black-hole, which drops ~everything,
                                         //!< still trips almost immediately. (1 == paper-exact, fragile.)

    // ----- trust state / countermeasures (Formula 15) -----
    bool responseEnabled = true;         //!< false == DETECTION-ONLY: detect+log but IsMalicious() stays false so
                                         //!< the topology is never perturbed (lets you measure detection alone).
    bool mistrustPermanent = false;      //!< Exact mistrust is temporary (rehabilitatable) by default so a
                                         //!< residual false positive self-heals after mistrustDuration
                                         //!< instead of permanently fragmenting routing; set true for the
                                         //!< paper-exact permanent variant.
    Time mistrustDuration = Seconds(60.0); //!< Rehabilitation window for temporary mistrust (mistrustPermanent=false).

    // ----- Section 5.1 extended cross-check (the network-wide neighbour-declaration check) -----
    // Paper Section 5.1, right after Formula (8): "if x detects a remote node y advertising one
    // of its neighbors z in the message TCy, but if z did not declare y as symmetric neighbor,
    // then it must mistrust y". This is the ONLY rule in the paper that can fire at a node which
    // is neither a neighbour of the attacker nor named by it, so it is what lets the paper's
    // detection rate approach 100%: a TC floods the entire network, and every node holding a
    // valid HELLO from a falsely-claimed selector can convict the originator.
    bool enableCrossCheck = true;

    // A witness's HELLO declaration may only be used while it is still valid (paper Section 4:
    // "HELLO and TC messages have validity time, which indicates for how long time after
    // reception a node must consider the information contained in the message as valid").
    // 6 s == OLSR_NEIGHB_HOLD_TIME at the default 2 s HELLO interval.
    Time helloValidity = Seconds(6.0);

    // Paper Section 5.1: a single contradiction "may be a temporary situation where a group of
    // nodes is at the beginning of a discovery process"; only "the node which continues to
    // receive contradictory messages should mistrust" the generator. The same
    // (accused, witness) contradiction must therefore be observed this many times.
    uint32_t crossCheckPersistence = 2;

    // Paper Section 5.1 applies the rule only "after an initialization process": suppress it for
    // this long after the defense starts (a cold start restarts the clock).
    Time consistencyGrace = Seconds(15.0);

    // How long a contradiction streak stays alive. Section 5.1 convicts the node which
    // CONTINUES to generate contradictions, so a streak that stops recurring for this long
    // is a resolved transient and is forgotten rather than counted towards a conviction.
    // 15 s == 3 TC intervals at the ns-3 default.
    Time persistenceWindow = Seconds(15.0);

    // Formula (9a): how long we wait for a selected MPR to originate a TC before
    // concluding it generates none. OLSR_TOP_HOLD_TIME == 3 * tcInterval == 15 s, i.e.
    // the lifetime the protocol itself assigns to topology information, and the same
    // grace is applied from the moment the node became one of our MPRs.
    Time tcAwaitingPeriod = Seconds(15.0);

    // Individual rule enables (for ablation; all part of the paper's Section 5).
    bool enableFormula8 = true;   //!< contradictory copies of one TC from two relays.
    bool enableFormula9a = true;  //!< selected MPR that originates no TC at all.
    bool enableFormula12 = true;  //!< two MPRs with nested neighbourhoods sharing a selector.

    // Validity of a TC-derived selector set, used by Formula 12. OLSR_TOP_HOLD_TIME
    // == 3 * tcInterval == 15 s is the lifetime the protocol itself assigns to
    // topology information (paper Section 4: messages carry a validity time).
    Time topologyValidity = Seconds(15.0);

    // Retained for provenance only: a Section 6.2 proof is superseded by the next one
    // from the same node rather than expiring on a timer (see ProveNeighborhood). A
    // node issues a proof exactly when its neighbourhood changes, so a timer would make
    // declarations unusable precisely in the settled networks where they matter most.
    Time proofValidity = Seconds(30.0);
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_TRUST_CONFIG_H */
