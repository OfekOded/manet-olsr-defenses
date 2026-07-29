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
                                         //!< identity, which is sound for drop detection -- see README).
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
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_TRUST_CONFIG_H */
