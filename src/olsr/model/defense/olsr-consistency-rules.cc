/*
 * Trust-based OLSR defense (Adnane et al., Computer Communications 36, 2013)
 * olsr-consistency-rules.cc -- Formulas (6),(7),(9b) implemented; (8),(9a),(12) stubbed.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "olsr-consistency-rules.h"

#include "../olsr-routing-protocol.h"

#include "ns3/log.h"

#include <algorithm>

namespace ns3
{
namespace olsr
{

NS_LOG_COMPONENT_DEFINE("OlsrConsistencyRules");

// linkCode bit layout (RFC 3626): bits[0:1]=link type, bits[2:3]=neighbour type.
static constexpr uint8_t OLSR_SYM_LINK = 2;  // LinkType::SYM_LINK
static constexpr uint8_t OLSR_SYM_NEIGH = 1; // NeighborType::SYM_NEIGH
static constexpr uint8_t OLSR_MPR_NEIGH = 2; // NeighborType::MPR_NEIGH

OlsrConsistencyRules::OlsrConsistencyRules(const OlsrTrustDefenseConfig& cfg,
                                           RoutingProtocol* proto,
                                           Ipv4Address self,
                                           MistrustCallback onMistrust)
    : m_cfg(cfg),
      m_proto(proto),
      m_self(self),
      m_onMistrust(std::move(onMistrust))
{
}

std::set<Ipv4Address>
OlsrConsistencyRules::SymNeighborsOf(const MessageHeader::Hello& hello)
{
    std::set<Ipv4Address> sym;
    for (const auto& lm : hello.linkMessages)
    {
        uint8_t linkType = lm.linkCode & 0x03;
        uint8_t neighType = (lm.linkCode >> 2) & 0x03;
        bool isSym = (linkType == OLSR_SYM_LINK) || (neighType == OLSR_SYM_NEIGH) ||
                     (neighType == OLSR_MPR_NEIGH);
        if (isSym)
        {
            for (const auto& a : lm.neighborInterfaceAddresses)
            {
                sym.insert(a);
            }
        }
    }
    return sym;
}

void
OlsrConsistencyRules::OnRecvHello(Ipv4Address origin, const MessageHeader::Hello& hello, Time now)
{
    if (origin == m_self)
    {
        return;
    }
    // Remember what symmetric neighbours y currently advertises (for Formula 6).
    m_advSymNeighbors[origin] = SymNeighborsOf(hello);
}

void
OlsrConsistencyRules::OnRecvTc(Ipv4Address origin, const MessageHeader::Tc& tc, Time now)
{
    if (origin == m_self)
    {
        return;
    }
    const Ipv4Address y = origin;
    MprSet mprs = m_proto->GetMprSet(); // MPRSx
    bool ySelectedByMe = (mprs.find(y) != mprs.end());
    bool meListedInTc = (std::find(tc.neighborAddresses.begin(),
                                   tc.neighborAddresses.end(),
                                   m_self) != tc.neighborAddresses.end());

    // ---- Formula (7): y advertises x as its selector, but x never selected y. ----
    //   x TCy ; x in TCy ; y not in MPRSx  ==> x ¬trusts(y)
    if (meListedInTc && !ySelectedByMe)
    {
        // Proof (falsifiable, for alert distribution): y's TC selector list must contain
        // the accuser, and the accuser's own MPR set must NOT contain y.
        ConsistencyProof proof;
        proof.formula = "7";
        proof.accused = y;
        proof.advertised = tc.neighborAddresses;
        proof.reference.assign(mprs.begin(), mprs.end());
        m_onMistrust({y}, true, "7",
                     "TC originator advertises me as its MPR-selector, but I never selected it as MPR",
                     proof, now);
    }

    // ---- Formula (9b): y is my MPR, so y must advertise me as a selector. ----
    //   y in MPRSx ; x TCy y ; x not in TCy  ==> x ¬trusts(y)
    // NOTE: 9b is NOT in the alert-distribution set ({6,7,8,12}); a third party
    // cannot re-verify "y omitted ME" without my private MPR-selection, so it stays
    // a local detection (empty proof).
    if (ySelectedByMe && !meListedInTc)
    {
        m_onMistrust({y}, true, "9b",
                     "I selected this node as MPR, but its TC omits me from its MPR-selector set",
                     ConsistencyProof{"9b", y, {}, {}}, now);
    }

    // ---- Formula (6): every MPR-selector y advertises in TCy must be a symmetric ----
    //   neighbour y advertised in HELLOy.   TCy (subset of) NSy must hold.
    auto sit = m_advSymNeighbors.find(y);
    if (sit != m_advSymNeighbors.end())
    {
        const std::set<Ipv4Address>& advSym = sit->second;
        for (const auto& sel : tc.neighborAddresses)
        {
            if (advSym.find(sel) == advSym.end())
            {
                // Proof: y's TC selectors vs y's HELLO symmetric neighbours -- a third
                // party re-verifies that some advertised selector is absent from the set.
                ConsistencyProof proof;
                proof.formula = "6";
                proof.accused = y;
                proof.advertised = tc.neighborAddresses;
                proof.reference.assign(advSym.begin(), advSym.end());
                m_onMistrust({y}, true, "6",
                             "TC advertises an MPR-selector that was never advertised as a symmetric "
                             "neighbour in HELLO",
                             proof, now);
                break;
            }
        }
    }

    // ---- Formula (8) [STUB]: two DIFFERENT TCs with the same originator arriving ----
    //   from different relays z,w => partial mistrust {z,w}. Requires buffering TC
    //   contents keyed by (originator, ANSN) and comparing on the next copy. Left as
    //   a documented TODO; enable once the TC-content cache is added.
}

void
OlsrConsistencyRules::PeriodicCheck(Time now)
{
    // ---- Formula (9a) [STUB]: an MPR y of x that generates NO TC within an awaiting ----
    //   period must be mistrusted. Requires per-MPR "last TC originated by y seen" plus
    //   a grace window from when y became an MPR (to avoid start-up false positives).
    //   Left as a documented TODO.
    //
    // ---- Formula (12) [STUB]: NSA (subset of) NSB with a common selector z among A,B ----
    //   => partial mistrust {A,B,z}. Requires cross-neighbour HELLO correlation. TODO.
    (void)now;
}

} // namespace olsr
} // namespace ns3
