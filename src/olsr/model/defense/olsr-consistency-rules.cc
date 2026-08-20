/*
 * Trust-based OLSR defense (Adnane et al., Computer Communications 36, 2013)
 * olsr-consistency-rules.cc -- Formulas (6),(7),(9b) implemented; (8),(9a),(12) stubbed.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "olsr-consistency-rules.h"

#include "../olsr-routing-protocol.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <algorithm>
#include <iterator>

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
      m_onMistrust(std::move(onMistrust)),
      m_startTime(Simulator::Now())
{
}

void
OlsrConsistencyRules::PruneExpired(Time now)
{
    // Formula 8's cache is keyed by a never-repeating sequence number, so without this
    // it would grow for the whole run. A copy older than the topology-validity horizon
    // can no longer be paired with anything, nor used as evidence.
    for (auto it = m_tcCopies.begin(); it != m_tcCopies.end();)
    {
        it = ((now - it->second.received) > m_cfg.topologyValidity) ? m_tcCopies.erase(it)
                                                                   : std::next(it);
    }
    // A contradiction streak that has gone quiet past its window is already treated as
    // resolved by Persisted(); drop it so the map tracks live disputes only.
    for (auto it = m_streaks.begin(); it != m_streaks.end();)
    {
        it = ((now - it->second.last) > m_cfg.persistenceWindow) ? m_streaks.erase(it)
                                                                 : std::next(it);
    }
}

bool
OlsrConsistencyRules::PastInitialization(Time now) const
{
    return (now - m_startTime) >= m_cfg.consistencyGrace;
}

bool
OlsrConsistencyRules::Persisted(const std::string& rule,
                                Ipv4Address accused,
                                Ipv4Address witness,
                                Time now)
{
    Streak& s = m_streaks[std::make_tuple(rule, accused, witness)];
    if (s.hits > 0 && (now - s.last) > m_cfg.persistenceWindow)
    {
        // The contradiction stopped recurring: it was a transient of the discovery
        // process and must not be counted towards a later, unrelated one.
        s.hits = 0;
    }
    ++s.hits;
    s.last = now;
    return s.hits >= m_cfg.crossCheckPersistence;
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
OlsrConsistencyRules::OnRecvHello(Ipv4Address origin,
                                  const MessageHeader& msg,
                                  const MessageHeader::Hello& hello,
                                  Time now)
{
    if (origin == m_self)
    {
        return;
    }
    // Remember what symmetric neighbours y currently advertises, with its arrival time so
    // the validity rule of Section 4 can be applied when it is used as evidence (5.1e).
    m_advSymNeighbors[origin] = Declaration{SymNeighborsOf(hello), now, msg};
}

void
OlsrConsistencyRules::OnRecvTc(Ipv4Address origin,
                               Ipv4Address relay,
                               const MessageHeader& msg,
                               const MessageHeader::Tc& tc,
                               Time now)
{
    if (origin == m_self)
    {
        return;
    }
    const Ipv4Address y = origin;

    // Formula 9a bookkeeping: y demonstrably originates TCs.
    m_lastTcOriginated[y] = now;
    // Formula 12 bookkeeping: remember the MPR-selector set y advertises (MSSy).
    m_advSelectors[y] =
        Declaration{std::set<Ipv4Address>(tc.neighborAddresses.begin(), tc.neighborAddresses.end()),
                    now, msg};
    const uint16_t msgSeq = msg.GetMessageSequenceNumber();
    MprSet mprs = m_proto->GetMprSet(); // MPRSx
    bool ySelectedByMe = (mprs.find(y) != mprs.end());
    bool meListedInTc = (std::find(tc.neighborAddresses.begin(),
                                   tc.neighborAddresses.end(),
                                   m_self) != tc.neighborAddresses.end());

    // ---- Formula (7): y advertises x as its selector, but x never selected y. ----
    //   x TCy ; x in TCy ; y not in MPRSx  ==> x ¬trusts(y)
    // Section 5.1: MPR selection and a peer's TC (ANSN) advance on different timers, so a
    // node that has just changed its MPR set sees a contradiction that resolves one TC later.
    // Only a node which CONTINUES to receive them convicts.
    if (meListedInTc && !ySelectedByMe && PastInitialization(now) && Persisted("7", y, m_self, now))
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
    // Same transient as Formula 7, in the opposite direction: we may have selected y only
    // moments ago, before y could advertise us in a TC.
    if (ySelectedByMe && !meListedInTc && PastInitialization(now) &&
        Persisted("9b", y, m_self, now))
    {
        m_onMistrust({y}, true, "9b",
                     "I selected this node as MPR, but its TC omits me from its MPR-selector set",
                     ConsistencyProof{"9b", y, {}, {}}, now);
    }

    // ---- Formula (6): every MPR-selector y advertises in TCy must be a symmetric ----
    //   neighbour y advertised in HELLOy.   TCy (subset of) NSy must hold.
    auto sit = m_advSymNeighbors.find(y);
    // Section 4: only a HELLO that is still valid may be used as evidence. A TC and a
    // HELLO are emitted on different timers, so comparing a fresh TC against a stale
    // HELLO manufactures contradictions out of ordinary neighbourhood churn.
    if (sit != m_advSymNeighbors.end() && (now - sit->second.received) <= m_cfg.helloValidity &&
        PastInitialization(now))
    {
        const std::set<Ipv4Address>& advSym = sit->second.sym;
        for (const auto& sel : tc.neighborAddresses)
        {
            if (advSym.find(sel) == advSym.end())
            {
                // Section 5.1: a single contradiction can be a transient of the discovery
                // process; only a node which CONTINUES to receive contradictory messages
                // convicts the generator.
                if (!Persisted("6", y, sel, now))
                {
                    break;
                }
                // Proof: y's TC selectors vs y's HELLO symmetric neighbours -- a third
                // party re-verifies that some advertised selector is absent from the set.
                ConsistencyProof proof;
                proof.formula = "6";
                proof.accused = y;
                proof.advertised = tc.neighborAddresses;
                proof.reference.assign(advSym.begin(), advSym.end());
                proof.evidence.push_back(msg);            // TCy
                proof.evidence.push_back(sit->second.raw); // HELLOy
                m_onMistrust({y}, true, "6",
                             "TC advertises an MPR-selector that was never advertised as a symmetric "
                             "neighbour in HELLO",
                             proof, now);
                break;
            }
        }
    }

    // ---- Section 5.1 (extended property): cross-check the originator's claim against ----
    //   the WITNESS's own declaration.
    //
    //   Paper Section 5.1: "if x detects a remote node y advertising one of its neighbors z in
    //   the message TCy, but if z did not declare y as symmetric neighbor, then it must mistrust
    //   y because its behavior does not correspond to the OLSR specification."
    //
    //   Unlike Formulas 6/7/9b -- which can only fire at a 1-hop neighbour of y, at a node y
    //   named in TCy, or at y's own selector -- this rule fires at ANY node that holds a valid
    //   HELLO from a falsely-claimed selector. Because a TC floods the whole network, that is
    //   most of the network, which is what makes the paper's detection rate approach 100%.
    if (m_cfg.enableCrossCheck && PastInitialization(now))
    {
        for (const auto& sel : tc.neighborAddresses)
        {
            auto wit = m_advSymNeighbors.find(sel);
            if (wit == m_advSymNeighbors.end())
            {
                continue; // we hold no declaration from this witness -> we cannot judge.
            }
            if (now - wit->second.received > m_cfg.helloValidity)
            {
                continue; // Section 4: the witness's declaration has expired -> we cannot judge.
            }
            if (wit->second.sym.find(y) != wit->second.sym.end())
            {
                continue; // consistent: the witness does declare y as a symmetric neighbour.
            }
            // Contradiction. Section 5.1 convicts only a node which CONTINUES to generate them,
            // because a single one can be a transient of the neighbourhood-discovery process.
            if (!Persisted("5.1e", y, sel, now))
            {
                continue;
            }
            // Proof (Section 7 scenario 2: "inconsistency between two messages provided by other
            // nodes ... retransmitting these two messages"): TCy must name the witness, and the
            // witness's own HELLO must not name y.
            ConsistencyProof proof;
            proof.formula = "5.1e";
            proof.accused = y;
            proof.witness = sel;
            proof.advertised = tc.neighborAddresses;
            proof.reference.assign(wit->second.sym.begin(), wit->second.sym.end());
            // Section 7 scenario 2: retransmit THE TWO MESSAGES that revealed it.
            proof.evidence.push_back(msg);              // TCy
            proof.evidence.push_back(wit->second.raw);  // HELLO of the witness
            m_onMistrust({y}, true, "5.1e",
                         "TC advertises an MPR-selector whose own HELLO never declared the TC "
                         "originator as a symmetric neighbour",
                         proof, now);
            break;
        }
    }

    // ---- Formula (8): two DIFFERENT copies of the SAME TC (same originator and ----
    //   sequence number) arriving from two different relays z,w.
    //
    //   Paper: "If x receives two TC messages from two different nodes with the same
    //   sequence number and originator address but with different information, then x
    //   must mistrust the two sender nodes." The mistrust is PARTIAL: the originator may
    //   be honest and one relay may have altered the message, or the originator may have
    //   an accomplice -- x cannot tell which, so it mistrusts the group.
    if (m_cfg.enableFormula8 && PastInitialization(now))
    {
        const auto key = std::make_pair(y, msgSeq);
        std::set<Ipv4Address> content(tc.neighborAddresses.begin(), tc.neighborAddresses.end());
        auto prev = m_tcCopies.find(key);
        if (prev == m_tcCopies.end())
        {
            m_tcCopies[key] = TcCopy{content, relay, now};
        }
        else if (prev->second.relay != relay && prev->second.content != content)
        {
            // Same TC identity, different content, different relay: one of the two
            // relays is lying, and x cannot tell which.
            if (Persisted("8", prev->second.relay, relay, now))
            {
                m_onMistrust({prev->second.relay, relay}, false, "8",
                             "two contradictory copies of the same TC (same originator and "
                             "sequence number) arrived from two different relays",
                             ConsistencyProof{"8", y}, now);
            }
            prev->second = TcCopy{content, relay, now};
        }
    }
}

bool
OlsrConsistencyRules::ContradictsLocalVision(const ConsistencyProof& proof, Time now) const
{
    if (proof.formula == "5.1e")
    {
        // The alert claims the witness never declared the accused as a symmetric
        // neighbour. If OUR OWN valid HELLO from that witness does declare the accused,
        // the alert is false and must be rejected.
        auto wit = m_advSymNeighbors.find(proof.witness);
        if (wit == m_advSymNeighbors.end() || (now - wit->second.received) > m_cfg.helloValidity)
        {
            return false; // no local evidence either way.
        }
        return wit->second.sym.find(proof.accused) != wit->second.sym.end();
    }
    if (proof.formula == "6")
    {
        // The alert claims the accused advertised a selector it never declared symmetric.
        // If our own valid HELLO from the accused declares every selector the alert lists,
        // the inconsistency does not exist in our vision and the alert is false.
        auto acc = m_advSymNeighbors.find(proof.accused);
        if (acc == m_advSymNeighbors.end() || (now - acc->second.received) > m_cfg.helloValidity)
        {
            return false;
        }
        for (const auto& sel : proof.advertised)
        {
            if (acc->second.sym.find(sel) == acc->second.sym.end())
            {
                return false; // we see the same inconsistency -> not contradicted.
            }
        }
        return true;
    }
    // Formula 7 rests on the accuser's own MPR selection, which no third party holds;
    // there is nothing in the local vision that can contradict it.
    return false;
}

void
OlsrConsistencyRules::PeriodicCheck(Time now)
{
    PruneExpired(now);

    if (!m_proto || !PastInitialization(now))
    {
        return;
    }

    // ---- Formula (9a): a node we selected as MPR must GENERATE TC messages. ----
    //   Paper: "If a selected MPR (y) does not generate TC messages correctly advertising
    //   its MPR selectors, each selector (x) must mistrust this MPR."  This is the
    //   "x !<- TCy" branch: no TC from y at all within the awaiting period.
    const MprSet mprs = m_proto->GetMprSet();
    for (const auto& y : mprs)
    {
        auto since = m_mprSince.find(y);
        if (since == m_mprSince.end())
        {
            m_mprSince[y] = now; // just selected: start its awaiting period now.
            continue;
        }
        if ((now - since->second) < m_cfg.tcAwaitingPeriod)
        {
            continue; // still within the grace we owe a freshly selected MPR.
        }
        auto last = m_lastTcOriginated.find(y);
        const bool silent = (last == m_lastTcOriginated.end()) ||
                            ((now - last->second) > m_cfg.tcAwaitingPeriod);
        if (m_cfg.enableFormula9a && silent && Persisted("9a", y, m_self, now))
        {
            // No third party can check "y never sent a TC" -- it is an absence of
            // evidence local to x -- so this stays a local detection with no proof.
            m_onMistrust({y}, true, "9a",
                         "selected MPR originated no TC within the awaiting period",
                         ConsistencyProof{"9a", y}, now);
        }
    }
    // Forget nodes that are no longer our MPRs, so re-selection restarts the grace.
    for (auto it = m_mprSince.begin(); it != m_mprSince.end();)
    {
        it = (mprs.find(it->first) == mprs.end()) ? m_mprSince.erase(it) : std::next(it);
    }

    // ---- Formula (12): two neighbours with nested neighbourhoods cannot both be ----
    //   MPRs of a common node.
    //
    //   Paper: "Two nodes x and y with the same neighborhood (the same symmetric
    //   neighbors) cannot be both selected as MPRs by common neighbors. Because, if one
    //   is selected, for example x, it will provide reachability to its neighborhood
    //   (NSx) which covers y's neighborhood (NSy)."  Formalised as formula (12):
    //   NSA (subset of) NSB with some z in MSSA ^ MSSB  =>  !trusts({A,B,z}).
    //   PARTIAL: x cannot tell whether A or B lied, or whether z selected badly.
    if (!m_cfg.enableFormula12)
    {
        return;
    }
    for (const auto& a : m_advSymNeighbors)
    {
        if ((now - a.second.received) > m_cfg.helloValidity || a.second.sym.empty())
        {
            continue;
        }
        auto selA = m_advSelectors.find(a.first);
        if (selA == m_advSelectors.end() || (now - selA->second.received) > m_cfg.topologyValidity)
        {
            continue;
        }
        for (const auto& b : m_advSymNeighbors)
        {
            if (b.first == a.first || (now - b.second.received) > m_cfg.helloValidity)
            {
                continue;
            }
            auto selB = m_advSelectors.find(b.first);
            if (selB == m_advSelectors.end() || (now - selB->second.received) > m_cfg.topologyValidity)
            {
                continue;
            }
            // NSA strictly inside NSB (equality is symmetric and would fire twice).
            if (a.second.sym.size() >= b.second.sym.size() ||
                !std::includes(b.second.sym.begin(), b.second.sym.end(),
                               a.second.sym.begin(), a.second.sym.end()))
            {
                continue;
            }
            std::set<Ipv4Address> shared;
            std::set_intersection(selA->second.sym.begin(), selA->second.sym.end(),
                                  selB->second.sym.begin(), selB->second.sym.end(),
                                  std::inserter(shared, shared.begin()));
            shared.erase(m_self);
            if (shared.empty() || !Persisted("12", a.first, b.first, now))
            {
                continue;
            }
            std::set<Ipv4Address> group{a.first, b.first};
            group.insert(*shared.begin());
            m_onMistrust(group, false, "12",
                         "a node whose neighbourhood is contained in another's is still an "
                         "MPR of a node they both serve",
                         ConsistencyProof{"12", a.first}, now);
            return; // one partial detection per sweep is enough.
        }
    }
}

} // namespace olsr
} // namespace ns3
