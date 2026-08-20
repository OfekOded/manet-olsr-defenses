/*
 * Trust-based OLSR defense (Adnane et al., Computer Communications 36, 2013)
 *
 * olsr-consistency-rules.h -- neighbourhood / TC consistency checks that
 * COMPLEMENT the black-hole forward monitor (paper Section 5). Each rule is a
 * message-correlation test that yields an EXACT or PARTIAL mistrust:
 *
 *   Formula (6):  x HELLOy y; x TCy y; TCy (subset of) NSy fails  ==> ¬trusts(y)   [IMPLEMENTED]
 *   Formula (7):  x TCy; x in TCy; y not in MPRSx                 ==> ¬trusts(y)   [IMPLEMENTED]
 *   Formula (9b): y in MPRSx; x TCy y; x not in TCy              ==> ¬trusts(y)   [IMPLEMENTED]
 *   Formula (9a): y in MPRSx; y generates no TC (awaiting)        ==> ¬trusts(y)   [STUB]
 *   Formula (8):  two different TCy (same orig) from z,w          ==> ¬trusts{z,w} [STUB]
 *   Formula (12): NSA (subset of) NSB w/ common MPR selector z    ==> ¬trusts{A,B,z}[STUB]
 *
 * Default OFF (config.enableConsistencyRules) so the black-hole forward monitor
 * can be measured in isolation first.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef OLSR_CONSISTENCY_RULES_H
#define OLSR_CONSISTENCY_RULES_H

#include "olsr-alert-distributor.h" // ConsistencyProof
#include "olsr-trust-config.h"

#include "../olsr-header.h"

#include "ns3/ipv4-address.h"
#include "ns3/nstime.h"

#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <utility>

namespace ns3
{
namespace olsr
{

class RoutingProtocol;

/**
 * \ingroup olsr
 * \brief Consistency checks (Formulas 6,7,8,9,12) feeding mistrust decisions.
 */
class OlsrConsistencyRules
{
  public:
    /// \param group nodes concerned; \param exact true for exact mistrust (1 node), false for partial.
    /// \param proof falsifiable evidence (for alert distribution); empty/unverifiable when N/A.
    using MistrustCallback = std::function<void(const std::set<Ipv4Address>& group,
                                                bool exact,
                                                const std::string& formula,
                                                const std::string& reason,
                                                const ConsistencyProof& proof,
                                                Time now)>;

    OlsrConsistencyRules(const OlsrTrustDefenseConfig& cfg,
                         RoutingProtocol* proto,
                         Ipv4Address self,
                         MistrustCallback onMistrust);

    /// \param origin the node y that generated this HELLO (== sender for HELLO).
    void OnRecvHello(Ipv4Address origin,
                     const MessageHeader& msg,
                     const MessageHeader::Hello& hello,
                     Time now);

    /// \param origin the node y that ORIGINATED this TC.
    /// \param relay the neighbour we actually received this copy from (Formula 8).
    /// \param msgSeq the message sequence number carried by the TC (Formula 8).
    void OnRecvTc(Ipv4Address origin,
                  Ipv4Address relay,
                  const MessageHeader& msg,
                  const MessageHeader::Tc& tc,
                  Time now);

    /// Periodic hook (used by the Formula 9a generation-timeout stub).
    void PeriodicCheck(Time now);

    /// Section 7: does our OWN local vision contradict the claim carried by an alert?
    /// Used to "detect false alerts" before accepting or re-broadcasting one. Returns
    /// false when we simply hold no evidence either way -- absence of corroboration is
    /// not contradiction.
    bool ContradictsLocalVision(const ConsistencyProof& proof, Time now) const;

  private:
    /// Extract from a HELLO the addresses y advertises as SYMMETRIC neighbours.
    static std::set<Ipv4Address> SymNeighborsOf(const MessageHeader::Hello& hello);

    OlsrTrustDefenseConfig m_cfg;
    RoutingProtocol* m_proto; //!< non-owning.
    Ipv4Address m_self;
    MistrustCallback m_onMistrust;

    /// One node's latest HELLO declaration plus the time it arrived, so the paper's
    /// message-validity rule (Section 4) can be applied before the declaration is used
    /// as evidence against a third party.
    struct Declaration
    {
        std::set<Ipv4Address> sym; //!< what the node advertised as its symmetric neighbours.
        Time received;             //!< when that HELLO was received.
        MessageHeader raw;         //!< the message verbatim, so it can be retransmitted
                                   //!< as evidence (Section 7).
    };

    /// Latest HELLO declaration of each node we hear directly (Formula 6 and Section 5.1e).
    std::map<Ipv4Address, Declaration> m_advSymNeighbors;

    /// Latest MPR-selector set (MSS) each node advertised in its TC, for Formula 12.
    std::map<Ipv4Address, Declaration> m_advSelectors;

    /// Formula 8: one seen copy of a TC, so a contradictory second copy can be caught.
    struct TcCopy
    {
        std::set<Ipv4Address> content; //!< the advertised MPR-selector set.
        Ipv4Address relay;             //!< the neighbour that handed us this copy.
        Time received;
    };

    /// Formula 8 cache, keyed by (originator, message sequence number).
    std::map<std::pair<Ipv4Address, uint16_t>, TcCopy> m_tcCopies;

    /// Formula 9a: when each node last ORIGINATED a TC we saw, and when it became one
    /// of our MPRs (so a freshly selected MPR is given the awaiting period before we
    /// conclude it generates no TC).
    std::map<Ipv4Address, Time> m_lastTcOriginated;
    std::map<Ipv4Address, Time> m_mprSince;

    /// A run of contradictions of one kind about one (accused, witness) pair.
    struct Streak
    {
        uint32_t hits;  //!< how many times it has recurred without a gap.
        Time last;      //!< when it was last observed.
    };

    /// Contradiction streaks, keyed by (rule, accused, witness). Section 5.1 convicts only a
    /// node which CONTINUES to generate them, so a streak that goes quiet is forgotten.
    std::map<std::tuple<std::string, Ipv4Address, Ipv4Address>, Streak> m_streaks;

    /// Drop cached state that can no longer be used as evidence (Section 4 validity),
    /// so nothing grows with elapsed time.
    void PruneExpired(Time now);

    /// \return true once this contradiction has recurred often enough to convict.
    bool Persisted(const std::string& rule, Ipv4Address accused, Ipv4Address witness, Time now);

    /// \return true once the defense has been up long enough for the rules to apply
    /// (Section 5.1: "after an initialization process").
    bool PastInitialization(Time now) const;

    /// When this rule set was created (i.e. the last defense cold start). Backs the
    /// Section 5.1 "after an initialization process" grace period.
    Time m_startTime;
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_CONSISTENCY_RULES_H */
