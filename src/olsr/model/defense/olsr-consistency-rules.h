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

#include <functional>
#include <map>
#include <set>
#include <string>

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
    void OnRecvHello(Ipv4Address origin, const MessageHeader::Hello& hello, Time now);

    /// \param origin the node y that ORIGINATED this TC (not the relay).
    void OnRecvTc(Ipv4Address origin, const MessageHeader::Tc& tc, Time now);

    /// Periodic hook (used by the Formula 9a generation-timeout stub).
    void PeriodicCheck(Time now);

  private:
    /// Extract from a HELLO the addresses y advertises as SYMMETRIC neighbours.
    static std::set<Ipv4Address> SymNeighborsOf(const MessageHeader::Hello& hello);

    OlsrTrustDefenseConfig m_cfg;
    RoutingProtocol* m_proto; //!< non-owning.
    Ipv4Address m_self;
    MistrustCallback m_onMistrust;

    /// Latest symmetric-neighbour set each node advertised in its HELLO (for Formula 6).
    std::map<Ipv4Address, std::set<Ipv4Address>> m_advSymNeighbors;
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_CONSISTENCY_RULES_H */
