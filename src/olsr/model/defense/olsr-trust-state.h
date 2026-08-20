/*
 * Trust-based OLSR defense (Adnane et al., Computer Communications 36, 2013)
 *
 * olsr-trust-state.h -- trust / mistrust state (the DECISION side).
 *
 * Maintains MN_x, the set of Mistrusted Nodes of node x (paper Formula 15).
 * This module records WHO is (mis)trusted and WHY; it never sends anything and
 * never touches the routing tables itself. Turning a verdict into an actual
 * countermeasure is done by OlsrTrustDefense::IsMalicious() reading this state,
 * which keeps detection cleanly separable from response.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef OLSR_TRUST_STATE_H
#define OLSR_TRUST_STATE_H

#include "olsr-trust-config.h"

#include "ns3/ipv4-address.h"
#include "ns3/nstime.h"

#include <map>
#include <set>
#include <string>
#include <vector>

namespace ns3
{
namespace olsr
{

/**
 * \ingroup olsr
 * \brief One recorded detection decision (for measurement, independent of response).
 */
struct TrustDetectionEvent
{
    Time time;             //!< When the decision was taken.
    Ipv4Address target;    //!< Node (exact) the decision concerns; for partial, the first of the group.
    std::set<Ipv4Address> group; //!< Full group for a partial mistrust (single element for exact).
    bool exact;            //!< true == exact mistrust (countermeasure-eligible); false == partial (no rule).
    std::string formula;   //!< Paper formula that fired, e.g. "10-DATA", "10-TC", "6", "7".
    std::string reason;    //!< Human-readable explanation.
};

/**
 * \ingroup olsr
 * \brief MN_x (Mistrusted Nodes) plus the detection log.
 *
 * Exact vs. partial mistrust follow the paper Section 3: exact mistrust is
 * total and countermeasure-eligible (Formula 15); partial mistrust flags a
 * group that contains the attacker but cannot single it out, so NO rule is
 * applied (paper p.1169) -- it is recorded for measurement only.
 */
class OlsrTrustState
{
  public:
    OlsrTrustState(const OlsrTrustDefenseConfig& cfg, Ipv4Address self);

    /**
     * \brief Exact mistrust of \p node (Formula 15: MN_x <- MN_x U {node}).
     * Idempotent; refreshes the temporary-mistrust deadline if already present.
     */
    void MistrustExact(Ipv4Address node, const std::string& formula, const std::string& reason, Time now);

    /**
     * \brief Partial mistrust of a group (paper Section 3, "partial mistrust").
     * Records the group for measurement; applies NO countermeasure.
     */
    void MistrustPartial(const std::set<Ipv4Address>& group,
                         const std::string& formula,
                         const std::string& reason,
                         Time now);

    /// \return true if \p node is currently in MN_x by EXACT mistrust.
    bool IsExactMistrusted(Ipv4Address node) const;

    /// \return the current exact-mistrust set MN_x.
    std::set<Ipv4Address> GetMistrusted() const;

    /// Nodes under PARTIAL mistrust (Table 3's second series). No countermeasure is
    /// applied to these -- paper: "when the mistrust is partial, no rule is applied".
    std::set<Ipv4Address> GetPartialMistrusted() const;

    /// Rehabilitate temporary mistrust whose deadline has passed (no-op when permanent).
    void Expire(Time now);

    /// Full detection log (every decision, exact or partial) -- for precision/recall measurement.
    const std::vector<TrustDetectionEvent>& GetLog() const { return m_log; }

    /// Convenience counters.
    uint32_t GetExactCount() const { return static_cast<uint32_t>(m_exact.size()); }

  private:
    OlsrTrustDefenseConfig m_cfg;
    Ipv4Address m_self;
    /// Exact mistrust set with per-node rehabilitation deadline (Max() == permanent).
    std::map<Ipv4Address, Time> m_exact;
    std::map<Ipv4Address, Time> m_partial; //!< group members under partial mistrust.
    std::vector<TrustDetectionEvent> m_log;
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_TRUST_STATE_H */
