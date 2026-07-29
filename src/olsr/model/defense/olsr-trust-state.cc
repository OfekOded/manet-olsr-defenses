/*
 * Trust-based OLSR defense (Adnane et al., Computer Communications 36, 2013)
 * olsr-trust-state.cc
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "olsr-trust-state.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3
{
namespace olsr
{

NS_LOG_COMPONENT_DEFINE("OlsrTrustState");

OlsrTrustState::OlsrTrustState(const OlsrTrustDefenseConfig& cfg, Ipv4Address self)
    : m_cfg(cfg),
      m_self(self)
{
}

void
OlsrTrustState::MistrustExact(Ipv4Address node,
                              const std::string& formula,
                              const std::string& reason,
                              Time now)
{
    // Formula 15: MN_x <- MN_x U {node}. Permanent => never rehabilitated.
    Time deadline = m_cfg.mistrustPermanent ? Time::Max() : (now + m_cfg.mistrustDuration);

    auto it = m_exact.find(node);
    if (it != m_exact.end())
    {
        // Already mistrusted: just refresh the temporary deadline, do not re-log.
        it->second = deadline;
        return;
    }

    m_exact[node] = deadline;

    TrustDetectionEvent ev;
    ev.time = now;
    ev.target = node;
    ev.group = {node};
    ev.exact = true;
    ev.formula = formula;
    ev.reason = reason;
    m_log.push_back(ev);

    NS_LOG_INFO("[" << now.As(Time::S) << "] node " << m_self << " EXACT-mistrusts " << node
                    << " (Formula " << formula << "): " << reason);
}

void
OlsrTrustState::MistrustPartial(const std::set<Ipv4Address>& group,
                                const std::string& formula,
                                const std::string& reason,
                                Time now)
{
    // Partial mistrust: recorded for measurement, NO countermeasure applied
    // (paper p.1169: "when the mistrust is partial, no rule is applied").
    TrustDetectionEvent ev;
    ev.time = now;
    ev.target = group.empty() ? Ipv4Address() : *group.begin();
    ev.group = group;
    ev.exact = false;
    ev.formula = formula;
    ev.reason = reason;
    m_log.push_back(ev);

    NS_LOG_INFO("[" << now.As(Time::S) << "] node " << m_self << " PARTIAL-mistrusts a group of "
                    << group.size() << " (Formula " << formula << "): " << reason);
}

bool
OlsrTrustState::IsExactMistrusted(Ipv4Address node) const
{
    return m_exact.find(node) != m_exact.end();
}

std::set<Ipv4Address>
OlsrTrustState::GetMistrusted() const
{
    std::set<Ipv4Address> out;
    for (const auto& kv : m_exact)
    {
        out.insert(kv.first);
    }
    return out;
}

void
OlsrTrustState::Expire(Time now)
{
    if (m_cfg.mistrustPermanent)
    {
        return; // nothing ever expires
    }
    for (auto it = m_exact.begin(); it != m_exact.end();)
    {
        if (it->second <= now)
        {
            NS_LOG_INFO("[" << now.As(Time::S) << "] node " << m_self << " rehabilitates " << it->first
                            << " (temporary mistrust elapsed)");
            it = m_exact.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

} // namespace olsr
} // namespace ns3
