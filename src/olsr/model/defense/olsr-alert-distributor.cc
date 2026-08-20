/*
 * Trust-based OLSR defense (Adnane et al., Computer Communications 36, 2013)
 * olsr-alert-distributor.cc -- §7 trust-information distribution (idealized bus).
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "olsr-alert-distributor.h"

#include "ns3/log.h"

#include <algorithm>
#include <sstream>

namespace ns3
{
namespace olsr
{

NS_LOG_COMPONENT_DEFINE("OlsrAlertDistributor");

namespace
{
bool
Contains(const std::vector<Ipv4Address>& v, Ipv4Address a)
{
    return std::find(v.begin(), v.end(), a) != v.end();
}
} // namespace

bool
ConsistencyProof::Verify(Ipv4Address accuser) const
{
    if (formula == "6")
    {
        // Some advertised MPR-selector was never advertised as a symmetric neighbour.
        for (const auto& s : advertised)
        {
            if (!Contains(reference, s))
            {
                return true;
            }
        }
        return false;
    }
    if (formula == "7")
    {
        // Accused's TC lists the accuser as a selector, yet the accuser (reference =
        // its own MPR set) never selected the accused as MPR.
        return Contains(advertised, accuser) && !Contains(reference, accused);
    }
    if (formula == "5.1e")
    {
        // Section 5.1e: the accused's TC must name the witness, and the witness's own HELLO
        // declaration (carried as the reference) must not name the accused.
        return Contains(advertised, witness) && !Contains(reference, accused);
    }
    // (8),(12) not yet produced; reject unknown/unverifiable proofs (no blind trust).
    return false;
}

// ---------------------------------------------------------------------------
// OlsrTrustBus
// ---------------------------------------------------------------------------
OlsrTrustBus&
OlsrTrustBus::Instance()
{
    static OlsrTrustBus instance;
    return instance;
}

void
OlsrTrustBus::Register(OlsrAlertDistributor* d)
{
    if (d && std::find(m_nodes.begin(), m_nodes.end(), d) == m_nodes.end())
    {
        m_nodes.push_back(d);
    }
}

void
OlsrTrustBus::Unregister(OlsrAlertDistributor* d)
{
    m_nodes.erase(std::remove(m_nodes.begin(), m_nodes.end(), d), m_nodes.end());
}

void
OlsrTrustBus::Broadcast(const TrustAlert& a, OlsrAlertDistributor* from, Time now)
{
    // Idealized network-wide flood: deliver to every other registered node.
    // Iterate over a copy so a Deliver() that re-announces cannot invalidate it.
    std::vector<OlsrAlertDistributor*> snapshot = m_nodes;
    for (auto* d : snapshot)
    {
        if (d != from)
        {
            d->Deliver(a, now);
        }
    }
}

// ---------------------------------------------------------------------------
// OlsrAlertDistributor
// ---------------------------------------------------------------------------
OlsrAlertDistributor::OlsrAlertDistributor(Ipv4Address self, AcceptCallback onAccept)
    : m_self(self),
      m_onAccept(std::move(onAccept)),
      m_running(false)
{
}

OlsrAlertDistributor::~OlsrAlertDistributor()
{
    OlsrTrustBus::Instance().Unregister(this); // safety against dangling pointers across runs.
}

void
OlsrAlertDistributor::Start()
{
    m_running = true;
    // NOTE: the process-wide OlsrTrustBus is no longer used. Section 7 alerts are
    // retransmitted control messages carried by real OLSR broadcast (see
    // RoutingProtocol::BroadcastTrustAlert), so there is no verdict to deliver
    // out of band. The bus type is retained only so older scenarios still link.
}

void
OlsrAlertDistributor::Stop()
{
    m_running = false;
    OlsrTrustBus::Instance().Unregister(this);
    m_seen.clear();
}

std::string
OlsrAlertDistributor::Key(const TrustAlert& a)
{
    std::ostringstream os;
    os << a.accuser << '|' << a.proof.accused << '|' << a.proof.formula;
    return os.str();
}

bool
OlsrAlertDistributor::ShouldAnnounce(const ConsistencyProof& proof, Time now)
{
    if (!m_running)
    {
        return false;
    }
    std::ostringstream os;
    os << m_self << '|' << proof.accused << '|' << proof.formula;
    const std::string k = os.str();
    if (m_seen.find(k) != m_seen.end())
    {
        return false;
    }
    m_seen.insert(k);
    NS_LOG_INFO("[" << now.As(Time::S) << "] node " << m_self
                    << " ANNOUNCES alert: retransmitting the " << proof.evidence.size()
                    << " control message(s) that incriminate " << proof.accused
                    << " (Formula " << proof.formula << ")");
    return true;
}

void
OlsrAlertDistributor::Announce(const ConsistencyProof& proof, Time now)
{
    if (!m_running)
    {
        return;
    }
    TrustAlert a;
    a.accuser = m_self;
    a.proof = proof;
    m_seen.insert(Key(a)); // do not re-accept our own alert.
    NS_LOG_INFO("[" << now.As(Time::S) << "] node " << m_self << " ANNOUNCES alert: accused="
                    << proof.accused << " Formula(" << proof.formula << ")");
    OlsrTrustBus::Instance().Broadcast(a, this, now);
}

void
OlsrAlertDistributor::Deliver(const TrustAlert& a, Time now)
{
    if (!m_running || a.proof.accused == m_self)
    {
        return; // never mistrust ourselves from an alert.
    }
    const std::string k = Key(a);
    if (m_seen.find(k) != m_seen.end())
    {
        return; // dedup.
    }
    m_seen.insert(k);

    // Re-verify the carried proof before accepting (no blind trust of a verdict).
    if (!a.proof.Verify(a.accuser))
    {
        NS_LOG_LOGIC("node " << m_self << " rejected alert (proof does not verify) from " << a.accuser);
        return;
    }
    NS_LOG_INFO("[" << now.As(Time::S) << "] node " << m_self << " ACCEPTS alert: accused="
                    << a.proof.accused << " Formula(" << a.proof.formula << ") from " << a.accuser);
    if (m_onAccept)
    {
        m_onAccept(a.proof, a.accuser, now);
    }
}

} // namespace olsr
} // namespace ns3
