/*
 * Trust-based OLSR defense (Adnane et al., Computer Communications 36, 2013)
 * olsr-forward-monitor.cc -- Formula (10) forward monitoring / wait event.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "olsr-forward-monitor.h"

#include "../olsr-header.h"
#include "../olsr-routing-protocol.h"

#include "ns3/ipv4-header.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/udp-header.h"

namespace ns3
{
namespace olsr
{

NS_LOG_COMPONENT_DEFINE("OlsrForwardMonitor");

// IP protocol number for UDP (OLSR control + the UDP data used in experiments).
static constexpr uint8_t IP_PROTO_UDP = 17;

OlsrForwardMonitor::OlsrForwardMonitor(const OlsrTrustDefenseConfig& cfg,
                                       RoutingProtocol* proto,
                                       Ipv4Address self,
                                       ForwardFailureCallback onFailure)
    : m_cfg(cfg),
      m_proto(proto),
      m_self(self),
      m_onFailure(std::move(onFailure)),
      m_running(false)
{
}

void
OlsrForwardMonitor::Start()
{
    m_running = true;
    m_sweepEvent = Simulator::Schedule(m_cfg.checkInterval, &OlsrForwardMonitor::Sweep, this);
}

void
OlsrForwardMonitor::Stop()
{
    m_running = false;
    m_sweepEvent.Cancel();
    m_dataPending.clear();
    m_tcPending.clear();
    m_macToIp.clear();
    m_failCount.clear();
}

void
OlsrForwardMonitor::OnDataForward(Ptr<const Packet> p,
                                  Ipv4Address nextHop,
                                  Ipv4Address dst,
                                  bool originatedHere,
                                  Time now)
{
    if (!m_running || !m_cfg.monitorData)
    {
        return;
    }
    // Default scope == DATAx (faithful to Formula 10): only traffic x originated.
    // Relayed traffic is watched only if explicitly enabled (generalized watchdog).
    if (!originatedHere && !m_cfg.monitorRelayedData)
    {
        return;
    }
    // Last-hop guard: if the next hop IS the final destination, it consumes the
    // packet and is NOT expected to re-air it. Watching for a (never-coming)
    // retransmission would falsely accuse the destination, so do not register.
    if (nextHop == dst)
    {
        return;
    }
    // Formula 10 is MPR-scoped: only register when the next hop is one of x's MPRs.
    MprSet mprs = m_proto->GetMprSet();
    if (mprs.find(nextHop) == mprs.end())
    {
        return;
    }

    DataRecord rec;
    rec.nextHop = nextHop;
    rec.dst = dst;
    rec.originatedHere = originatedHere;
    rec.deadline = now + m_cfg.forwardTimeout;
    m_dataPending[p->GetUid()] = rec;

    NS_LOG_LOGIC("node " << m_self << " awaiting forward of DATA uid=" << p->GetUid() << " by MPR "
                         << nextHop << " (dst " << dst << "), deadline " << rec.deadline.As(Time::S));
}

void
OlsrForwardMonitor::OnTcGenerated(Time now)
{
    if (!m_running || !m_cfg.monitorTc)
    {
        return;
    }
    // A node's own TCx must be re-flooded by exactly its MPR set (MPRSx): in OLSR
    // a neighbour re-floods a broadcast only if the originator selected it as MPR.
    MprSet mprs = m_proto->GetMprSet();
    if (mprs.empty())
    {
        return; // no MPRs -> nobody is expected to forward -> nothing to watch.
    }
    TcRecord rec;
    rec.pendingForwarders.insert(mprs.begin(), mprs.end());
    rec.deadline = now + m_cfg.forwardTimeout;
    m_tcPending.push_back(rec);

    NS_LOG_LOGIC("node " << m_self << " awaiting TC re-flood by " << mprs.size()
                         << " MPR(s), deadline " << rec.deadline.As(Time::S));
}

void
OlsrForwardMonitor::OnLocalDrop(Ptr<const Packet> p)
{
    // We dropped the packet ourselves -> it was never handed to the MPR, so do
    // not let it time out and wrongly accuse the MPR.
    m_dataPending.erase(p->GetUid());
}

void
OlsrForwardMonitor::OnOverheard(Mac48Address tx, Mac48Address rx, Ptr<const Packet> pkt, Time now)
{
    if (!m_running)
    {
        return;
    }
    Ptr<Packet> copy = pkt->Copy();
    Ipv4Header ip;
    if (copy->GetSize() < ip.GetSerializedSize())
    {
        return;
    }
    copy->RemoveHeader(ip);

    if (ip.GetProtocol() == IP_PROTO_UDP)
    {
        UdpHeader udp;
        if (copy->GetSize() >= udp.GetSerializedSize())
        {
            copy->PeekHeader(udp);
            if (udp.GetDestinationPort() == RoutingProtocol::OLSR_PORT_NUMBER)
            {
                copy->RemoveHeader(udp);
                // For a hop-by-hop OLSR control packet the IP source is the
                // immediate sender == the forwarder that re-aired the message.
                HandleOverheardOlsr(tx, ip.GetSource(), copy, now);
                return;
            }
        }
    }

    // Anything else is treated as a DATA frame: match by packet UID.
    HandleOverheardData(tx, pkt, now);
}

void
OlsrForwardMonitor::HandleOverheardData(Mac48Address tx, Ptr<const Packet> pkt, Time now)
{
    auto it = m_dataPending.find(pkt->GetUid());
    if (it == m_dataPending.end())
    {
        return;
    }
    if (m_cfg.strictMacAttribution)
    {
        auto mit = m_macToIp.find(tx);
        if (mit == m_macToIp.end() || mit->second != it->second.nextHop)
        {
            return; // cannot confirm the expected MPR re-aired it; let it time out.
        }
    }
    // Forward observed: the MPR did its job. Clear the record and reset its
    // consecutive-failure counter.
    NS_LOG_LOGIC("node " << m_self << " overheard MPR " << it->second.nextHop
                         << " forward DATA uid=" << pkt->GetUid());
    m_failCount[it->second.nextHop] = 0;
    m_dataPending.erase(it);
}

void
OlsrForwardMonitor::HandleOverheardOlsr(Mac48Address tx, Ipv4Address srcIp, Ptr<Packet> olsr, Time now)
{
    m_macToIp[tx] = srcIp; // learn MAC<->IP for (optional) strict DATA attribution.

    PacketHeader ph;
    if (olsr->GetSize() < ph.GetSerializedSize())
    {
        return;
    }
    olsr->RemoveHeader(ph);
    if (ph.GetPacketLength() < ph.GetSerializedSize())
    {
        return;
    }
    uint32_t sizeLeft = ph.GetPacketLength() - ph.GetSerializedSize();
    while (sizeLeft > 0 && olsr->GetSize() > 0)
    {
        MessageHeader mh;
        if (olsr->RemoveHeader(mh) == 0)
        {
            break;
        }
        uint32_t msz = mh.GetSerializedSize();
        sizeLeft = (sizeLeft >= msz) ? (sizeLeft - msz) : 0;

        if (mh.GetMessageType() == MessageHeader::TC_MESSAGE &&
            mh.GetOriginatorAddress() == m_self)
        {
            // Someone re-aired MY TCx -> credit the forwarder (the immediate sender).
            CreditTcForward(srcIp, now);
        }
    }
}

void
OlsrForwardMonitor::CreditTcForward(Ipv4Address forwarder, Time now)
{
    for (auto it = m_tcPending.begin(); it != m_tcPending.end(); ++it)
    {
        auto f = it->pendingForwarders.find(forwarder);
        if (f != it->pendingForwarders.end())
        {
            NS_LOG_LOGIC("node " << m_self << " overheard MPR " << forwarder << " re-flood my TC");
            it->pendingForwarders.erase(f);
            m_failCount[forwarder] = 0;
            if (it->pendingForwarders.empty())
            {
                m_tcPending.erase(it);
            }
            return;
        }
    }
}

void
OlsrForwardMonitor::RaiseFailure(Ipv4Address mpr, ForwardFailureType type, Time now)
{
    uint32_t c = ++m_failCount[mpr];
    NS_LOG_INFO("[" << now.As(Time::S) << "] node " << m_self << " forward-FAILURE: MPR " << mpr
                    << " did not forward " << (type == ForwardFailureType::Data ? "DATA" : "TC")
                    << " (consecutive=" << c << ")");
    if (c >= m_cfg.minForwardFailures && m_onFailure)
    {
        m_onFailure(mpr, type, c, now); // internal error -> Formula 10 decision (in the owner).
    }
}

void
OlsrForwardMonitor::Sweep()
{
    Time now = Simulator::Now();

    for (auto it = m_dataPending.begin(); it != m_dataPending.end();)
    {
        if (it->second.deadline <= now)
        {
            RaiseFailure(it->second.nextHop, ForwardFailureType::Data, now);
            it = m_dataPending.erase(it);
        }
        else
        {
            ++it;
        }
    }

    for (auto it = m_tcPending.begin(); it != m_tcPending.end();)
    {
        if (it->deadline <= now)
        {
            for (const auto& fwd : it->pendingForwarders)
            {
                RaiseFailure(fwd, ForwardFailureType::Tc, now);
            }
            it = m_tcPending.erase(it);
        }
        else
        {
            ++it;
        }
    }

    if (m_running)
    {
        m_sweepEvent = Simulator::Schedule(m_cfg.checkInterval, &OlsrForwardMonitor::Sweep, this);
    }
}

} // namespace olsr
} // namespace ns3
