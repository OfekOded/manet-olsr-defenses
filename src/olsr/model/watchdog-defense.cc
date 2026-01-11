#include "watchdog-defense.h"
#include "ns3/log.h"
#include "ns3/olsr-routing-protocol.h"

namespace ns3 {
namespace olsr {

NS_LOG_COMPONENT_DEFINE("WatchdogDefense");

NS_OBJECT_ENSURE_REGISTERED(WatchdogDefense);

TypeId
WatchdogDefense::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::olsr::WatchdogDefense")
    .SetParent<OlsrDefenseStrategy>()
    .SetGroupName("Olsr")
    .AddConstructor<WatchdogDefense>();
  return tid;
}

WatchdogDefense::WatchdogDefense()
  : m_mainAddress(Ipv4Address::GetAny()),
    m_protocol(nullptr),
    m_watchdogTimeout(Seconds(2.0)),
    m_maliciousThreshold(10)
{
}

WatchdogDefense::~WatchdogDefense()
{
}

void 
WatchdogDefense::Setup(RoutingProtocol* proto, Ipv4Address nodeAddress)
{
  m_protocol = proto;
  m_mainAddress = nodeAddress;
}

void 
WatchdogDefense::DoDispose()
{
  m_pendingPackets.clear();
  m_maliciousScore.clear();
  m_blacklist.clear();
  m_protocol = nullptr;
}

bool 
WatchdogDefense::IsMalicious(Ipv4Address addr)
{
  return m_blacklist.find(addr) != m_blacklist.end();
}

std::set<Ipv4Address> 
WatchdogDefense::GetBlacklist() const
{
  return m_blacklist;
}

void 
WatchdogDefense::OnRecvHello(Ipv4Address senderAddress,
                             Ptr<const Packet> packet, 
                             const MessageHeader& msg, 
                             const MessageHeader::Hello& hello)
{
}

void 
WatchdogDefense::OnRecvTc(Ipv4Address senderIfaceAddr, 
                          Ptr<const Packet> packet, 
                          const MessageHeader& msg, 
                          const MessageHeader::Tc& tc)
{
}

void 
WatchdogDefense::OnTcGenerated(const MessageHeader::Tc& tc)
{
}

void 
WatchdogDefense::OnDataPacketReceived(Ptr<const Packet> packet,
                                      Ipv4Address source,
                                      Ipv4Address destination,
                                      Ipv4Address nextHop)
{
}

void 
WatchdogDefense::OnDataPacketForwarded(Ptr<const Packet> packet, 
                                       Ipv4Address nextHop,
                                       Ipv4Address finalDest)
{
  if (IsMalicious(nextHop))
    {
      return;
    }

  PendingPacket pp;
  pp.timestamp = Simulator::Now();
  pp.expectedForwarder = nextHop;
  
  m_pendingPackets[packet->GetUid()] = pp;
}

void 
WatchdogDefense::OnDataPacketDropped(Ptr<const Packet> packet, 
                                     Ipv4Address source,
                                     Ipv4Address destination,
                                     DropReason reason)
{
}

void 
WatchdogDefense::OnNeighborForwardedPacket(Mac48Address transmitter, 
                                           Mac48Address receiver, 
                                           Ptr<const Packet> packet)
{
  auto it = m_pendingPackets.find(packet->GetUid());
  if (it != m_pendingPackets.end())
    {
      m_pendingPackets.erase(it);
    }
}

void 
WatchdogDefense::PeriodicCheck()
{
  Time now = Simulator::Now();
  auto it = m_pendingPackets.begin();

  while (it != m_pendingPackets.end())
    {
      if (now - it->second.timestamp > m_watchdogTimeout)
        {
          Ipv4Address suspect = it->second.expectedForwarder;
          m_maliciousScore[suspect]++;

          if (m_maliciousScore[suspect] > m_maliciousThreshold)
            {
              m_blacklist.insert(suspect);
            }

          it = m_pendingPackets.erase(it);
        }
      else
        {
          ++it;
        }
    }
}

} 
}