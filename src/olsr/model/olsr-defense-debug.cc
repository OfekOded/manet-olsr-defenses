#include "olsr-defense-debug.h"
#include "ns3/log.h"
#include "ns3/ipv4-address.h"
#include "ns3/mac48-address.h"
#include <iostream>

namespace ns3 {
namespace olsr {

NS_OBJECT_ENSURE_REGISTERED (OlsrDefenseDebug);

TypeId
OlsrDefenseDebug::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::olsr::OlsrDefenseDebug")
    .SetParent<OlsrDefenseStrategy> ()
    .SetGroupName ("Olsr")
    .AddConstructor<OlsrDefenseDebug> ();
  return tid;
}

void 
OlsrDefenseDebug::Setup(RoutingProtocol* proto, Ipv4Address nodeAddress)
{
  std::cout << "[DefenseDebug] Setup invoked. Node Address: " << nodeAddress << std::endl;
}

void 
OlsrDefenseDebug::DoDispose()
{
  std::cout << "[DefenseDebug] DoDispose invoked." << std::endl;
}

bool 
OlsrDefenseDebug::IsMalicious(Ipv4Address addr)
{
  // Debug logic: No one is malicious
  return false;
}

std::set<Ipv4Address> 
OlsrDefenseDebug::GetBlacklist() const
{
  return std::set<Ipv4Address>();
}

void 
OlsrDefenseDebug::OnRecvHello(Ipv4Address senderAddress,
                              Ptr<const Packet> packet, 
                              const MessageHeader& msg, 
                              const MessageHeader::Hello& hello)
{
  std::cout << "[DefenseDebug] OnRecvHello from " << senderAddress << std::endl;
}

void 
OlsrDefenseDebug::OnRecvTc (Ipv4Address senderIfaceAddr, 
                            Ptr<const Packet> packet, 
                            const MessageHeader& msg, 
                            const MessageHeader::Tc& tc)
{
  std::cout << "[DefenseDebug] OnRecvTc from " << senderIfaceAddr << std::endl;
}

void 
OlsrDefenseDebug::OnTcGenerated(const MessageHeader::Tc& tc)
{
  std::cout << "[DefenseDebug] OnTcGenerated. ANSN: " << tc.ansn << std::endl;
}

void 
OlsrDefenseDebug::OnDataPacketReceived(Ptr<const Packet> packet,
                                       Ipv4Address source,
                                       Ipv4Address destination,
                                       Ipv4Address nextHop)
{
  std::cout << "[DefenseDebug] Data Received: " << source << " -> " << destination << std::endl;
}

void 
OlsrDefenseDebug::OnDataPacketForwarded(Ptr<const Packet> packet, 
                                        Ipv4Address nextHop,
                                        Ipv4Address finalDest)
{
  std::cout << "[DefenseDebug] Data Forwarded to: " << nextHop << " (Final: " << finalDest << ")" << std::endl;
}

void 
OlsrDefenseDebug::OnDataPacketDropped(Ptr<const Packet> packet, 
                                      Ipv4Address source,
                                      Ipv4Address destination,
                                      DropReason reason)
{
  std::cout << "[DefenseDebug] Data Dropped (" << source << "->" << destination << ") Reason: " << (int)reason << std::endl;
}

void 
OlsrDefenseDebug::OnNeighborForwardedPacket(Mac48Address transmitter,
                                            Mac48Address receiver, Ptr<const Packet> packet)
{
  std::cout << "[DefenseDebug] Neighbor Promiscuous: " << transmitter << " -> " << receiver << std::endl;
}

void 
OlsrDefenseDebug::OnQueueStatusReport(uint32_t size, uint32_t capacity)
{
  double occupancy = 0.0;
  if (capacity > 0)
  {
    occupancy = (double) size / (double) capacity;
  }

  std::string state;
  if (size == 0)
  {
    state = "EMPTY";
  }
  else if (occupancy < 0.5)
  {
    state = "LOW";
  }
  else if (occupancy < 0.9)
  {
    state = "MEDIUM";
  }
  else
  {
    state = "HIGH";
  }

  std::cout 
    << "[DefenseDebug][QueueStatus] "
    << "Size=" << size 
    << " / Capacity=" << capacity
    << " (" << (occupancy * 100.0) << "%)"
    << " State=" << state
    << std::endl;
}


void 
OlsrDefenseDebug::PeriodicCheck()
{
  std::cout << "[DefenseDebug] Periodic check." << std::endl;
}

} // namespace olsr
} // namespace ns3