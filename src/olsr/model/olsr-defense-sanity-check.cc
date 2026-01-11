#include "olsr-defense-sanity-check.h"

namespace ns3 {
namespace olsr {

NS_OBJECT_ENSURE_REGISTERED(OlsrDefenseSanityCheck);

TypeId
OlsrDefenseSanityCheck::GetTypeId(void)
{
  static TypeId tid = TypeId("ns3::olsr::OlsrDefenseSanityCheck")
    .SetParent<OlsrDefenseStrategy>()
    .SetGroupName("Olsr")
    .AddConstructor<OlsrDefenseSanityCheck>();
  return tid;
}

OlsrDefenseSanityCheck::OlsrDefenseSanityCheck()
{
}

OlsrDefenseSanityCheck::~OlsrDefenseSanityCheck()
{
}

void 
OlsrDefenseSanityCheck::Setup(RoutingProtocol* proto, Ipv4Address nodeAddress)
{
  std::cout << "HOOK-CHECK: Setup | Node Address: " << nodeAddress << std::endl;
}

void 
OlsrDefenseSanityCheck::DoDispose()
{
  std::cout << "HOOK-CHECK: DoDispose" << std::endl;
}

bool 
OlsrDefenseSanityCheck::IsMalicious(Ipv4Address addr)
{
  std::cout << "HOOK-CHECK: IsMalicious | Address: " << addr << std::endl;
  return false;
}

std::set<Ipv4Address> 
OlsrDefenseSanityCheck::GetBlacklist() const
{
  std::cout << "HOOK-CHECK: GetBlacklist" << std::endl;
  return std::set<Ipv4Address>();
}

void 
OlsrDefenseSanityCheck::OnRecvHello(Ipv4Address senderAddress,
                                    Ptr<const Packet> packet, 
                                    const MessageHeader& msg, 
                                    const MessageHeader::Hello& hello)
{
  std::cout << "HOOK-CHECK: OnRecvHello | Sender: " << senderAddress 
            << " | Packet UID: " << packet->GetUid() << std::endl;
}

void 
OlsrDefenseSanityCheck::OnRecvTc(Ipv4Address senderIfaceAddr, 
                                 Ptr<const Packet> packet, 
                                 const MessageHeader& msg, 
                                 const MessageHeader::Tc& tc)
{
  std::cout << "HOOK-CHECK: OnRecvTc | Sender: " << senderIfaceAddr 
            << " | Packet UID: " << packet->GetUid() << std::endl;
}

void 
OlsrDefenseSanityCheck::OnTcGenerated(const MessageHeader::Tc& tc)
{
  std::cout << "HOOK-CHECK: OnTcGenerated" << std::endl;
}

void 
OlsrDefenseSanityCheck::OnDataPacketReceived(Ptr<const Packet> packet,
                                             Ipv4Address source,
                                             Ipv4Address destination,
                                             Ipv4Address nextHop)
{
  std::cout << "HOOK-CHECK: OnDataPacketReceived | Source: " << source 
            << " | Dest: " << destination 
            << " | NextHop: " << nextHop 
            << " | UID: " << packet->GetUid() << std::endl;
}

void 
OlsrDefenseSanityCheck::OnDataPacketForwarded(Ptr<const Packet> packet, 
                                              Ipv4Address nextHop,
                                              Ipv4Address finalDest)
{
  std::cout << "HOOK-CHECK: OnDataPacketForwarded | NextHop: " << nextHop 
            << " | FinalDest: " << finalDest 
            << " | UID: " << packet->GetUid() << std::endl;
}

void 
OlsrDefenseSanityCheck::OnDataPacketDropped(Ptr<const Packet> packet, 
                                            Ipv4Address source,
                                            Ipv4Address destination,
                                            DropReason reason)
{
  std::cout << "HOOK-CHECK: OnDataPacketDropped | Source: " << source 
            << " | Dest: " << destination 
            << " | Reason ID: " << (int)reason << std::endl;
}

void 
OlsrDefenseSanityCheck::OnNeighborForwardedPacket(Mac48Address transmitter,
                                                  Mac48Address receiver, 
                                                  Ptr<const Packet> packet)
{
  std::cout << "HOOK-CHECK: OnNeighborForwardedPacket | TX: " << transmitter 
            << " | RX: " << receiver 
            << " | UID: " << packet->GetUid() << std::endl;
}

void 
OlsrDefenseSanityCheck::PeriodicCheck()
{
  std::cout << "HOOK-CHECK: PeriodicCheck" << std::endl;
}

} 
}