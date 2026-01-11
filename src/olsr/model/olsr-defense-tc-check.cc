// #include "olsr-defense-tc-check.h"
// #include "ns3/log.h"
// #include <iostream>

// namespace ns3 {
// namespace olsr {

// NS_LOG_COMPONENT_DEFINE("OlsrDefenseTcCheck");
// NS_OBJECT_ENSURE_REGISTERED(OlsrDefenseTcCheck);

// TypeId
// OlsrDefenseTcCheck::GetTypeId(void)
// {
//     static TypeId tid = TypeId("ns3::olsr::OlsrDefenseTcCheck")
//       .SetParent<OlsrDefenseStrategy>()
//       .SetGroupName("Olsr")
//       .AddConstructor<OlsrDefenseTcCheck>();
//     return tid;
// }

// void 
// OlsrDefenseTcCheck::Setup(RoutingProtocol* proto, Ipv4Address nodeAddress)
// {
//     m_me = nodeAddress;
// }

// bool 
// OlsrDefenseTcCheck::IsMalicious(Ipv4Address addr)
// {
//     return m_blacklist.find(addr) != m_blacklist.end();
// }

// std::set<Ipv4Address> 
// OlsrDefenseTcCheck::GetBlacklist() const
// {
//     return m_blacklist;
// }

// void 
// OlsrDefenseTcCheck::OnRecvTc(Ipv4Address senderIfaceAddr, 
//                              Ptr<const Packet> packet, 
//                              const MessageHeader& msg, 
//                              const MessageHeader::Tc& tc)
// {
//     uint32_t advertisedNeighbors = tc.neighborAddresses.size();

//     if (advertisedNeighbors > 2)
//     {
//         Ipv4Address originator = msg.GetOriginatorAddress();
        
//         if (m_blacklist.find(originator) == m_blacklist.end() && originator != m_me)
//         {
//             std::cout << "[DEFENSE ALERT] TC CHECK: Node " << m_me 
//                       << " detected malicious node: " << originator 
//                       << " (Advertised " << advertisedNeighbors << " neighbors via TC)" << std::endl;
            
//             m_blacklist.insert(originator);
//         }
//     }
// }

// }
// }