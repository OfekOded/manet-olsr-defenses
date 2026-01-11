// #include "olsr-defense-degree-check.h"
// #include "ns3/log.h"
// #include <iostream>

// namespace ns3 {
// namespace olsr {

// NS_LOG_COMPONENT_DEFINE("OlsrDefenseDegreeCheck");
// NS_OBJECT_ENSURE_REGISTERED(OlsrDefenseDegreeCheck);

// TypeId
// OlsrDefenseDegreeCheck::GetTypeId(void)
// {
//     static TypeId tid = TypeId("ns3::olsr::OlsrDefenseDegreeCheck")
//       .SetParent<OlsrDefenseStrategy>()
//       .SetGroupName("Olsr")
//       .AddConstructor<OlsrDefenseDegreeCheck>();
//     return tid;
// }

// void 
// OlsrDefenseDegreeCheck::Setup(RoutingProtocol* proto, Ipv4Address nodeAddress)
// {
//     m_me = nodeAddress;
// }

// bool 
// OlsrDefenseDegreeCheck::IsMalicious(Ipv4Address addr)
// {
//     return m_blacklist.find(addr) != m_blacklist.end();
// }

// std::set<Ipv4Address> 
// OlsrDefenseDegreeCheck::GetBlacklist() const
// {
//     return m_blacklist;
// }

// void 
// OlsrDefenseDegreeCheck::OnRecvHello(Ipv4Address senderAddress,
//                                     Ptr<const Packet> packet, 
//                                     const MessageHeader& msg, 
//                                     const MessageHeader::Hello& hello)
// {
//     m_myNeighbors.insert(senderAddress);

//     uint32_t senderDegree = 0;
//     for (const auto& linkMsg : hello.linkMessages)
//     {
//         senderDegree += linkMsg.neighborInterfaceAddresses.size();
//     }

//     uint32_t myDegree = m_myNeighbors.size();

//     if (myDegree > 0 && senderDegree > (myDegree * 1.5))
//     {
//         if (m_blacklist.find(senderAddress) == m_blacklist.end())
//         {
//             std::cout << "[DEFENSE ALERT] Node " << m_me 
//                       << " detected malicious node: " << senderAddress 
//                       << " (Sender Degree: " << senderDegree 
//                       << ", My Degree: " << myDegree << ")" << std::endl;
            
//             m_blacklist.insert(senderAddress);
//         }
//     }
// }

// }
// }