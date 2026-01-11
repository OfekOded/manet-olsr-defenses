// #include "olsr-defense-flood-check.h"
// #include "ns3/log.h"
// #include "ns3/simulator.h" // בשביל הטיימר
// #include <iostream>

// namespace ns3 {
// namespace olsr {

// NS_LOG_COMPONENT_DEFINE("OlsrDefenseFloodCheck");
// NS_OBJECT_ENSURE_REGISTERED(OlsrDefenseFloodCheck);

// TypeId
// OlsrDefenseFloodCheck::GetTypeId(void)
// {
//     static TypeId tid = TypeId("ns3::olsr::OlsrDefenseFloodCheck")
//       .SetParent<OlsrDefenseStrategy>()
//       .SetGroupName("Olsr")
//       .AddConstructor<OlsrDefenseFloodCheck>();
//     return tid;
// }

// void 
// OlsrDefenseFloodCheck::Setup(RoutingProtocol* proto, Ipv4Address nodeAddress)
// {
//     m_me = nodeAddress;
//     m_threshold = 100; // נגיד ש-100 חבילות בשנייה זה המקסימום המותר
    
//     // הפעלת הטיימר של עצמנו (כמו שלמדנו מהטעות הקודמת - עכשיו הפרוטוקול מפעיל אותנו אז לא צריך כאן Schedule)
//     // הערה: אם אתה משתמש ב-RoutingProtocol העדכני ששלחת לי קודם, אל תוסיף פה Schedule!
// }

// bool 
// OlsrDefenseFloodCheck::IsMalicious(Ipv4Address addr)
// {
//     return m_blacklist.find(addr) != m_blacklist.end();
// }

// std::set<Ipv4Address> 
// OlsrDefenseFloodCheck::GetBlacklist() const
// {
//     return m_blacklist;
// }

// void 
// OlsrDefenseFloodCheck::OnDataPacketReceived(Ptr<const Packet> packet, Ipv4Address source,
//                                             Ipv4Address destination, Ipv4Address nextHop)
// {
//     // אנחנו לא רוצים לספור חבילות שאנחנו עצמנו יצרנו
//     if (source == m_me) return;

//     m_packetCounts[source]++;
// }

// void 
// OlsrDefenseFloodCheck::PeriodicCheck()
// {
//     // 1. מעבר על כל המונים
//     for (auto const& [source, count] : m_packetCounts)
//     {
//         if (count > m_threshold)
//         {
//             if (m_blacklist.find(source) == m_blacklist.end())
//             {
//                 std::cout << "[DEFENSE ALERT] FLOOD CHECK: Node " << m_me 
//                           << " detected DOS ATTACK from: " << source 
//                           << " (Sent " << count << " packets/sec)" << std::endl;
                
//                 m_blacklist.insert(source);
//             }
//         }
//     }

//     // 2. איפוס המונים לשנייה הבאה
//     m_packetCounts.clear();
// }

// }
// }