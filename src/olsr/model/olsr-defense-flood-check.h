// #ifndef OLSR_DEFENSE_FLOOD_CHECK_H
// #define OLSR_DEFENSE_FLOOD_CHECK_H

// #include "olsr-defense-strategy.h"
// #include <map>
// #include <set>

// namespace ns3 {
// namespace olsr {

// class OlsrDefenseFloodCheck : public OlsrDefenseStrategy
// {
// public:
//     static TypeId GetTypeId(void);
    
//     virtual void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) override;
//     virtual bool IsMalicious(Ipv4Address addr) override;
//     virtual std::set<Ipv4Address> GetBlacklist() const override;

//     // לא בשימוש כרגע
//     virtual void OnRecvHello(Ipv4Address, Ptr<const Packet>, const MessageHeader&, const MessageHeader::Hello&) override {}
//     virtual void OnRecvTc(Ipv4Address, Ptr<const Packet>, const MessageHeader&, const MessageHeader::Tc&) override {}
//     virtual void OnTcGenerated(const MessageHeader::Tc&) override {}
//     virtual void OnDataPacketForwarded(Ptr<const Packet> packet, 
//                                     Ipv4Address nextHop,
//                                     Ipv4Address finalDest) override {}
//     virtual void OnDataPacketDropped(Ptr<const Packet>, Ipv4Address, uint8_t) override {}
//     virtual void OnNeighborForwardedPacket(Ipv4Address, Ptr<const Packet>) override {}

//     // === הפונקציות הנבדקות ===
    
//     // נקראת על כל חבילה שנכנסת לניתוב
//     virtual void OnDataPacketReceived(Ptr<const Packet> packet, Ipv4Address source,
//                                       Ipv4Address destination, Ipv4Address nextHop) override;

//     // מאפסת את המונים ובודקת חריגות
//     virtual void PeriodicCheck() override;

// private:
//     Ipv4Address m_me;
//     std::set<Ipv4Address> m_blacklist;

//     // מונה חבילות לכל מקור (Source IP -> Count)
//     std::map<Ipv4Address, uint32_t> m_packetCounts;
    
//     // סף לחסימה (חבילות לשנייה)
//     uint32_t m_threshold; 
// };

// }
// }

// #endif