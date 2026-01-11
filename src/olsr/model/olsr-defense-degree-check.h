// #ifndef OLSR_DEFENSE_DEGREE_CHECK_H
// #define OLSR_DEFENSE_DEGREE_CHECK_H

// #include "olsr-defense-strategy.h"
// #include <set>
// #include <vector>

// namespace ns3 {
// namespace olsr {

// class OlsrDefenseDegreeCheck : public OlsrDefenseStrategy
// {
// public:
//     static TypeId GetTypeId(void);
    
//     virtual void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) override;
//     virtual bool IsMalicious(Ipv4Address addr) override;
//     virtual std::set<Ipv4Address> GetBlacklist() const override;

//     virtual void OnRecvHello(Ipv4Address senderAddress,
//                              Ptr<const Packet> packet, 
//                              const MessageHeader& msg, 
//                              const MessageHeader::Hello& hello) override;

//     virtual void OnRecvTc(Ipv4Address senderIfaceAddr, Ptr<const Packet> packet, 
//                           const MessageHeader& msg, const MessageHeader::Tc& tc) override {}

//     virtual void OnTcGenerated(const MessageHeader::Tc& tc) override {}

//     virtual void OnDataPacketReceived(Ptr<const Packet> packet, Ipv4Address source,
//                                       Ipv4Address destination, Ipv4Address nextHop) override {}

//     virtual void OnDataPacketForwarded(Ptr<const Packet> packet, 
//                                     Ipv4Address nextHop,
//                                     Ipv4Address finalDest) override {}

//     virtual void OnDataPacketDropped(Ptr<const Packet> packet, Ipv4Address destination,
//                                      uint8_t reason) override {}

//     virtual void OnNeighborForwardedPacket(Ipv4Address neighbor, Ptr<const Packet> packet) override {}

//     virtual void PeriodicCheck() override {}

// private:
//     std::set<Ipv4Address> m_blacklist;
//     std::set<Ipv4Address> m_myNeighbors;
//     Ipv4Address m_me;
// };

// }
// }

// #endif