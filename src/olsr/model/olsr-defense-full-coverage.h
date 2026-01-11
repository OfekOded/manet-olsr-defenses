// /*
//  * Copyright (c) 2024 NS-3 Security Extension Project
//  *
//  * Author: Oded Ofek <odedofek2@gmail.com>
//  *
//  * Description: QA Strategy for verifying 100% hook coverage in OLSR.
//  */

// #ifndef OLSR_DEFENSE_FULL_COVERAGE_H
// #define OLSR_DEFENSE_FULL_COVERAGE_H

// #include "olsr-defense-strategy.h"
// #include <map>

// namespace ns3 {
// namespace olsr {

// /**
//  * \ingroup olsr
//  * \brief Integration Test Strategy.
//  *
//  * Logs every interaction to verify that hooks in RoutingProtocol
//  * are correctly placed and triggered.
//  */
// class OlsrDefenseFullCoverage : public OlsrDefenseStrategy
// {
// public:
//   static TypeId GetTypeId(void);
//   OlsrDefenseFullCoverage();
//   virtual ~OlsrDefenseFullCoverage();

//   // ==================== Lifecycle ====================
//   virtual void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) override;
//   virtual void PeriodicCheck() override;

//   // ==================== Security Logic ====================
//   virtual bool IsMalicious(Ipv4Address addr) override;
//   virtual std::set<Ipv4Address> GetBlacklist() const override;

//   // ==================== Control Plane ====================
//   virtual void OnRecvHello(Ipv4Address senderAddress,
//                            Ptr<const Packet> packet, 
//                            const MessageHeader& msg, 
//                            const MessageHeader::Hello& hello) override;

//   virtual void OnRecvTc(Ipv4Address senderIfaceAddr, 
//                         Ptr<const Packet> packet, 
//                         const MessageHeader& msg, 
//                         const MessageHeader::Tc& tc) override;

//   virtual void OnTcGenerated(const MessageHeader::Tc& tc) override;

//   // ==================== Data Plane ====================
//   virtual void OnDataPacketReceived(Ptr<const Packet> packet,
//                                     Ipv4Address source,
//                                     Ipv4Address destination,
//                                     Ipv4Address nextHop) override;

//   virtual void OnDataPacketForwarded(Ptr<const Packet> packet, 
//                                      Ipv4Address nextHop,
//                                      Ipv4Address finalDest) override;

//   virtual void OnDataPacketDropped(Ptr<const Packet> packet, 
//                                    Ipv4Address destination,
//                                    uint8_t reason) override;

//   // ==================== Promiscuous / Monitoring ====================
//   virtual void OnNeighborForwardedPacket(Ipv4Address neighbor,
//                                          Ptr<const Packet> packet) override;

// private:
//   Ipv4Address m_myAddress;
//   RoutingProtocol* m_protocol;

//   // Counters for Verification
//   uint32_t m_cntSetup;
//   uint32_t m_cntPeriodic;
//   uint32_t m_cntIsMalicious;
//   uint32_t m_cntRecvHello;
//   uint32_t m_cntRecvTc;
//   uint32_t m_cntTcGen;
//   uint32_t m_cntDataRecv;
//   uint32_t m_cntDataFwd;
//   uint32_t m_cntDataDrop;
//   uint32_t m_cntPromisc;
// };

// } // namespace olsr
// } // namespace ns3

// #endif // OLSR_DEFENSE_FULL_COVERAGE_H