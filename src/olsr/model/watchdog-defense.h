#ifndef WATCHDOG_DEFENSE_H
#define WATCHDOG_DEFENSE_H

#include "olsr-defense-strategy.h"
#include "ns3/nstime.h"
#include "ns3/simulator.h"
#include <map>
#include <set>

namespace ns3 {
namespace olsr {

class WatchdogDefense : public OlsrDefenseStrategy
{
public:
  static TypeId GetTypeId(void);
  WatchdogDefense();
  virtual ~WatchdogDefense();

  virtual void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) override;
  virtual void DoDispose() override;

  virtual bool IsMalicious(Ipv4Address addr) override;
  virtual std::set<Ipv4Address> GetBlacklist() const override;

  virtual void OnRecvHello(Ipv4Address senderAddress,
                           Ptr<const Packet> packet, 
                           const MessageHeader& msg, 
                           const MessageHeader::Hello& hello) override;

  virtual void OnRecvTc(Ipv4Address senderIfaceAddr, 
                        Ptr<const Packet> packet, 
                        const MessageHeader& msg, 
                        const MessageHeader::Tc& tc) override;

  virtual void OnTcGenerated(const MessageHeader::Tc& tc) override;

  virtual void OnDataPacketReceived(Ptr<const Packet> packet,
                                    Ipv4Address source,
                                    Ipv4Address destination,
                                    Ipv4Address nextHop) override;

  virtual void OnDataPacketForwarded(Ptr<const Packet> packet, 
                                     Ipv4Address nextHop,
                                     Ipv4Address finalDest) override;

  virtual void OnDataPacketDropped(Ptr<const Packet> packet, 
                                   Ipv4Address source,
                                   Ipv4Address destination,
                                   DropReason reason) override;

  virtual void OnNeighborForwardedPacket(Mac48Address transmitter, 
                                         Mac48Address receiver, 
                                         Ptr<const Packet> packet) override;

  virtual void PeriodicCheck() override;

private:
  struct PendingPacket
  {
    Time timestamp;
    Ipv4Address expectedForwarder;
  };

  Ipv4Address m_mainAddress;
  RoutingProtocol* m_protocol;
  
  std::map<uint64_t, PendingPacket> m_pendingPackets;
  std::map<Ipv4Address, uint32_t> m_maliciousScore;
  std::set<Ipv4Address> m_blacklist;

  Time m_watchdogTimeout;
  uint32_t m_maliciousThreshold;
};

} 
} 

#endif