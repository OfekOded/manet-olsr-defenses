/*
 * Copyright (c) 2024 NS-3 Security Extension Project
 *
 * Author: Oded Ofek <odedofek2@gmail.com>
 *
 * olsr-defense-strategy.h -- the abstraction both trust-based defenses in this
 * fork are written against.
 *
 * RoutingProtocol owns exactly one OlsrDefenseStrategy, chosen through its
 * "DefenseStrategy" attribute, and calls into it at fixed points: a control
 * message arrived or was generated, a data packet was forwarded or dropped,
 * the promiscuous sniffer saw a frame, a periodic timer fired. The strategy
 * answers one question back -- IsMalicious() -- plus the richer accessors
 * below.
 *
 * The split is deliberate and worth preserving: the STRATEGY decides who is
 * untrustworthy, the ROUTING PROTOCOL decides what to do about it. Detection
 * and response are separately measurable that way, which is what the papers
 * report.
 *
 * OlsrDefenseNull is the default: it answers "nobody is malicious" to
 * everything. The evaluation harness swaps it in and out to turn the defense
 * off for half of each run's measurement windows without rebuilding.
 *
 * Hooks added for one specific defense are declared NON-PURE with a harmless
 * default, so a defense that does not participate in that mechanism needs no
 * code for it at all. Only the hooks every defense must answer are pure.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef OLSR_DEFENSE_STRATEGY_H
#define OLSR_DEFENSE_STRATEGY_H

#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/ipv4-address.h"
#include "ns3/mac48-address.h" 
#include "olsr-header.h"
#include <set>

namespace ns3 {
namespace olsr {

class RoutingProtocol;

/**
 * @ingroup olsr
 * @brief Why the routing protocol gave up on a data packet.
 *
 * Passed to OlsrDefenseStrategy::OnDataPacketDropped so a defense can tell a
 * drop it should hold someone responsible for apart from an ordinary local
 * failure it should not.
 */
enum DropReason : uint8_t {
    DROP_NO_ROUTE = 0,    //!< No route to the destination.
    DROP_TTL_EXPIRED = 1, //!< Hop limit reached zero.
    DROP_QUEUE_FULL = 2   //!< Local transmit queue overflowed.
};

/**
 * @ingroup olsr
 * @brief Interface for a trust-based defense plugged into OLSR.
 *
 * See the file header for the contract. Implementations in this fork:
 * OlsrTrustDefense (Adnane et al. 2013) on trust-defense, and OlsrDefenseFpnt
 * (Tan et al. 2015) on fpnt-defense.
 */
class OlsrDefenseStrategy : public Object
{
public:
  /**
   * @brief Get the type ID.
   * @returns the object TypeId
   */
  static TypeId GetTypeId(void);
  virtual ~OlsrDefenseStrategy() {}

  /**
   * @brief Bind this strategy to its routing protocol instance.
   * @param proto the owning RoutingProtocol (not owned by the strategy)
   * @param nodeAddress this node's OLSR main address
   */
  virtual void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) = 0;
  virtual void DoDispose() = 0;

  /**
   * @brief The verdict the routing protocol acts on.
   * @param addr the node being asked about
   * @returns true if @p addr is currently mistrusted by this node
   */
  virtual bool IsMalicious(Ipv4Address addr) = 0;

  /**
   * @brief Every node this one currently mistrusts.
   * @returns the set of mistrusted addresses (empty if none)
   */
  virtual std::set<Ipv4Address> GetBlacklist() const = 0;

  /// Nodes under PARTIAL mistrust, if the strategy distinguishes them (Adnane et al.
  /// Table 3 reports exact and partial detection separately). Defaults to empty for
  /// strategies with a single verdict class.
  virtual std::set<Ipv4Address> GetPartialMistrusted() const { return {}; }

  // --- Control Plane Hooks ---
  // Called by RoutingProtocol as OLSR control traffic is received or built.
  virtual void OnRecvHello(Ipv4Address senderAddress,
                           Ptr<const Packet> packet, 
                           const MessageHeader& msg, 
                           const MessageHeader::Hello& hello) = 0;

  virtual void OnRecvTc (Ipv4Address senderIfaceAddr, 
                         Ptr<const Packet> packet, 
                         const MessageHeader& msg, 
                         const MessageHeader::Tc& tc) = 0;

  virtual void OnTcGenerated(const MessageHeader::Tc& tc) = 0;

  /// This node just built its own HELLO. Needed by Section 6 so a node can publish
  /// the neighbourhood declaration its peers will have to prove against.
  virtual void OnHelloGenerated(const MessageHeader::Hello& hello) { (void)hello; }

  /// A Section 6.2 proof of neighbourhood arrived.
  virtual void OnRecvProof(const MessageHeader::Proof& proof) { (void)proof; }

  // --- Data Plane Hooks ---
  // The evidence a black-hole detector runs on: what this node forwarded,
  // to whom, and what never arrived.
  virtual void OnDataPacketReceived(Ptr<const Packet> packet,
                                     Ipv4Address source,
                                     Ipv4Address destination,
                                     Ipv4Address nextHop) = 0;

  virtual void OnDataPacketForwarded(Ptr<const Packet> packet, 
                                      Ipv4Address nextHop,
                                      Ipv4Address finalDest) = 0;

  virtual void OnDataPacketDropped(Ptr<const Packet> packet, 
                                    Ipv4Address source,
                                    Ipv4Address destination,
                                    DropReason reason) = 0;

  // --- Sniffer / Promiscuous Hooks ---
  virtual void OnNeighborForwardedPacket(Mac48Address transmitter,
                                         Mac48Address receiver, Ptr<const Packet> packet) = 0;

  // --- Cross Layer & Physical Metrics ---
  virtual void OnQueueStatusReport(uint32_t size, uint32_t capacity) = 0;
  virtual void OnEnergyStateUpdate(double remainingEnergyJoules, double energyFraction) = 0;
  virtual void OnMacTxFailure(Ipv4Address neighbor, uint32_t count) = 0;

  // --- NEW: Cooperative Detection Extensions (Cross-Layer) ---
  // Reports local physical layer drops (noise/interference) to assess self-reliability
  virtual void OnSelfReliabilityReport(uint32_t localDropsCount) = 0;
  
  // Reports RTS frames seen by the sniffer (Algorithm 1)
  virtual void OnRtsReceived(Mac48Address sender, Mac48Address receiver) = 0;
  
  // Reports CTS frames seen by the sniffer (Algorithm 1)
  virtual void OnCtsReceived(Mac48Address receiver) = 0;

  /// Periodic reasoning tick. Driven by RoutingProtocol's defense timer, not
  /// by the strategy itself, so that every defense is stepped the same way.
  virtual void PeriodicCheck() = 0;

  /**
   * @brief Whether the topology currently warrants injecting a fictitious node
   *        into HELLO/TC (the GCOP/GCOHP countermeasure).
   * @returns true to inject
   */
  virtual bool RequiresFictitiousNode() = 0;
};

/**
 * @ingroup olsr
 * @brief The default strategy: no defense at all.
 *
 * Every hook is a no-op and IsMalicious() always answers false, so OLSR
 * behaves exactly as RFC 3626 specifies. The evaluation harness installs this
 * for the defense-off measurement windows.
 */
class OlsrDefenseNull : public OlsrDefenseStrategy
{
public:
  /**
   * @brief Get the type ID.
   * @returns the object TypeId
   */
  static TypeId GetTypeId(void);

  virtual void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) override {}
  virtual void DoDispose() override {}
  virtual bool IsMalicious(Ipv4Address addr) override { return false; }
  virtual std::set<Ipv4Address> GetBlacklist() const override { return {}; }

  virtual void OnRecvHello(Ipv4Address, Ptr<const Packet>, const MessageHeader&, 
                           const MessageHeader::Hello&) override {}
  virtual void OnRecvTc(Ipv4Address, Ptr<const Packet>, 
                        const MessageHeader&, const MessageHeader::Tc&) override {}
  virtual void OnTcGenerated(const MessageHeader::Tc&) override {}

  virtual void OnDataPacketReceived(Ptr<const Packet>, Ipv4Address, Ipv4Address, 
                                     Ipv4Address) override {}
  virtual void OnDataPacketForwarded(Ptr<const Packet>, Ipv4Address, Ipv4Address) override {}
  
  virtual void OnDataPacketDropped(Ptr<const Packet>, Ipv4Address, Ipv4Address, DropReason) override {}

  virtual void OnNeighborForwardedPacket(Mac48Address, Mac48Address, Ptr<const Packet>) override {}
  virtual void OnQueueStatusReport(uint32_t, uint32_t) override {}
  virtual void OnEnergyStateUpdate(double, double) override {}
  virtual void OnMacTxFailure(Ipv4Address, uint32_t) override {}
  
  // New empty implementations for the null strategy
  virtual void OnSelfReliabilityReport(uint32_t) override {}
  virtual void OnRtsReceived(Mac48Address, Mac48Address) override {}
  virtual void OnCtsReceived(Mac48Address) override {}

  virtual void PeriodicCheck() override {}

  virtual bool RequiresFictitiousNode() override { return false; }
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_DEFENSE_STRATEGY_H */
