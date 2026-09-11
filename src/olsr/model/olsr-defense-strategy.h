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
 * code for it at all. Only the hooks every defense must answer are pure. On
 * this branch that applies to the trust-routing group (GetNodeTrust,
 * IsTrustRoutingEnabled, GetEvaluationVectors, OnRecvEvaluationVectors),
 * which FPNT-OLSR uses and a simpler defense can ignore entirely.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef OLSR_DEFENSE_STRATEGY_H
#define OLSR_DEFENSE_STRATEGY_H

#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/ipv4-address.h"
#include "ns3/mac48-address.h"
#include "ns3/ipv4-header.h"
#include "olsr-header.h"
#include <set>
#include <vector>

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
 * OlsrDefenseFpnt (Tan et al. 2015) on this branch, and OlsrTrustDefense
 * (Adnane et al. 2013) on trust-defense.
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

  virtual bool IsMalicious(Ipv4Address addr) = 0;
  virtual std::set<Ipv4Address> GetBlacklist() const = 0;

  // --- Trust-routing hooks (FPNT-OLSR, Tan et al. 2015) ---------------------
  // Non-pure, so a defense that does not participate in trust routing (GCOP,
  // the null strategy) needs no changes at all.

  /// @brief Evaluation vectors to piggyback onto an outgoing TC, one per
  ///        advertised neighbor. An empty return leaves the TC in plain
  ///        RFC 3626 form.
  virtual std::vector<EvaluationVector> GetEvaluationVectors(
      const std::vector<Ipv4Address>& neighbors)
  {
    return {};
  }

  /// @brief Evaluation vectors extracted from a received TC (recommendations).
  virtual void OnRecvEvaluationVectors(Ipv4Address sender,
                                       const std::vector<Ipv4Address>& advertisedNeighbors,
                                       const std::vector<EvaluationVector>& vectors)
  {
  }

  /// @brief Trust value T(V_j) in [0,1], the node weight of the max-path-trust
  ///        routing algorithm. 1.0 = fully trusted.
  virtual double GetNodeTrust(Ipv4Address node)
  {
    return 1.0;
  }

  /// @brief Whether RoutingTableComputation should be replaced by the trust
  ///        based routing algorithm. False keeps stock RFC 3626 routing.
  virtual bool IsTrustRoutingEnabled() const
  {
    return false;
  }

  // --- Control Plane Hooks ---
  virtual void OnRecvHello(Ipv4Address senderAddress,
                           Ptr<const Packet> packet, 
                           const MessageHeader& msg, 
                           const MessageHeader::Hello& hello) = 0;

  virtual void OnRecvTc (Ipv4Address senderIfaceAddr, 
                         Ptr<const Packet> packet, 
                         const MessageHeader& msg, 
                         const MessageHeader::Tc& tc) = 0;

  virtual void OnTcGenerated(const MessageHeader::Tc& tc) = 0;

  // --- Data Plane Hooks ---
  virtual void OnDataPacketReceived(Ptr<const Packet> packet,
                                     Ipv4Address source,
                                     Ipv4Address destination,
                                     Ipv4Address nextHop) = 0;

  virtual void OnDataPacketForwarded(Ptr<const Packet> packet,
                                      Ipv4Address nextHop,
                                      Ipv4Address finalDest) = 0;

  /**
   * @brief Header-carrying variant, called from RouteInput/RouteOutput.
   *
   * RouteInput hands the routing layer a packet whose IPv4 header has already
   * been stripped, so a defense that has to fingerprint the datagram --
   * FPNT-OLSR matches an arrival against the neighbor's later retransmission
   * to measure forwarding delay -- cannot recover the header on its own.
   * Defenses that do not need it inherit this default, which drops the header
   * and calls the three-argument form. A subclass overriding either form must
   * pull both into scope with
   * `using OlsrDefenseStrategy::OnDataPacketForwarded;`.
   */
  virtual void OnDataPacketForwarded(const Ipv4Header& header,
                                     Ptr<const Packet> packet,
                                     Ipv4Address nextHop,
                                     Ipv4Address finalDest)
  {
    OnDataPacketForwarded(packet, nextHop, finalDest);
  }

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

  virtual void PeriodicCheck() = 0;

  // Determines whether the current topology requires injecting a fictitious node
  // Returns true if a fictitious node should be added to HELLO/TC messages
  virtual bool RequiresFictitiousNode() = 0;
};

// --- Null Implementation (Default) ---
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
  using OlsrDefenseStrategy::OnDataPacketForwarded;
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
