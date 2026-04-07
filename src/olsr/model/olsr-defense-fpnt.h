/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#ifndef OLSR_DEFENSE_FPNT_H
#define OLSR_DEFENSE_FPNT_H

#include "olsr-defense-strategy.h"
#include "ns3/nstime.h"
#include "ns3/mac48-address.h"
#include <map>
#include <vector>

namespace ns3 {
namespace olsr {

/**
 * \brief FPNT-OLSR Trust Reasoning Mechanism
 *
 * Implements the "Trust based routing mechanism" described by Tan et al. (2015).
 * * Architecture Note:
 * This class is passive regarding execution scheduling. The RoutingProtocol 
 * is responsible for calling PeriodicCheck() at the defined 'TrustUpdateInterval'.
 */
class OlsrDefenseFpnt : public OlsrDefenseStrategy
{
public:
  static TypeId GetTypeId (void);

  OlsrDefenseFpnt ();
  virtual ~OlsrDefenseFpnt ();

  // ======================================================================
  // Setup & Lifecycle
  // ======================================================================
  
  /**
   * \brief Initialize the defense strategy.
   * Note: Does NOT start a timer. The RoutingProtocol manages the schedule.
   */
  virtual void Setup(RoutingProtocol* proto, Ipv4Address nodeAddress) override;
  
  virtual void DoDispose() override;

  // ======================================================================
  // Trust Query Methods (Routing Integration)
  // ======================================================================

  virtual bool IsMalicious(Ipv4Address addr) override;
  virtual std::set<Ipv4Address> GetBlacklist() const override;
  virtual std::vector<EvaluationVector> GetEvaluationVectors (
      const std::vector<Ipv4Address> &neighbors) override;
  virtual double GetNodeTrust (Ipv4Address node) override;
  virtual bool IsTrustRoutingEnabled () const override { return true; }

  // ======================================================================
  // Incoming Message Handlers (Trust Propagation)
  // ======================================================================

  virtual void OnRecvEvaluationVectors (
      Ipv4Address sender,
      const std::vector<Ipv4Address> &advertisedNeighbors,
      const std::vector<EvaluationVector> &vectors) override;

  virtual void OnRecvHello(Ipv4Address senderAddress,
                           Ptr<const Packet> packet, 
                           const MessageHeader& msg, 
                           const MessageHeader::Hello& hello) override;

  virtual void OnRecvTc (Ipv4Address senderIfaceAddr, 
                         Ptr<const Packet> packet, 
                         const MessageHeader& msg, 
                         const MessageHeader::Tc& tc) override;

  virtual void OnTcGenerated(const MessageHeader::Tc& tc) override;

  // ======================================================================
  // Monitoring & Metric Collection (Section 5.1)
  // ======================================================================

  virtual void OnDataPacketReceived(Ptr<const Packet> packet,
                                    Ipv4Address source,
                                    Ipv4Address destination,
                                    Ipv4Address nextHop) override;

  virtual void OnDataPacketForwarded(const Ipv4Header &header, 
                                     Ptr<const Packet> packet, 
                                     Ipv4Address nextHop, 
                                     Ipv4Address finalDest) override;

  virtual void OnDataPacketDropped(Ptr<const Packet> packet, 
                                   Ipv4Address source,
                                   Ipv4Address destination,
                                   DropReason reason) override;

  virtual void OnNeighborForwardedPacket(Mac48Address transmitter,
                                         Mac48Address receiver, Ptr<const Packet> packet) override;

  virtual void OnQueueStatusReport(uint32_t size, uint32_t capacity) override;
  virtual void OnEnergyStateUpdate(double remainingEnergyJoules, double energyFraction) override;
  virtual void OnMacTxFailure(Ipv4Address neighbor, uint32_t count) override;

  /**
   * \brief Executes the Trust Reasoning Cycle.
   * Called externally by RoutingProtocol::HandleDefenseTimer.
   * * Logic:
   * 1. Normalizes collected counters using m_checkInterval (variable 't').
   * 2. Runs the Fuzzy Petri Net (Algorithm 1).
   * 3. Updates the Direct Trust for neighbors.
   * 4. Resets counters for the next period.
   */
  virtual void PeriodicCheck() override;

private:
  RoutingProtocol* m_protocol;
  // ----------------------------------------------------------------------
  // Internal Structures & Logic
  // ----------------------------------------------------------------------

  struct NodeBehaviorMetrics {
      uint32_t countLoad;     // Bytes received
      uint32_t countRcv;      // Packets expected to be forwarded
      uint32_t countFwd;      // Packets actually forwarded
      uint32_t countRCheat;   // Routing abnormal behaviors
      double totalDelay;      // Accumulator for forwarding delay

      NodeBehaviorMetrics() : 
          countLoad(0), countRcv(0), countFwd(0), countRCheat(0), totalDelay(0.0) {}
  };

  std::map<Ipv4Address, NodeBehaviorMetrics> m_metrics;
  std::map<Ipv4Address, double> m_trustTable; 
  std::map<Ipv4Address, EvaluationVector> m_directEvaluationVectors;
  std::map<Ipv4Address, std::vector<double>> m_lastSValues;

  // We keep this variable to perform the math: Rate = Count / t
  // It must match the external timer frequency set in RoutingProtocol.
  Time m_checkInterval; 

  // FPN Parameters
  double m_maxLoad;           
  double m_maxDelay;          
  uint32_t m_cheatThreshold;  
  double m_maliciousThreshold;
  double m_uncertaintyBeta;

  // Helpers (signatures only)
  std::vector<double> MetricsToS0(Ipv4Address addr, const NodeBehaviorMetrics& metrics);
  EvaluationVector RunFuzzyPetriNet(const std::vector<double>& s0);
  std::vector<double> MatrixOp_Threshold(const std::vector<double>& input, 
                                       const std::vector<double>& threshold);
  std::vector<double> MatrixOp_Max(const std::vector<double>& a, 
                                 const std::vector<double>& b);
  std::vector<double> MatrixOp_WeightedMax(const std::vector<std::vector<double>>& U, 
                                         const std::vector<double>& G);

  Ipv4Address MacToIpv4(Mac48Address mac);
};

} // namespace olsr
} // namespace ns3

#endif