/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "olsr-defense-fpnt.h"
#include "ns3/log.h"
#include "ns3/double.h"
#include "ns3/pointer.h"
#include "ns3/olsr-routing-protocol.h"
#include "ns3/node.h"
#include "ns3/ipv4.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv4-interface.h"
#include "ns3/arp-cache.h"
#include <algorithm> // For std::max, std::min

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("OlsrDefenseFpnt");

namespace olsr {

NS_OBJECT_ENSURE_REGISTERED (OlsrDefenseFpnt);

// ======================================================================
// Static Constants for Fuzzy Petri Net (Algorithm 1)
// ======================================================================
static const int NUM_TRANSITIONS = 11;
static const int NUM_PLACES = 15;

// Threshold Vector TH
// R1(0.4), R2(0.4), R3(0.5), R4(0.5), R5(0.5), R6(0.7), R7(0.8), R8(0.4), R9(0.4), R10(0.4), R11(0.6)
static const std::vector<double> TH = {0.4, 0.4, 0.5, 0.5, 0.5, 0.7, 0.8, 0.4, 0.4, 0.4, 0.6};

TypeId
OlsrDefenseFpnt::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::olsr::OlsrDefenseFpnt")
    .SetParent<OlsrDefenseStrategy> ()
    .SetGroupName ("Olsr")
    .AddConstructor<OlsrDefenseFpnt> ()
    .AddAttribute ("TrustUpdateInterval",
                   "The period 't' used for normalizing counters (e.g. Load/t).",
                   TimeValue (Seconds (1.0)),
                   MakeTimeAccessor (&OlsrDefenseFpnt::m_checkInterval),
                   MakeTimeChecker ())
    .AddAttribute ("MaliciousThreshold",
                   "If Trust Value T is below this threshold, the node is considered malicious.",
                   DoubleValue (0.2),
                   MakeDoubleAccessor (&OlsrDefenseFpnt::m_maliciousThreshold),
                   MakeDoubleChecker<double> (0.0, 1.0))
    .AddAttribute ("UncertaintyBeta",
                   "The factor 'beta' weighting uncertainty in the final trust calculation.",
                   DoubleValue (0.5),
                   MakeDoubleAccessor (&OlsrDefenseFpnt::m_uncertaintyBeta),
                   MakeDoubleChecker<double> (0.0, 1.0))
  ;
  return tid;
}

OlsrDefenseFpnt::OlsrDefenseFpnt ()
  : m_protocol (nullptr),
    m_checkInterval (Seconds(1.0)),
    m_maxLoad (10000.0), // Default 10kbps ref
    m_maxDelay (1.0),    // Default 1s ref
    m_cheatThreshold (0),
    m_maliciousThreshold (0.4),
    m_uncertaintyBeta (0.5)
{
  NS_LOG_FUNCTION (this);
}

OlsrDefenseFpnt::~OlsrDefenseFpnt ()
{
  NS_LOG_FUNCTION (this);
}

void
OlsrDefenseFpnt::Setup (RoutingProtocol* proto, Ipv4Address nodeAddress)
{
  NS_LOG_FUNCTION (this << nodeAddress);
  m_protocol = proto;
  NS_LOG_INFO ("FPNT-OLSR Strategy initialized for node " << nodeAddress);
}

void
OlsrDefenseFpnt::DoDispose ()
{
  NS_LOG_FUNCTION (this);
  m_metrics.clear ();
  m_trustTable.clear ();
  m_directEvaluationVectors.clear ();
  m_lastSValues.clear ();
  OlsrDefenseStrategy::DoDispose ();
}

bool
OlsrDefenseFpnt::IsMalicious (Ipv4Address addr)
{
  // Section 4: Avoid malicious nodes
  auto it = m_trustTable.find (addr);
  if (it == m_trustTable.end ())
    {
      return false; // Unknown nodes are neutral
    }

  double trustValue = it->second;
  bool isMalicious = (trustValue < m_maliciousThreshold);

  if (isMalicious)
    {
      NS_LOG_DEBUG ("Node " << addr << " flagged as MALICIOUS (Trust: " << trustValue << " < " << m_maliciousThreshold << ")");
    }

  return isMalicious;
}

std::set<Ipv4Address>
OlsrDefenseFpnt::GetBlacklist () const
{
  std::set<Ipv4Address> blacklist;
  for (auto const& [addr, trust] : m_trustTable)
    {
      if (trust < m_maliciousThreshold)
        {
          blacklist.insert (addr);
        }
    }
  return blacklist;
}

std::vector<EvaluationVector>
OlsrDefenseFpnt::GetEvaluationVectors (const std::vector<Ipv4Address> &neighbors)
{
  NS_LOG_FUNCTION (this);
  // Section 5.2: Piggyback recommendations
  
  std::vector<EvaluationVector> vectors;
  vectors.reserve (neighbors.size ());

  for (const auto& addr : neighbors)
    {
      EvaluationVector ev; // Default 0,0,0
      
      auto it = m_directEvaluationVectors.find (addr);
      if (it != m_directEvaluationVectors.end ())
        {
          ev = it->second;
        }
      else
        {
           // Unknown neighbor: Uncertain = 1.0 (quantized to 255)
           ev.uncertain = 255; 
        }
      
      vectors.push_back (ev);
    }
    
  return vectors;
}

// ======================================================================
// Trust Query & Calculation (Section 3.3)
// ======================================================================

double
OlsrDefenseFpnt::GetNodeTrust (Ipv4Address node)
{
  // Equation (4): T = E_trust + beta * E_uncertain 
  auto it = m_trustTable.find (node);
  if (it != m_trustTable.end ())
    {
      return it->second;
    }

  // Edge Case: If the node is unknown, return neutral/beta trust
  return m_uncertaintyBeta;
}

// ======================================================================
// Incoming Recommendations (Section 5.2 & 3.3)
// ======================================================================

void
OlsrDefenseFpnt::OnRecvEvaluationVectors (Ipv4Address sender,
                                          const std::vector<Ipv4Address> &advertisedNeighbors,
                                          const std::vector<EvaluationVector> &vectors)
{
  NS_LOG_FUNCTION (this << sender);

  if (advertisedNeighbors.size () != vectors.size ())
    {
      NS_LOG_WARN ("Received malformed TC from " << sender << ": Neighbor/EV size mismatch");
      return;
    }
  
  for (size_t i = 0; i < advertisedNeighbors.size (); ++i)
    {
      Ipv4Address target = advertisedNeighbors[i];
      EvaluationVector ev = vectors[i];

      double t_trust = ev.trust / 255.0;
      double t_distrust = ev.distrust / 255.0;
      
      NS_LOG_DEBUG ("Recv Recommendation from " << sender << " about " << target 
                    << ": T=" << t_trust << " D=" << t_distrust);
    }
}

void
OlsrDefenseFpnt::OnRecvHello (Ipv4Address sender, Ptr<const Packet> packet, 
                              const MessageHeader& msg, const MessageHeader::Hello& hello)
{
  NS_LOG_FUNCTION (this << sender);
}

void
OlsrDefenseFpnt::OnRecvTc (Ipv4Address sender, Ptr<const Packet> packet, 
                           const MessageHeader& msg, const MessageHeader::Tc& tc)
{
  NS_LOG_FUNCTION (this << sender);
}

void
OlsrDefenseFpnt::OnTcGenerated (const MessageHeader::Tc& tc)
{
  NS_LOG_FUNCTION (this);
}

// ======================================================================
// Metric Collection Hooks (Section 5.1)
// ======================================================================

void
OlsrDefenseFpnt::OnDataPacketReceived (Ptr<const Packet> packet, Ipv4Address source,
                                       Ipv4Address destination, Ipv4Address nextHop)
{
  if (nextHop.IsBroadcast () || nextHop.IsAny ()) return;

  auto& metrics = m_metrics[nextHop];
  metrics.countLoad += packet->GetSize ();
}

void
OlsrDefenseFpnt::OnDataPacketForwarded (const Ipv4Header &header, Ptr<const Packet> packet, 
                                        Ipv4Address nextHop, Ipv4Address finalDest)
{
   if (nextHop == finalDest) 
     {
       return; 
     }
   if (nextHop.IsBroadcast ()) 
     {
       return; 
     }

   auto& metrics = m_metrics[nextHop];
   metrics.countRcv++; 
}

void
OlsrDefenseFpnt::OnDataPacketDropped (Ptr<const Packet> packet, Ipv4Address source,
                                      Ipv4Address destination, DropReason reason)
{
  NS_LOG_FUNCTION (this << reason);
}

void
OlsrDefenseFpnt::OnNeighborForwardedPacket (Mac48Address transmitter, Mac48Address receiver, 
                                            Ptr<const Packet> packet)
{
  Ipv4Address neighborAddr = MacToIpv4(transmitter);
  
  if (neighborAddr == Ipv4Address::GetAny())
    {
      return;
    }

  auto& metrics = m_metrics[neighborAddr];
  metrics.countFwd++;

  NS_LOG_LOGIC ("Neighbor " << neighborAddr << " forwarded packet " << packet->GetUid ());
}

void
OlsrDefenseFpnt::OnQueueStatusReport (uint32_t size, uint32_t capacity)
{
}

void
OlsrDefenseFpnt::OnEnergyStateUpdate (double remainingEnergyJoules, double energyFraction)
{
}

void
OlsrDefenseFpnt::OnMacTxFailure (Ipv4Address neighbor, uint32_t count)
{
  NS_LOG_FUNCTION (this << neighbor << count);
  
  if (neighbor.IsAny ()) return;

  auto& metrics = m_metrics[neighbor];
  metrics.countRCheat++;
  
  NS_LOG_WARN ("Detected MAC TX Failure to " << neighbor << ". Incrementing Deviation Counter.");
}

// ======================================================================
// The Core Logic: Orchestration (PeriodicCheck)
// ======================================================================

void
OlsrDefenseFpnt::PeriodicCheck ()
{
  NS_LOG_FUNCTION (this);

  bool needsReactiveUpdate = false; 

  for (auto& entry : m_metrics)
    {
      Ipv4Address neighborAddr = entry.first;
      NodeBehaviorMetrics& metrics = entry.second;

      // Calculate S Vector using new persistence logic
      std::vector<double> s0 = MetricsToS0 (neighborAddr, metrics);
      
      // Store current S vector for future reference (Persistence)
      // This allows us to recall behavior if traffic stops in the next interval
      m_lastSValues[neighborAddr] = s0;

      // Run FPN
      EvaluationVector ev = RunFuzzyPetriNet (s0);
      m_directEvaluationVectors[neighborAddr] = ev;

      double t_trust = ev.trust / 255.0;
      double t_uncertain = ev.uncertain / 255.0;
      double T = t_trust + (m_uncertaintyBeta * t_uncertain);

      // Reactive Security Check
      double oldTrust = 1.0; 
      auto it = m_trustTable.find (neighborAddr);
      if (it != m_trustTable.end ())
        {
          oldTrust = it->second;
        }

      if (oldTrust >= m_maliciousThreshold && T < m_maliciousThreshold)
        {
          NS_LOG_WARN ("Node " << neighborAddr << " detected as MALICIOUS (T=" << T << ").");
          needsReactiveUpdate = true;
        }

      m_trustTable[neighborAddr] = T;
    }

  m_metrics.clear ();
  
  if (needsReactiveUpdate && m_protocol)
    {
      m_protocol->RunTrustDijkstra ();
    }
}

// ======================================================================
// Helper Implementation: Data Normalization
// ======================================================================

std::vector<double>
OlsrDefenseFpnt::MetricsToS0 (Ipv4Address addr, const NodeBehaviorMetrics& metrics)
{
  // Initialize S vector (inputs for propositions p1..p8)
  std::vector<double> S (NUM_PLACES, 0.0);
  
  // Retrieve history to support state persistence for intermittent traffic
  bool hasHistory = (m_lastSValues.find(addr) != m_lastSValues.end());
  std::vector<double> lastS;
  if (hasHistory) lastS = m_lastSValues[addr];

  double intervalSeconds = m_checkInterval.GetSeconds ();
  if (intervalSeconds <= 0) intervalSeconds = 1.0; 

  // --- p1 (High Load) & p2 (Low Load) ---
  // Load metrics are instantaneous and do not require optimistic initialization
  double effectiveMaxLoad = (m_maxLoad > 0) ? m_maxLoad : 10000.0;
  double loadRate = metrics.countLoad / intervalSeconds;
  double s1 = std::min (loadRate / effectiveMaxLoad, 1.0);
  S[0] = s1;          
  S[1] = 1.0 - s1;    

  // --- p3 (High Forwarding) & p4 (Low Forwarding) ---
  if (metrics.countRcv > 0)
    {
      // Traffic exists: Calculate Packet Delivery Ratio (PDR) normally
      double rate = (double)metrics.countFwd / metrics.countRcv;
      S[2] = std::min (rate, 1.0); // p3 (High Fwd)
      S[3] = 1.0 - S[2];           // p4 (Low Fwd)
    }
  else
    {
      // No traffic to judge performance
      if (hasHistory)
        {
          // Persistence: Reuse last known PDR (prevents "forgetting" attacks)
          S[2] = lastS[2];
          S[3] = lastS[3];
        }
      else
        {
          // OPTIMISTIC INITIALIZATION: Assume 100% Reliability
          // "Innocent until proven guilty" approach
          S[2] = 1.0; // Assume High Forwarding (Good)
          S[3] = 0.0; // Assume Low Forwarding (Bad) is 0
        }
    }

  // --- p5 (High Delay) & p6 (Low Delay) ---
  if (metrics.countFwd > 0)
    {
       // Traffic exists: Calculate average delay normally
       double effectiveMaxDelay = (m_maxDelay > 0) ? m_maxDelay : 1.0; 
       double avgDelay = metrics.totalDelay / metrics.countFwd;
       double s5 = std::min (avgDelay / effectiveMaxDelay, 1.0);
       S[4] = s5;        
       S[5] = 1.0 - s5;  
    }
  else
    {
       // No forwarding implies we cannot measure delay
       if (hasHistory)
        {
           // Persistence: Reuse last known Delay
           S[4] = lastS[4];
           S[5] = lastS[5];
        }
       else
        {
           // OPTIMISTIC INITIALIZATION: Assume Perfect (Zero) Delay
           S[4] = 0.0; // Assume High Delay (Bad) is 0
           S[5] = 1.0; // Assume Low Delay (Good) is 1.0
        }
    }

  // --- p7 (Routing Deviation) & p8 (Routing Normal) ---
  // Default to Normal unless cheating is explicitly detected
  if (metrics.countRCheat > m_cheatThreshold)
    {
      S[6] = 1.0; // p7 (Deviation Detected)
      S[7] = 0.0; // p8 (Normal)
    }
  else
    {
      S[6] = 0.0;
      S[7] = 1.0; // Assume Normal Behavior
    }

  return S;
}

// ======================================================================
// Helper Implementation: Fuzzy Petri Net Core (Algorithm 1)
// ======================================================================

EvaluationVector
OlsrDefenseFpnt::RunFuzzyPetriNet (const std::vector<double>& s0)
{
  // 1. Define Matrices (Static for performance)
  static std::vector<std::vector<double>> W_T (NUM_TRANSITIONS, std::vector<double>(NUM_PLACES, 0.0));
  static bool initialized = false;
  if (!initialized)
  {
      W_T[0][0] = 1.0;                            // R1
      W_T[1][3] = 1.0;                            // R2
      W_T[2][4] = 1.0;                            // R3
      W_T[3][1] = 0.4; W_T[3][4] = 0.6;           // R4
      W_T[4][6] = 1.0;                            // R5
      W_T[5][2] = 0.6; W_T[5][5] = 0.3; W_T[5][1] = 0.1; // R6
      W_T[6][7] = 1.0;                            // R7
      W_T[7][8] = 1.0;                            // R8
      W_T[8][9] = 1.0;                            // R9
      W_T[9][10] = 1.0;                           // R10
      W_T[10][11] = 0.5; W_T[10][12] = 0.5;       // R11
      initialized = true;
  }

  // Output Incidence Matrix U
  static std::vector<std::vector<double>> U (NUM_PLACES, std::vector<double>(NUM_TRANSITIONS, 0.0));
  if (U[8][0] == 0.0) // Quick init check
  {
      U[8][0] = 0.9; U[8][1] = 0.9; U[8][2] = 0.6; // -> p9
      U[9][3] = 0.8;                               // -> p10
      U[10][4] = 0.9;                              // -> p11
      U[11][5] = 0.9;                              // -> p12
      U[12][6] = 1.0;                              // -> p13
      U[13][7] = 0.9; U[13][8] = 0.7; U[13][9] = 0.9; // -> p14
      U[14][10] = 0.9;                             // -> p15
  }

  // 2. Reasoning Loop (Steps 1-5 of Algo 1)
  std::vector<double> S = s0;
  std::vector<double> S_next = S;
  int k = 0;
  bool converged = false;

  while (k < 10 && !converged)
    {
      // Step 1: I = W^T * S
      std::vector<double> I (NUM_TRANSITIONS, 0.0);
      for (int r = 0; r < NUM_TRANSITIONS; ++r)
        {
           for (int p = 0; p < NUM_PLACES; ++p)
             if (W_T[r][p] > 0) I[r] += W_T[r][p] * S[p];
        }

      // Step 2: G = I (x) TH
      std::vector<double> G = MatrixOp_Threshold (I, TH);

      // Step 3: S_new = U (x) G
      std::vector<double> S_calc = MatrixOp_WeightedMax (U, G);

      // Step 4: S(k+1) = S(k) (.) S_new
      S_next = MatrixOp_Max (S, S_calc);

      // Step 5: Check Convergence
      if (S_next == S) converged = true;
      else { S = S_next; k++; }
    }

  // 3. Extract Result (Step 6)
  double s14 = S[13]; // Distrust
  double s15 = S[14]; // Trust

  EvaluationVector ev;
  // Conflict resolution logic
  if (s14 + s15 >= 1.0)
    {
       ev.trust = (uint8_t)(s15 * 255.0);
       ev.distrust = (uint8_t)((1.0 - s15) * 255.0);
       ev.uncertain = 0;
    }
  else
    {
       ev.trust = (uint8_t)(s15 * 255.0);
       ev.distrust = (uint8_t)(s14 * 255.0);
       ev.uncertain = (uint8_t)((1.0 - s14 - s15) * 255.0);
    }
  
  return ev;
}

// ======================================================================
// Matrix Operator Implementations
// ======================================================================

std::vector<double> 
OlsrDefenseFpnt::MatrixOp_Threshold (const std::vector<double>& input, 
                                     const std::vector<double>& threshold)
{
  // Definition 5: c_ij = a_ij if a_ij > b_ij, else 0
  std::vector<double> result (input.size (), 0.0);
  for (size_t i = 0; i < input.size (); ++i)
    {
      if (input[i] >= threshold[i]) result[i] = input[i];
      else result[i] = 0.0;
    }
  return result;
}

std::vector<double> 
OlsrDefenseFpnt::MatrixOp_WeightedMax (const std::vector<std::vector<double>>& U, 
                                       const std::vector<double>& G)
{
  // Definition 7: C = A (x) B => max { a_ik * b_kj }
  std::vector<double> result (NUM_PLACES, 0.0);
  for (int p = 0; p < NUM_PLACES; ++p)
    {
      double max_val = 0.0;
      for (int r = 0; r < NUM_TRANSITIONS; ++r)
        {
           double val = U[p][r] * G[r];
           if (val > max_val) max_val = val;
        }
      result[p] = max_val;
    }
  return result;
}

std::vector<double> 
OlsrDefenseFpnt::MatrixOp_Max (const std::vector<double>& a, 
                               const std::vector<double>& b)
{
  // Definition 6: C = A (.) B => max { a_ij, b_ij }
  std::vector<double> result (a.size ());
  for (size_t i = 0; i < a.size (); ++i)
    {
      result[i] = std::max (a[i], b[i]);
    }
  return result;
}

Ipv4Address
OlsrDefenseFpnt::MacToIpv4(Mac48Address mac)
{
  if (!m_protocol) return Ipv4Address::GetAny ();
  Ptr<Node> node = m_protocol->GetObject<Node> ();
  if (!node) return Ipv4Address::GetAny ();
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
  if (!ipv4) return Ipv4Address::GetAny ();

  for (uint32_t i = 0; i < ipv4->GetNInterfaces (); i++)
    {
      Ptr<Ipv4L3Protocol> l3 = node->GetObject<Ipv4L3Protocol> ();
      Ptr<Ipv4Interface> interface = l3->GetInterface (i);
      Ptr<ArpCache> arp = interface->GetArpCache ();

      if (arp)
        {
          // We check our known monitored neighbors first
          for (auto const& [ip, metric] : m_metrics)
            {
               ArpCache::Entry* entry = arp->Lookup (ip);
               if (entry && entry->IsAlive () && entry->GetMacAddress () == mac)
                 {
                   return ip;
                 }
            }
        }
    }
  return Ipv4Address::GetAny (); 
}

} // namespace olsr
} // namespace ns3