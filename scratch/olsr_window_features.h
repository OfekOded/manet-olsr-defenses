#ifndef OLSR_WINDOW_FEATURES_H
#define OLSR_WINDOW_FEATURES_H

// ===========================================================================
//  Single-Listener OLSR feature collector  (schema SL-1, 2026-08-24)
// ===========================================================================
//
//  WHAT CHANGED vs. the previous (schema v4, 128-column) collector
//  ---------------------------------------------------------------
//  This version emits ONLY features that a SINGLE in-network listener -- one
//  attacker node, one radio in promiscuous mode -- can compute from the frames
//  it alone receives, with no exception for where it happens to sit.
//
//    128 columns  ->   69 columns  (71 with SL_INCLUDE_PACKET_SIZE_SHAPE)
//
//      -  44 removed : not computable from one vantage (data-plane: latency,
//                      PDR, per-flow stats, delivered/sent counts, hop counts,
//                      first-hop-MAC churn, and the whole V2/L flow block).
//      -  12 removed : documented artifacts.
//                        * 5 V2/L-parity columns -- normalised by nObs, which
//                          is itself a DCFM readout (AUC .947/.986); four were
//                          also bit-identical duplicates of Core columns.
//                        * 7 TC_SIZE_FEATURES -- TcMessageSize{Mean,Std,P95,
//                          Max}, TcBytesPerSecond, PerNodeTcBytes{Std,Gini}.
//                          FPNT's byte padding. Project decision 2026-08-24.
//      -   1 removed : NumDistinctTcSenderAddresses == the B-group column
//                      NumDistinctTcSenderNodesPerWindow (provably identical
//                      every window: both are |{TC originators}|).
//      -   2 removed : m_sourceDestPairs (dead) and the Core/V2 mode switch.
//      -   4 REDEFINED and kept: NumPhantomAddresses, NumEphemeralAddresses,
//                      PacketSizeDistribution{Skew,Kurtosis} -- their
//                      data-plane clause was dropped (see notes at each site).
//
//  TC DEDUPLICATION -- the single most important behavioural change
//  ----------------------------------------------------------------
//  A single listener hears every flooded TC once PER RELAYING NEIGHBOUR in
//  range. ObserveTc() now suppresses repeats by (originator, messageSequence).
//  Without this, TcPacketRate counts copies rather than messages, ANSN deltas
//  fill with spurious zeros, and TcInterArrival* collapse toward zero because
//  they measure millisecond gaps between copies of the SAME message.
//  Copies are still counted where they carry meaning: ObserveTcRelayOnAir()
//  must be fed EVERY copy -- that is what TcRelayerBreadth* measures.
//
//  HOW TO FEED IT (harness contract)
//  ---------------------------------
//   1. Attach the PHY sniffer to the ATTACKER NODE ONLY. This header can only
//      emit what it is fed; feeding it from a global/omniscient sniffer
//      produces numbers that are NOT single-listener, whatever the columns say.
//   2. ObserveTc()             -- every TC parsed from an overheard frame.
//                                 Repeats are dropped internally.
//   3. ObserveTcRelayOnAir()   -- EVERY on-air copy, repeats included.
//   4. ObserveMid()/ObserveHna()-- pass msgSeq when available to enable dedup.
//   5. ObserveMacFrame()       -- every frame EXCEPT HELLO (OBS-001) and the
//                                 RTS/CTS/ACK control frames (OBS-007).
//   6. SetPhyAvailable(true)   -- otherwise the two F-group columns emit 0.
//   7. The data-plane Observe* entry points are retained as NO-OPS so an
//      existing harness keeps compiling; they feed nothing.
//
//  HEADER/ROW LOCK-STEP
//  --------------------
//  Column names and row values are generated from ONE list (SL_FEATURE_LIST),
//  and EmitFeatureCsv() checks the value count against it at runtime. The two
//  cannot silently drift apart.
//
//  KNOWN CAVEATS (carried deliberately, documented, not silently fixed)
//  -------------------------------------------------------------------
//   * Isolation confound: TcOriginationCount*, TcRelayerBreadth* and
//     AdvertisedConnectivityComponents partly measure the attacker's OWN
//     cut-off. Isolation strength is defense efficacy, so these sit on top of
//     the detectability<->efficacy thesis rather than beside it.
//   * Fragile under frame loss: AdvertisedConnectivityComponents, Diameter,
//     Radius, Betweenness*, Closeness*, cycles and SpectralRadius are global
//     graph functionals -- one missed TC re-partitions the graph.
//   * DCFM timing artefact (open): realigned DCFM adds no channel traffic and
//     does not change TC timing, so ChannelBusyTimeFraction,
//     InterFrameSpacingMean and the six H columns are artefacts FOR DCFM.
//     Open Q4 (forced RtsCtsThreshold=0) additionally implicates
//     InterFrameSpacingMean. Kept; drop them if the which-defense task needs it.
//
// ===========================================================================

// Set to 1 to also emit PacketSizeDistributionSkew / PacketSizeDistributionKurtosis
// (-> 71 columns). OFF BY DEFAULT: both are the shape of the control-message
// SIZE distribution, which FPNT shifts by padding TC -- i.e. the same channel as
// the seven TC_SIZE_FEATURES that were deliberately removed. The project's own
// a-priori 21-set attributes both to FPNT. Enabling them re-admits that artifact.
#ifndef SL_INCLUDE_PACKET_SIZE_SHAPE
#define SL_INCLUDE_PACKET_SIZE_SHAPE 0
#endif

#include "ns3/core-module.h"
#include "ns3/ipv4-address.h"
#include "ns3/olsr-module.h"
#include "ns3/mac48-address.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iomanip>
#include <limits>
#include <map>
#include <numeric>
#include <queue>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace ns3 {
namespace olsreval {

// ---------------------------------------------------------------------------
// Small numeric helpers (unchanged).
// ---------------------------------------------------------------------------
inline double Mean (const std::vector<double>& v)
{
  if (v.empty ()) return 0.0;
  double s = 0.0; for (double x : v) s += x;
  return s / v.size ();
}

inline double Std (const std::vector<double>& v)
{
  if (v.size () < 2) return 0.0;
  const double m = Mean (v);
  double s = 0.0;
  for (double x : v) { const double d = x - m; s += d * d; }
  return std::sqrt (s / v.size ());
}

inline double Percentile (std::vector<double> v, double p /* 0..1 */)
{
  if (v.empty ()) return 0.0;
  std::sort (v.begin (), v.end ());
  const double idx = p * (v.size () - 1);
  const size_t lo = static_cast<size_t> (std::floor (idx));
  const size_t hi = static_cast<size_t> (std::ceil  (idx));
  if (lo == hi) return v[lo];
  const double frac = idx - lo;
  return v[lo] * (1.0 - frac) + v[hi] * frac;
}

inline double Skewness (const std::vector<double>& v)
{
  if (v.size () < 3) return 0.0;
  const double m = Mean (v);
  const double s = Std  (v);
  if (s == 0.0) return 0.0;
  double num = 0.0;
  for (double x : v) { const double d = (x - m) / s; num += d * d * d; }
  return num / v.size ();
}

inline double Kurtosis (const std::vector<double>& v)
{
  if (v.size () < 4) return 0.0;
  const double m = Mean (v);
  const double s = Std  (v);
  if (s == 0.0) return 0.0;
  double num = 0.0;
  for (double x : v) { const double d = (x - m) / s; num += d * d * d * d; }
  return (num / v.size ()) - 3.0;       // excess kurtosis
}

inline double ShannonEntropy (const std::vector<uint64_t>& counts)
{
  uint64_t total = 0; for (uint64_t c : counts) total += c;
  if (total == 0) return 0.0;
  double h = 0.0;
  for (uint64_t c : counts)
    {
      if (c == 0) continue;
      const double p = static_cast<double> (c) / total;
      h -= p * std::log2 (p);
    }
  return h;
}

inline double ByteEntropy (const std::vector<uint8_t>& bytes)
{
  if (bytes.empty ()) return 0.0;
  std::vector<uint64_t> hist (256, 0);
  for (uint8_t b : bytes) hist[b]++;
  return ShannonEntropy (hist);
}

// Hurst exponent via simple rescaled-range (R/S). Marked exploratory.
inline double HurstRS (const std::vector<double>& x)
{
  const size_t n = x.size ();
  if (n < 10) return 0.5;
  const double m = Mean (x);
  std::vector<double> Y (n);
  double cum = 0.0;
  for (size_t i = 0; i < n; ++i) { cum += x[i] - m; Y[i] = cum; }
  double mx = *std::max_element (Y.begin (), Y.end ());
  double mn = *std::min_element (Y.begin (), Y.end ());
  const double R = mx - mn;
  const double S = Std (x);
  if (S == 0.0 || R == 0.0) return 0.5;
  return std::log (R / S) / std::log (static_cast<double> (n));
}

// ---------------------------------------------------------------------------
// THE COLUMN LIST -- the single source of truth for names AND order.
// FeatureCsvHeader() stringifies it; EmitFeatureCsv() pushes values in exactly
// this order and verifies the count. Edit here and both stay in step.
// ---------------------------------------------------------------------------
#if SL_INCLUDE_PACKET_SIZE_SHAPE
#define SL_PACKET_SIZE_SHAPE_COLUMNS(X) \
  X(PacketSizeDistributionSkew)         \
  X(PacketSizeDistributionKurtosis)
#else
#define SL_PACKET_SIZE_SHAPE_COLUMNS(X)
#endif

#define SL_FEATURE_LIST(X)                                                    \
  /* --- A. control-traffic volume (6) --------------------------------- */   \
  X(TcPacketRate) X(MidPacketRate) X(HnaPacketRate)                           \
  X(MidBytesPerSecond) X(HnaBytesPerSecond)                                   \
  X(PerNodeTcRateStd)                                                         \
  /* --- B. TC structure (10) ------------------------------------------ */   \
  X(AdvertisedLinksPerTcMean) X(AdvertisedLinksPerTcStd)                      \
  X(AdvertisedLinksPerTcP95)  X(AdvertisedLinksPerTcMax)                      \
  X(TcAnsnIncrementMean) X(TcAnsnSkipCount)                                   \
  X(NumDistinctTcSenderNodesPerWindow)                                        \
  X(TcMessageContentEntropy) X(TcVtimeMean) X(TcVtimeStd)                     \
  /* --- C. address sets (4, two redefined) ---------------------------- */   \
  X(NumDistinctAddressesInTcAdvertisements)                                   \
  X(NumAsymmetricAdvertisements)                                              \
  X(NumPhantomAddresses) X(NumEphemeralAddresses)                             \
  /* --- D. MPR selection (4) ------------------------------------------ */   \
  X(MprSelectorCountPerTcMean) X(MprSelectorCountPerTcStd)                    \
  X(NumberOfMprChurnEvents) X(NumDistinctMprSetsObserved)                     \
  /* --- F. MAC / PHY, observer-local (2) ------------------------------ */   \
  X(ChannelBusyTimeFraction) X(InterFrameSpacingMean)                         \
  /* --- H. time & periodicity, reception-timed (6) -------------------- */   \
  X(TcInterArrivalMean) X(TcInterArrivalStd) X(TcInterArrivalP95)             \
  X(TcBurstinessHurst)                                                        \
  X(ControlMessageInterArrivalSkew) X(ControlMessageInterArrivalKurtosis)     \
  /* --- I. entropy (3, +2 optional) ----------------------------------- */   \
  X(TcSenderAddressEntropy) X(TcAdvertisedAddressEntropy)                     \
  X(TcPayloadByteDistributionEntropy)                                         \
  SL_PACKET_SIZE_SHAPE_COLUMNS(X)                                             \
  /* --- J. advertised-topology graph (22) ----------------------------- */   \
  X(AdvertisedAverageDegree) X(AdvertisedDegreeStd)                           \
  X(AdvertisedDegreeSkew) X(AdvertisedDegreeKurtosis)                         \
  X(NumberOfDegreeOneNodes)                                                   \
  X(AdvertisedClusteringCoefficient) X(NumberOfTrianglesInAdvertisedGraph)    \
  X(AdvertisedConnectivityComponents)                                         \
  X(AdvertisedDiameter) X(AdvertisedRadius) X(AdvertisedGraphDensity)         \
  X(BetweennessCentralityMean) X(BetweennessCentralityStd)                    \
  X(BetweennessCentralityMax)                                                 \
  X(ClosenessCentralityMean) X(ClosenessCentralityStd)                        \
  X(EdgePersistenceMean)                                                      \
  X(EdgeEmergenceWithinWindowRate) X(EdgeChurnWithinWindowRate)               \
  X(NumberOfHexagonalCycles) X(NumberOfShortCycles)                           \
  X(AdvertisedSpectralRadius)                                                 \
  /* --- K. defense-detection breadth (12) ----------------------------- */   \
  X(TcOriginationCountMin) X(TcOriginationCountMean)                          \
  X(TcOriginationCountStd) X(TcOriginationCountMax)                           \
  X(TcRelayerBreadthMin) X(TcRelayerBreadthMean)                              \
  X(TcRelayerBreadthStd) X(TcRelayerBreadthMax)                               \
  X(TcMaxHopReachMin) X(TcMaxHopReachMean)                                    \
  X(TcMaxHopReachStd) X(TcMaxHopReachMax)

// ---------------------------------------------------------------------------
// FeatureCollector
// ---------------------------------------------------------------------------
class FeatureCollector
{
public:
  // Retained only so existing callers keep compiling. There is now ONE feature
  // set, so every value behaves identically. Do not add new uses.
  enum class FeatureMode { Core, V2Only, CoreAndV2 };

  static constexpr size_t FeatureCount ()
  {
#define SL_COUNT_ONE(name) + 1
    return 0 SL_FEATURE_LIST (SL_COUNT_ONE);
#undef SL_COUNT_ONE
  }

  // ------------------------- Per-window reset ------------------------------
  void Reset (double tStart)
  {
    m_winStart = tStart;
    m_winEnd   = tStart;

    m_tcCount = m_midCount = m_hnaCount = 0;
    m_midBytes = m_hnaBytes = 0;

    // TC de-duplication state (see header banner).
    m_seenTcMsgs.clear ();
    m_seenMidMsgs.clear ();
    m_seenHnaMsgs.clear ();
    m_tcDuplicatesSuppressed = 0;

    m_tcBySender.clear ();
    m_advertisedLinksPerTc.clear ();
    m_tcVtimes.clear ();
    m_lastAnsnBySender.clear ();
    m_ansnIncrements.clear ();
    m_ansnSkipCount = 0;
    m_tcContentKeys.clear ();
    m_tcPayloadBytes.clear ();
    m_tcAdvertisedAddrCounts.clear ();
    m_tcSenderAddrCounts.clear ();
    m_addressesSeenInTcPayload.clear ();
    m_addressesEverSentTc.clear ();
    m_addressesFirstSeen.clear ();
    m_addressesLastSeen.clear ();
    m_observedDirectedEdges.clear ();
    m_mprSelectorsByTcSender.clear ();
    m_mprSelectorsHistoryBySender.clear ();
    m_mprChurnEvents = 0;
    m_distinctMprSetsBySender.clear ();

    // MAC-frame counters (PHY-trace driven; suppressed if PHY unavailable).
    m_busyIntervals.clear ();
    m_interFrameSpacing.clear ();
    m_lastMacTxEnd = -1.0;

    m_tcInterArrivalsPerSender.clear ();
    m_lastTcTimeBySender.clear ();
    m_controlMessageTimes.clear ();
    m_controlMessageSizes.clear ();
    m_advertisedEdgesAllTime.clear ();
    m_edgeFirstSeen.clear ();
    m_edgeLastSeen.clear ();
    m_edgesFirstHalf.clear ();
    m_edgesLastHalf.clear ();

    m_tcSeqByOriginator.clear ();
    m_tcRelayMacsByOriginator.clear ();
    m_tcMaxHopByOriginator.clear ();
  }

  // -------------------------- Phy availability ----------------------------
  // Set once at start of simulation. When false, the two F-group columns
  // emit 0 (per DEG-003).
  void SetPhyAvailable (bool ok) { m_phyAvailable = ok; }

  // ---- Diagnostics: use these to confirm the single-listener setup is live.
  // A healthy run has GetTcDuplicatesSuppressed() > 0 -- it is the count of
  // re-flooded copies the listener overheard. Zero means either the sniffer is
  // attached to a node with one relaying neighbour, or ObserveTc() is being
  // fed pre-deduplicated input (in which case TcRelayerBreadth* will be flat).
  uint64_t GetTcDuplicatesSuppressed () const { return m_tcDuplicatesSuppressed; }
  uint64_t GetUniqueTcCount ()          const { return m_tcCount; }

  // -------------------------- Observations ---------------------------------

  // Feed EVERY TC parsed from an overheard frame. Repeats of the same
  // (originator, messageSequenceNumber) are suppressed here.
  void ObserveTc (Ipv4Address senderIfaceAddr,
                  Ipv4Address originator,
                  const olsr::MessageHeader& msg,
                  const olsr::MessageHeader::Tc& tc,
                  uint32_t messageSerializedSize)
  {
    const double now = Simulator::Now ().GetSeconds ();
    (void) senderIfaceAddr;

    // ---- TC DEDUPLICATION -------------------------------------------------
    // A flooded TC reaches this listener once per relaying neighbour in range.
    // Everything below must see each MESSAGE once, not each COPY.
    const uint16_t msgSeq = msg.GetMessageSequenceNumber ();
    if (!m_seenTcMsgs.insert (std::make_pair (originator, msgSeq)).second)
      {
        m_tcDuplicatesSuppressed++;
        return;                       // already accounted for this message
      }

    m_tcCount++;
    m_tcBySender[originator]++;
    m_advertisedLinksPerTc.push_back (tc.neighborAddresses.size ());
    m_tcVtimes.push_back (msg.GetVTime ().GetSeconds ());

    // BUG-001: ANSN delta with modular-16-bit arithmetic. The subtraction is
    // performed in uint16_t (wraps cleanly), then reinterpreted as int16_t to
    // get the shortest signed distance (RFC 1982 serial-number style).
    // With dedup in place these deltas are now genuine: a repeated copy used to
    // inject signedDelta == 0 and drag the mean toward zero.
    auto itAnsn = m_lastAnsnBySender.find (originator);
    if (itAnsn != m_lastAnsnBySender.end ())
      {
        const uint16_t prev = itAnsn->second;
        const uint16_t cur  = tc.ansn;
        const int16_t signedDelta =
            static_cast<int16_t> (static_cast<uint16_t> (cur - prev));
        m_ansnIncrements.push_back (signedDelta);
        if (signedDelta > 1 || signedDelta < 0) m_ansnSkipCount++;
      }
    m_lastAnsnBySender[originator] = tc.ansn;

    // Canonical key over sorted neighbour addresses (content entropy).
    std::vector<uint32_t> addrs;
    addrs.reserve (tc.neighborAddresses.size ());
    for (const auto& a : tc.neighborAddresses) addrs.push_back (a.Get ());
    std::sort (addrs.begin (), addrs.end ());
    std::string key;
    key.reserve (addrs.size () * 4);
    for (uint32_t a : addrs) {
      key.append (reinterpret_cast<const char*> (&a), sizeof (a));
    }
    m_tcContentKeys[key]++;

    m_tcSenderAddrCounts[originator]++;
    m_addressesEverSentTc.insert (originator);
    m_addressesFirstSeen.emplace (originator, now);
    m_addressesLastSeen[originator] = now;

    for (const auto& adv : tc.neighborAddresses)
      {
        m_addressesSeenInTcPayload.insert (adv);
        m_tcAdvertisedAddrCounts[adv]++;
        // REDEFINED (NumEphemeralAddresses): first/last-seen is now fed from TC
        // only. It used to also be written by ObserveDataSentOnAir, which a
        // single listener cannot observe network-wide.
        m_addressesFirstSeen.emplace (adv, now);
        m_addressesLastSeen[adv] = now;
        m_observedDirectedEdges.emplace (originator, adv);

        Edge e {originator, adv};
        if (e.a > e.b) std::swap (e.a, e.b);
        if (m_edgeFirstSeen.find (e) == m_edgeFirstSeen.end ())
          {
            m_edgeFirstSeen[e] = now;
          }
        m_edgeLastSeen[e] = now;
        m_advertisedEdgesAllTime.insert (e);

        // DEG-002: push only the last octet of the IP. The /8 prefix is
        // constant across all 10.0.0.0/8 nodes, so emitting all four bytes
        // destroyed the byte-entropy column's variance.
        const uint32_t raw = adv.Get ();
        m_tcPayloadBytes.push_back (static_cast<uint8_t> (raw & 0xff));
      }

    std::set<Ipv4Address> mprSet (tc.neighborAddresses.begin (),
                                  tc.neighborAddresses.end ());
    m_mprSelectorsByTcSender[originator].push_back (mprSet.size ());

    auto& history = m_mprSelectorsHistoryBySender[originator];
    if (!history.empty () && history.back () != mprSet) m_mprChurnEvents++;
    history.push_back (mprSet);
    m_distinctMprSetsBySender[originator].insert (SetToCanonicalKey (mprSet));

    auto itLast = m_lastTcTimeBySender.find (originator);
    if (itLast != m_lastTcTimeBySender.end ())
      {
        m_tcInterArrivalsPerSender[originator].push_back (now - itLast->second);
      }
    m_lastTcTimeBySender[originator] = now;
    m_controlMessageTimes.push_back (now);
    m_controlMessageSizes.push_back (messageSerializedSize);
  }

  // msgSeq >= 0 enables de-duplication (recommended -- MID is flooded too).
  // Pass -1 only if the sequence number is genuinely unavailable.
  void ObserveMid (Ipv4Address originator, uint32_t messageSerializedSize,
                   int32_t msgSeq = -1)
  {
    if (msgSeq >= 0
        && !m_seenMidMsgs.insert (
              std::make_pair (originator,
                              static_cast<uint16_t> (msgSeq))).second)
      return;
    m_midCount++;
    m_midBytes += messageSerializedSize;
    m_controlMessageTimes.push_back (Simulator::Now ().GetSeconds ());
    m_controlMessageSizes.push_back (messageSerializedSize);
  }

  void ObserveHna (Ipv4Address originator, uint32_t messageSerializedSize,
                   int32_t msgSeq = -1)
  {
    if (msgSeq >= 0
        && !m_seenHnaMsgs.insert (
              std::make_pair (originator,
                              static_cast<uint16_t> (msgSeq))).second)
      return;
    m_hnaCount++;
    m_hnaBytes += messageSerializedSize;
    m_controlMessageTimes.push_back (Simulator::Now ().GetSeconds ());
    m_controlMessageSizes.push_back (messageSerializedSize);
  }

  // ---- Data-plane entry points: RETAINED AS NO-OPS -----------------------
  // Every feature they used to feed requires correlating events a single
  // listener cannot both witness, or traffic that may never pass its radio.
  // Kept so an existing harness compiles unchanged; they feed nothing.
  void ObserveDataSentOnAir (Ipv4Address, Ipv4Address, uint32_t, double) {}
  void ObserveDataDeliveredOnAir (Ipv4Address, Ipv4Address, uint8_t, double,
                                  Mac48Address, double) {}
  void AddDeliveredBytes (uint64_t) {}
  void ObserveDataForwardOnAir (Mac48Address, Mac48Address, Ipv4Address) {}

  // OBS-002(b) / DEG-003: PHY-trace driven MAC frame observation.
  // The caller MUST already have filtered out HELLO (OBS-001) and the 1-hop
  // RTS/CTS/ACK control frames (OBS-007) before calling this.
  // durationSec is from WifiMacHeader::GetDuration() (NAV).
  // NOTE: busy-time and inter-frame spacing are fed by EVERY frame, so control
  // traffic alone keeps both columns non-degenerate. The isData/isRetry
  // arguments are now unused -- Layer2RetransmissionRate was removed because
  // its denominator counted DATA frames only.
  void ObserveMacFrame (double now, double durationSec, bool isData,
                        bool isRetry)
  {
    (void) isData; (void) isRetry;
    if (!m_phyAvailable) return;
    if (durationSec > 0.0)
      m_busyIntervals.emplace_back (now, now + durationSec);
    if (m_lastMacTxEnd >= 0.0)
      m_interFrameSpacing.push_back (now - m_lastMacTxEnd);
    m_lastMacTxEnd = now;
  }

  // Feed EVERY on-air copy of a TC, repeats included -- that is exactly what
  // TcRelayerBreadth* measures. transmitterMac is MAC Addr2 of the frame
  // carrying the copy; hopCount is the OLSR message-header hop count.
  void ObserveTcRelayOnAir (Ipv4Address originator,
                            uint16_t msgSeq,
                            uint8_t hopCount,
                            Mac48Address transmitterMac)
  {
    m_tcSeqByOriginator[originator].insert (msgSeq);
    if (transmitterMac != Mac48Address ())
      m_tcRelayMacsByOriginator[originator].insert (transmitterMac);
    const uint32_t h = static_cast<uint32_t> (hopCount);
    auto it = m_tcMaxHopByOriginator.find (originator);
    if (it == m_tcMaxHopByOriginator.end () || h > it->second)
      m_tcMaxHopByOriginator[originator] = h;
  }

  // -------------------------- Snapshot -------------------------------------
  static std::string FeatureCsvHeader ()
  {
    std::string h;
#define SL_EMIT_NAME(name) if (!h.empty ()) h += ","; h += #name;
    SL_FEATURE_LIST (SL_EMIT_NAME)
#undef SL_EMIT_NAME
    return h;
  }

  // Mode is ignored -- there is one feature set now. Overload kept so existing
  // callers that pass a mode still compile.
  static std::string FeatureCsvHeader (FeatureMode) { return FeatureCsvHeader (); }

  std::string EmitFeatureCsv (double tEnd)
  {
    m_winEnd = tEnd;
    const double dur = std::max (1e-6, m_winEnd - m_winStart);
    const double halfPoint = m_winStart + dur * 0.5;

    // BUG-002/003: bucket edges into first-half / last-half using
    // m_edgeFirstSeen / m_edgeLastSeen (a within-window split; the old
    // cross-window diff was broken).
    m_edgesFirstHalf.clear ();
    m_edgesLastHalf.clear ();
    for (const auto& e : m_advertisedEdgesAllTime)
      {
        auto itF = m_edgeFirstSeen.find (e);
        auto itL = m_edgeLastSeen.find (e);
        if (itF == m_edgeFirstSeen.end () || itL == m_edgeLastSeen.end ())
          continue;
        if (itF->second <  halfPoint) m_edgesFirstHalf.insert (e);
        if (itL->second >= halfPoint) m_edgesLastHalf.insert (e);
      }
    uint64_t emerged = 0, churned = 0;
    for (const auto& e : m_edgesLastHalf)
      if (m_edgesFirstHalf.find (e) == m_edgesFirstHalf.end ()) emerged++;
    for (const auto& e : m_edgesFirstHalf)
      if (m_edgesLastHalf.find (e) == m_edgesLastHalf.end ()) churned++;
    const double edgeEmergenceRate = emerged / dur;
    const double edgeChurnRate     = churned / dur;

    // === A. Control traffic volume =======================================
    // NOTE: post-dedup these are UNIQUE MESSAGES per second, not copies.
    const double tcRate  = m_tcCount  / dur;
    const double midRate = m_midCount / dur;
    const double hnaRate = m_hnaCount / dur;
    const double midBps  = m_midBytes / dur;
    const double hnaBps  = m_hnaBytes / dur;

    std::vector<double> perNodeTcRates;
    for (auto& kv : m_tcBySender) perNodeTcRates.push_back (kv.second / dur);
    const double perNodeTcRateStd = Std (perNodeTcRates);

    // === B. TC structure ==================================================
    const double advLnkMean = Mean (m_advertisedLinksPerTc);
    const double advLnkStd  = Std  (m_advertisedLinksPerTc);
    const double advLnkP95  = Percentile (m_advertisedLinksPerTc, 0.95);
    const double advLnkMax  = m_advertisedLinksPerTc.empty () ? 0.0
        : *std::max_element (m_advertisedLinksPerTc.begin (),
                             m_advertisedLinksPerTc.end ());
    const double   ansnMean    = Mean (m_ansnIncrements);
    const uint64_t ansnSkip    = m_ansnSkipCount;
    const uint64_t distSenders = m_tcBySender.size ();
    std::vector<uint64_t> contentHist;
    contentHist.reserve (m_tcContentKeys.size ());
    for (auto& kv : m_tcContentKeys) contentHist.push_back (kv.second);
    const double tcContentEntropy = ShannonEntropy (contentHist);
    const double tcVtMean = Mean (m_tcVtimes);
    const double tcVtStd  = Std  (m_tcVtimes);

    // === C. Address sets ==================================================
    const uint64_t numAddrInTc = m_addressesSeenInTcPayload.size ();

    uint64_t numAsym = 0;
    for (const auto& pr : m_observedDirectedEdges)
      {
        if (m_observedDirectedEdges.find ({pr.second, pr.first})
            == m_observedDirectedEdges.end ())
          numAsym++;
      }

    // REDEFINED (NumPhantomAddresses): "advertised in TC but never ORIGINATED
    // a TC". The old definition also required "and never sent DATA", which a
    // single listener cannot establish. Dropping that clause yields a clean
    // superset and is exactly the DCFM fictitious-node signal.
    uint64_t numPhantom = 0;
    for (const auto& a : m_addressesSeenInTcPayload)
      {
        if (m_addressesEverSentTc.find (a) == m_addressesEverSentTc.end ())
          numPhantom++;
      }

    // REDEFINED (NumEphemeralAddresses): first/last-seen are now TC-only.
    uint64_t numEphemeral = 0;
    const double halfDur = dur * 0.5;
    for (auto& kv : m_addressesFirstSeen)
      {
        auto itLast = m_addressesLastSeen.find (kv.first);
        if (itLast == m_addressesLastSeen.end ()) continue;
        if ((itLast->second - kv.second) < halfDur) numEphemeral++;
      }

    // === D. MPR selection ================================================
    std::vector<double> allSelectorCounts;
    for (auto& kv : m_mprSelectorsByTcSender)
      for (auto c : kv.second) allSelectorCounts.push_back (c);
    const double   mprSelMean = Mean (allSelectorCounts);
    const double   mprSelStd  = Std  (allSelectorCounts);
    const uint64_t mprChurn   = m_mprChurnEvents;
    uint64_t totalDistinctMprSets = 0;
    for (auto& kv : m_distinctMprSetsBySender)
      totalDistinctMprSets += kv.second.size ();

    // === F. MAC layer (DEG-003: gated on PHY availability) ================
    double busyFrac = 0.0, ifsMean = 0.0;
    if (m_phyAvailable)
      {
        // BUG-006 fix: union-of-intervals channel busy fraction.
        busyFrac = ComputeBusyFraction (m_busyIntervals, m_winStart, m_winEnd);
        ifsMean  = Mean (m_interFrameSpacing);
      }

    // === H. Time & periodicity ============================================
    std::vector<double> allTcGaps;
    for (auto& kv : m_tcInterArrivalsPerSender)
      for (double g : kv.second) allTcGaps.push_back (g);
    const double tcGapMean = Mean (allTcGaps);
    const double tcGapStd  = Std  (allTcGaps);
    const double tcGapP95  = Percentile (allTcGaps, 0.95);

    std::vector<double> tcPerSlot;
    if (m_tcCount > 0)
      {
        const int nslots = static_cast<int> (std::ceil (dur));
        tcPerSlot.assign (nslots > 0 ? nslots : 1, 0.0);
        for (double t : m_controlMessageTimes)
          {
            const int s = static_cast<int> (t - m_winStart);
            if (s >= 0 && s < static_cast<int> (tcPerSlot.size ()))
              tcPerSlot[s] += 1.0;
          }
      }
    const double tcHurst = HurstRS (tcPerSlot);

    std::vector<double> ctrlGaps;
    if (m_controlMessageTimes.size () >= 2)
      {
        std::vector<double> t = m_controlMessageTimes;
        std::sort (t.begin (), t.end ());
        for (size_t i = 1; i < t.size (); ++i) ctrlGaps.push_back (t[i] - t[i-1]);
      }
    const double ctrlSkew = Skewness (ctrlGaps);
    const double ctrlKurt = Kurtosis (ctrlGaps);

    // === I. Entropy & stats ==============================================
    std::vector<uint64_t> hSender, hAdv;
    for (auto& kv : m_tcSenderAddrCounts)     hSender.push_back (kv.second);
    for (auto& kv : m_tcAdvertisedAddrCounts) hAdv.push_back (kv.second);
    const double tcSenderEnt = ShannonEntropy (hSender);
    const double tcAdvEnt    = ShannonEntropy (hAdv);
    const double byteEnt     = ByteEntropy (m_tcPayloadBytes);
#if SL_INCLUDE_PACKET_SIZE_SHAPE
    // REDEFINED: control-message sizes only (the old m_packetSizes also took
    // DATA byte counts). WARNING: this is the shape of the TC/MID/HNA size
    // distribution, i.e. the same channel FPNT perturbs by padding TC.
    std::vector<double> sizesD;
    sizesD.reserve (m_controlMessageSizes.size ());
    for (auto s : m_controlMessageSizes) sizesD.push_back (s);
    const double pktSkew = Skewness (sizesD);
    const double pktKurt = Kurtosis (sizesD);
#endif

    // === J. Topology graph features ======================================
    std::map<Ipv4Address, uint32_t> idx;
    auto getIdx = [&] (Ipv4Address a) -> uint32_t {
      auto it = idx.find (a);
      if (it != idx.end ()) return it->second;
      const uint32_t v = idx.size ();
      idx[a] = v;
      return v;
    };
    for (const auto& e : m_advertisedEdgesAllTime) { getIdx (e.a); getIdx (e.b); }
    const uint32_t N = idx.size ();
    std::vector<std::vector<uint32_t>> adj (N);
    for (const auto& e : m_advertisedEdgesAllTime)
      {
        const uint32_t u = idx[e.a];
        const uint32_t v = idx[e.b];
        if (u == v) continue;
        adj[u].push_back (v);
        adj[v].push_back (u);
      }
    for (auto& nb : adj)
      {
        std::sort (nb.begin (), nb.end ());
        nb.erase (std::unique (nb.begin (), nb.end ()), nb.end ());
      }

    std::vector<double> degrees (N);
    for (uint32_t i = 0; i < N; ++i) degrees[i] = adj[i].size ();
    const double degMean = Mean (degrees);
    const double degStd  = Std  (degrees);
    const double degSkew = Skewness (degrees);
    const double degKurt = Kurtosis (degrees);
    uint64_t degOne = 0;
    for (double d : degrees) if (static_cast<int> (d) == 1) degOne++;

    double clusterSum = 0.0;
    uint64_t triangles3 = 0;
    for (uint32_t v = 0; v < N; ++v)
      {
        const auto& nbv = adj[v];
        if (nbv.size () < 2) continue;
        uint64_t edgesAmongNb = 0;
        for (size_t i = 0; i < nbv.size (); ++i)
          for (size_t j = i + 1; j < nbv.size (); ++j)
            {
              const uint32_t a = nbv[i], b = nbv[j];
              if (std::binary_search (adj[a].begin (), adj[a].end (), b))
                edgesAmongNb++;
            }
        const double k = nbv.size ();
        clusterSum += (2.0 * edgesAmongNb) / (k * (k - 1));
        triangles3 += edgesAmongNb;
      }
    const double   clustering = (N > 0) ? (clusterSum / N) : 0.0;
    const uint64_t triangles  = triangles3 / 3;

    // Connected components.
    std::vector<int> componentId (N, -1);
    uint32_t numComponents = 0;
    for (uint32_t s = 0; s < N; ++s)
      {
        if (componentId[s] != -1) continue;
        numComponents++;
        std::queue<uint32_t> q;
        q.push (s);
        componentId[s] = static_cast<int> (numComponents);
        while (!q.empty ())
          {
            const uint32_t u = q.front (); q.pop ();
            for (uint32_t v : adj[u])
              if (componentId[v] == -1)
                {
                  componentId[v] = static_cast<int> (numComponents);
                  q.push (v);
                }
          }
      }

    // Eccentricity, diameter, radius.
    std::vector<int> eccentricity (N, 0);
    int diameterFinal = 0;
    for (uint32_t s = 0; s < N; ++s)
      {
        std::vector<int> dist (N, -1);
        std::queue<uint32_t> bq;
        bq.push (s);
        dist[s] = 0;
        int best = 0;
        while (!bq.empty ())
          {
            const uint32_t u = bq.front (); bq.pop ();
            for (uint32_t w : adj[u])
              if (dist[w] < 0)
                {
                  dist[w] = dist[u] + 1;
                  bq.push (w);
                  if (dist[w] > best) best = dist[w];
                }
          }
        eccentricity[s] = best;
        if (best > diameterFinal) diameterFinal = best;
      }
    const int diameter = diameterFinal;
    // BUG-005: initialise radius with int-max and take min over POSITIVE
    // eccentricities; collapse to 0 only if none is positive.
    int radius = std::numeric_limits<int>::max ();
    for (uint32_t i = 0; i < N; ++i)
      if (eccentricity[i] > 0 && eccentricity[i] < radius) radius = eccentricity[i];
    if (radius == std::numeric_limits<int>::max ()) radius = 0;

    const double density = (N >= 2)
        ? (2.0 * m_advertisedEdgesAllTime.size () / (N * (N - 1.0)))
        : 0.0;

    // Betweenness & closeness (Brandes' algorithm).
    std::vector<double> betweenness (N, 0.0);
    std::vector<double> closenessV  (N, 0.0);
    for (uint32_t s = 0; s < N; ++s)
      {
        std::vector<std::vector<uint32_t>> P (N);
        std::vector<int> sigma (N, 0); sigma[s] = 1;
        std::vector<int> dist  (N, -1); dist[s]  = 0;
        std::queue<uint32_t> bfsq; bfsq.push (s);
        std::vector<uint32_t> stk;
        while (!bfsq.empty ())
          {
            const uint32_t v = bfsq.front (); bfsq.pop ();
            stk.push_back (v);
            for (uint32_t w : adj[v])
              {
                if (dist[w] < 0) { dist[w] = dist[v] + 1; bfsq.push (w); }
                if (dist[w] == dist[v] + 1)
                  {
                    sigma[w] += sigma[v];
                    P[w].push_back (v);
                  }
              }
          }
        double sumDist = 0; int reach = 0;
        for (uint32_t i = 0; i < N; ++i)
          if (i != s && dist[i] > 0) { sumDist += dist[i]; reach++; }
        if (sumDist > 0) closenessV[s] = static_cast<double> (reach) / sumDist;

        std::vector<double> delta (N, 0.0);
        while (!stk.empty ())
          {
            const uint32_t w = stk.back (); stk.pop_back ();
            for (uint32_t v : P[w])
              {
                if (sigma[w] == 0) continue;
                delta[v] += (static_cast<double> (sigma[v]) / sigma[w])
                            * (1.0 + delta[w]);
              }
            if (w != s) betweenness[w] += delta[w];
          }
      }
    for (double& b : betweenness) b /= 2.0;

    const double btwMean = Mean (betweenness);
    const double btwStd  = Std  (betweenness);
    const double btwMax  = betweenness.empty () ? 0.0
        : *std::max_element (betweenness.begin (), betweenness.end ());
    const double closMean = Mean (closenessV);
    const double closStd  = Std  (closenessV);

    // Edge persistence (within-window).
    double sumPersistence = 0.0;
    for (const auto& e : m_advertisedEdgesAllTime)
      sumPersistence += (m_edgeLastSeen[e] - m_edgeFirstSeen[e]);
    const double edgePersistMean = m_advertisedEdgesAllTime.empty () ? 0.0
        : (sumPersistence / m_advertisedEdgesAllTime.size ());

    // Cycle counts (BUG-007 fix: dead branch removed in CountCyclesOfLength).
    const uint64_t hexCycles   = CountCyclesOfLength (adj, 6);
    const uint64_t shortCycles = CountCyclesOfLength (adj, 3)
                               + CountCyclesOfLength (adj, 4)
                               + CountCyclesOfLength (adj, 5);
    const double spectralRadius = PowerIterationLargestEigen (adj);

    // === K. Defense-detection breadth ====================================
    std::vector<double> tcOrigCounts, tcRelayBreadths, tcMaxHops;
    for (const auto& kv : m_tcSeqByOriginator)
      tcOrigCounts.push_back (static_cast<double> (kv.second.size ()));
    for (const auto& kv : m_tcRelayMacsByOriginator)
      tcRelayBreadths.push_back (static_cast<double> (kv.second.size ()));
    for (const auto& kv : m_tcMaxHopByOriginator)
      tcMaxHops.push_back (static_cast<double> (kv.second));

    auto vecMin = [] (const std::vector<double>& v) -> double {
      if (v.empty ()) return 0.0;
      double mn = v.front (); for (double x : v) if (x < mn) mn = x; return mn;
    };
    auto vecMax = [] (const std::vector<double>& v) -> double {
      if (v.empty ()) return 0.0;
      double mx = v.front (); for (double x : v) if (x > mx) mx = x; return mx;
    };

    // ---- Assemble the row IN SL_FEATURE_LIST ORDER ----------------------
    std::vector<double> v;
    v.reserve (FeatureCount ());
    // A (6)
    v.push_back (tcRate);            v.push_back (midRate);
    v.push_back (hnaRate);           v.push_back (midBps);
    v.push_back (hnaBps);            v.push_back (perNodeTcRateStd);
    // B (10)
    v.push_back (advLnkMean);        v.push_back (advLnkStd);
    v.push_back (advLnkP95);         v.push_back (advLnkMax);
    v.push_back (ansnMean);          v.push_back (static_cast<double> (ansnSkip));
    v.push_back (static_cast<double> (distSenders));
    v.push_back (tcContentEntropy);  v.push_back (tcVtMean);
    v.push_back (tcVtStd);
    // C (4)
    v.push_back (static_cast<double> (numAddrInTc));
    v.push_back (static_cast<double> (numAsym));
    v.push_back (static_cast<double> (numPhantom));
    v.push_back (static_cast<double> (numEphemeral));
    // D (4)
    v.push_back (mprSelMean);        v.push_back (mprSelStd);
    v.push_back (static_cast<double> (mprChurn));
    v.push_back (static_cast<double> (totalDistinctMprSets));
    // F (2)
    v.push_back (busyFrac);          v.push_back (ifsMean);
    // H (6)
    v.push_back (tcGapMean);         v.push_back (tcGapStd);
    v.push_back (tcGapP95);          v.push_back (tcHurst);
    v.push_back (ctrlSkew);          v.push_back (ctrlKurt);
    // I (3, +2 optional)
    v.push_back (tcSenderEnt);       v.push_back (tcAdvEnt);
    v.push_back (byteEnt);
#if SL_INCLUDE_PACKET_SIZE_SHAPE
    v.push_back (pktSkew);           v.push_back (pktKurt);
#endif
    // J (22)
    v.push_back (degMean);           v.push_back (degStd);
    v.push_back (degSkew);           v.push_back (degKurt);
    v.push_back (static_cast<double> (degOne));
    v.push_back (clustering);
    v.push_back (static_cast<double> (triangles));
    v.push_back (static_cast<double> (numComponents));
    v.push_back (static_cast<double> (diameter));
    v.push_back (static_cast<double> (radius));
    v.push_back (density);
    v.push_back (btwMean);           v.push_back (btwStd);
    v.push_back (btwMax);
    v.push_back (closMean);          v.push_back (closStd);
    v.push_back (edgePersistMean);
    v.push_back (edgeEmergenceRate); v.push_back (edgeChurnRate);
    v.push_back (static_cast<double> (hexCycles));
    v.push_back (static_cast<double> (shortCycles));
    v.push_back (spectralRadius);
    // K (12)
    v.push_back (vecMin (tcOrigCounts));    v.push_back (Mean (tcOrigCounts));
    v.push_back (Std    (tcOrigCounts));    v.push_back (vecMax (tcOrigCounts));
    v.push_back (vecMin (tcRelayBreadths)); v.push_back (Mean (tcRelayBreadths));
    v.push_back (Std    (tcRelayBreadths)); v.push_back (vecMax (tcRelayBreadths));
    v.push_back (vecMin (tcMaxHops));       v.push_back (Mean (tcMaxHops));
    v.push_back (Std    (tcMaxHops));       v.push_back (vecMax (tcMaxHops));

    // Header/row lock-step guard. This is a hard error, not a warning: a
    // silently shifted column would poison every downstream result.
    if (v.size () != FeatureCount ())
      {
        std::ostringstream e;
        e << "olsr_window_features: row/header mismatch -- emitted "
          << v.size () << " values for " << FeatureCount () << " columns";
        NS_FATAL_ERROR (e.str ());
      }

    std::ostringstream r;
    r << std::fixed << std::setprecision (6);
    for (size_t i = 0; i < v.size (); ++i)
      {
        if (i) r << ",";
        r << v[i];
      }
    return r.str ();
  }

  // Mode is ignored; overload kept for source compatibility.
  std::string EmitFeatureCsv (double tEnd, FeatureMode) { return EmitFeatureCsv (tEnd); }

  // ----- Public test hooks (used by harness --self-test) -------------------
  static uint64_t TestCountCyclesOfLength (
      const std::vector<std::vector<uint32_t>>& adj, uint32_t k)
  {
    return CountCyclesOfLength (adj, k);
  }

private:
  // ------------- raw observation state ------------------------------------
  double m_winStart = 0.0, m_winEnd = 0.0;

  uint64_t m_tcCount = 0, m_midCount = 0, m_hnaCount = 0;
  uint64_t m_midBytes = 0, m_hnaBytes = 0;

  // TC/MID/HNA de-duplication: a flooded message reaches this listener once
  // per relaying neighbour in range.
  std::set<std::pair<Ipv4Address, uint16_t>> m_seenTcMsgs;
  std::set<std::pair<Ipv4Address, uint16_t>> m_seenMidMsgs;
  std::set<std::pair<Ipv4Address, uint16_t>> m_seenHnaMsgs;
  uint64_t m_tcDuplicatesSuppressed = 0;

  std::map<Ipv4Address, uint64_t> m_tcBySender;
  std::vector<double>             m_advertisedLinksPerTc;
  std::vector<double>             m_tcVtimes;
  std::map<Ipv4Address, uint16_t> m_lastAnsnBySender;
  std::vector<double>             m_ansnIncrements;
  uint64_t                        m_ansnSkipCount = 0;
  std::map<std::string, uint64_t> m_tcContentKeys;
  std::vector<uint8_t>            m_tcPayloadBytes;

  std::map<Ipv4Address, uint64_t> m_tcSenderAddrCounts;
  std::map<Ipv4Address, uint64_t> m_tcAdvertisedAddrCounts;
  std::set<Ipv4Address>           m_addressesSeenInTcPayload;
  std::set<Ipv4Address>           m_addressesEverSentTc;
  std::map<Ipv4Address, double>   m_addressesFirstSeen;
  std::map<Ipv4Address, double>   m_addressesLastSeen;
  std::set<std::pair<Ipv4Address, Ipv4Address>> m_observedDirectedEdges;

  std::map<Ipv4Address, std::vector<double>>                m_mprSelectorsByTcSender;
  std::map<Ipv4Address, std::vector<std::set<Ipv4Address>>> m_mprSelectorsHistoryBySender;
  uint64_t                                                  m_mprChurnEvents = 0;
  std::map<Ipv4Address, std::set<std::string>>              m_distinctMprSetsBySender;

  // PHY-trace driven MAC layer state.
  bool     m_phyAvailable = false;
  std::vector<std::pair<double,double>> m_busyIntervals;
  std::vector<double> m_interFrameSpacing;
  double   m_lastMacTxEnd = -1.0;

  std::map<Ipv4Address, std::vector<double>> m_tcInterArrivalsPerSender;
  std::map<Ipv4Address, double>              m_lastTcTimeBySender;
  std::vector<double>                        m_controlMessageTimes;
  std::vector<uint32_t>                      m_controlMessageSizes;

  // Graph state.
  struct Edge
  {
    Ipv4Address a, b;
    bool operator< (const Edge& o) const
    { return a < o.a || (a == o.a && b < o.b); }
    bool operator== (const Edge& o) const
    { return a == o.a && b == o.b; }
  };
  std::set<Edge>         m_advertisedEdgesAllTime;
  std::map<Edge, double> m_edgeFirstSeen;
  std::map<Edge, double> m_edgeLastSeen;
  std::set<Edge>         m_edgesFirstHalf;
  std::set<Edge>         m_edgesLastHalf;

  // Defense-detection breadth, fed from the on-air sniffer.
  std::map<Ipv4Address, std::set<uint16_t>>     m_tcSeqByOriginator;
  std::map<Ipv4Address, std::set<Mac48Address>> m_tcRelayMacsByOriginator;
  std::map<Ipv4Address, uint32_t>               m_tcMaxHopByOriginator;

  // --------------- internal helpers ---------------------------------------
  static std::string SetToCanonicalKey (const std::set<Ipv4Address>& s)
  {
    std::string k; k.reserve (s.size () * 4);
    for (const auto& a : s)
      {
        uint32_t raw = a.Get ();
        k.append (reinterpret_cast<const char*> (&raw), sizeof (raw));
      }
    return k;
  }

  // BUG-006: union of busy intervals (replaces sum-of-NAVs).
  static double ComputeBusyFraction (std::vector<std::pair<double,double>> v,
                                     double winStart, double winEnd)
  {
    if (v.empty ()) return 0.0;
    const double dur = std::max (1e-6, winEnd - winStart);
    for (auto& p : v)
      {
        if (p.first  < winStart) p.first  = winStart;
        if (p.second > winEnd)   p.second = winEnd;
      }
    std::sort (v.begin (), v.end (),
               [] (const std::pair<double,double>& a,
                   const std::pair<double,double>& b)
               { return a.first < b.first; });
    double total = 0.0;
    double curS = v[0].first;
    double curE = v[0].second;
    for (size_t i = 1; i < v.size (); ++i)
      {
        if (v[i].first <= curE)
          {
            if (v[i].second > curE) curE = v[i].second;
          }
        else
          {
            total += std::max (0.0, curE - curS);
            curS = v[i].first;
            curE = v[i].second;
          }
      }
    total += std::max (0.0, curE - curS);
    return std::min (1.0, total / dur);
  }

  // BUG-007: dead `depth==1 && w < path[1]` branch removed. The DFS is entered
  // at depth=2 from the outer loop, so the branch was unreachable.
  static uint64_t
  CountCyclesOfLength (const std::vector<std::vector<uint32_t>>& adj, uint32_t k)
  {
    if (k < 3) return 0;
    uint64_t total = 0;
    const uint32_t N = adj.size ();
    std::vector<uint32_t> path; path.reserve (k);
    std::vector<bool>     visited (N, false);

    std::function<void (uint32_t, uint32_t, uint32_t)> dfs =
      [&] (uint32_t start, uint32_t v, uint32_t depth) {
        if (depth == k)
          {
            for (uint32_t w : adj[v])
              if (w == start) { total++; break; }
            return;
          }
        for (uint32_t w : adj[v])
          {
            if (visited[w]) continue;
            if (w < start)  continue;            // rotation pruning
            visited[w] = true;
            path.push_back (w);
            dfs (start, w, depth + 1);
            path.pop_back ();
            visited[w] = false;
          }
      };
    for (uint32_t s = 0; s < N; ++s)
      {
        visited[s] = true;
        path.push_back (s);
        for (uint32_t w : adj[s])
          {
            if (w <= s) continue;
            visited[w] = true;
            path.push_back (w);
            dfs (s, w, 2);
            path.pop_back ();
            visited[w] = false;
          }
        path.pop_back ();
        visited[s] = false;
      }
    return total / 2;
  }

  static double
  PowerIterationLargestEigen (const std::vector<std::vector<uint32_t>>& adj)
  {
    const uint32_t N = adj.size ();
    if (N == 0) return 0.0;
    std::vector<double> v (N, 1.0 / std::sqrt (static_cast<double> (N)));
    std::vector<double> next (N, 0.0);
    double lambda = 0.0;
    for (int iter = 0; iter < 100; ++iter)
      {
        std::fill (next.begin (), next.end (), 0.0);
        for (uint32_t i = 0; i < N; ++i)
          for (uint32_t j : adj[i])
            next[i] += v[j];
        double norm = 0.0;
        for (double x : next) norm += x * x;
        norm = std::sqrt (norm);
        if (norm < 1e-12) return 0.0;
        double newLambda = 0.0;
        for (uint32_t i = 0; i < N; ++i) newLambda += v[i] * next[i];
        for (uint32_t i = 0; i < N; ++i) next[i] /= norm;
        v.swap (next);
        if (std::abs (newLambda - lambda) < 1e-8) { lambda = newLambda; break; }
        lambda = newLambda;
      }
    return std::abs (lambda);
  }
};

} // namespace olsreval
} // namespace ns3

#endif // OLSR_WINDOW_FEATURES_H
