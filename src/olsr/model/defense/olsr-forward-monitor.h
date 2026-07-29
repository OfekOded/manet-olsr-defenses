/*
 * Trust-based OLSR defense (Adnane et al., Computer Communications 36, 2013)
 *
 * olsr-forward-monitor.h -- FORWARD MONITORING / WAIT EVENT (priority 1, the
 * black-hole core). Implements the mechanism base OLSR lacks (paper Section 4.1,
 * the "x ->8 TC/DATA" awaiting event) and the detection of paper Formula (10):
 *
 *   y in MPRSx;
 *     ( x sends TCx ; x does NOT overhear (TCx) retransmitted by y )  OR
 *     ( x sends DATAx; x does NOT overhear (DATAx) retransmitted by y )
 *   ==> x must mistrust y      (Formula 10)
 *
 * After x transmits a TC/DATA it registers a pending-forward record (msg
 * identity, responsible MPR, deadline) and passively OVERHEARS neighbour
 * transmissions. Overhearing the MPR re-air the same message clears the record.
 * If the deadline passes first, an INTERNAL forward-failure is raised (a local
 * std::function call -- NOT a new OLSR message) which the owner turns into a
 * Formula (10) mistrust decision.
 *
 * This module is pure OBSERVATION + the timeout decision input; it never
 * mistrusts or alters routing itself (that is the trust-state / response side).
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef OLSR_FORWARD_MONITOR_H
#define OLSR_FORWARD_MONITOR_H

#include "olsr-trust-config.h"

#include "ns3/event-id.h"
#include "ns3/ipv4-address.h"
#include "ns3/mac48-address.h"
#include "ns3/nstime.h"
#include "ns3/packet.h"

#include <cstdint>
#include <functional>
#include <list>
#include <map>
#include <set>

namespace ns3
{
namespace olsr
{

class RoutingProtocol; // non-owning back-pointer, included in the .cc

/// Which branch of Formula (10) raised the internal forward-failure.
enum class ForwardFailureType
{
    Data, //!< DATAx branch.
    Tc    //!< TCx branch.
};

/**
 * \ingroup olsr
 * \brief Passive watchdog over a node's selected MPRs (paper Formula 10).
 *
 * Lifetime is owned by OlsrTrustDefense. The owner feeds it the send/overhear
 * events and supplies the forward-failure callback (the "internal error").
 */
class OlsrForwardMonitor
{
  public:
    /**
     * \param mpr   the MPR that failed to forward.
     * \param type  DATA or TC branch of Formula (10).
     * \param consecutiveFailures running count of consecutive misses for this MPR.
     * \param now   current simulation time.
     */
    using ForwardFailureCallback =
        std::function<void(Ipv4Address mpr, ForwardFailureType type, uint32_t consecutiveFailures, Time now)>;

    OlsrForwardMonitor(const OlsrTrustDefenseConfig& cfg,
                       RoutingProtocol* proto,
                       Ipv4Address self,
                       ForwardFailureCallback onFailure);

    /// Begin the periodic expiry sweep.
    void Start();
    /// Cancel the sweep and drop all pending state (call from DoDispose).
    void Stop();

    // ---- send-side registration (called by the owner from the OLSR hooks) ----

    /**
     * \brief Register that a data packet was handed to \p nextHop for forwarding.
     * Registered only when nextHop is one of x's MPRs (Formula 10 is MPR-scoped),
     * and only for traffic in scope (originated here, or relayed if configured).
     * \param originatedHere true if x is the origin of this packet (DATAx).
     */
    void OnDataForward(Ptr<const Packet> p,
                       Ipv4Address nextHop,
                       Ipv4Address dst,
                       bool originatedHere,
                       Time now);

    /// \brief Register that x generated a TCx; its MPRs (MPRSx) must re-flood it.
    void OnTcGenerated(Time now);

    /**
     * \brief Feed an overheard neighbour transmission (promiscuous sniffer).
     * Clears the matching pending record (DATA matched by packet UID, TC matched
     * by originator==self) and learns the transmitter's MAC<->IP from OLSR control
     * packets.
     */
    void OnOverheard(Mac48Address tx, Mac48Address rx, Ptr<const Packet> pkt, Time now);

    /// \brief Cancel a pending DATA record because x dropped the packet itself
    /// (no route / queue full) -- do not blame an MPR for a packet x never sent.
    void OnLocalDrop(Ptr<const Packet> p);

  private:
    void Sweep();                              //!< expire overdue records -> raise forward-failures.
    void CreditTcForward(Ipv4Address forwarder, Time now); //!< mark a TC re-aired by \p forwarder.
    void HandleOverheardOlsr(Mac48Address tx, Ipv4Address srcIp, Ptr<Packet> olsrPayload, Time now);
    void HandleOverheardData(Mac48Address tx, Ptr<const Packet> pkt, Time now);
    void RaiseFailure(Ipv4Address mpr, ForwardFailureType type, Time now);

    /// A data packet awaiting confirmation that \p nextHop re-aired it.
    struct DataRecord
    {
        Ipv4Address nextHop;
        Ipv4Address dst;
        bool originatedHere;
        Time deadline;
    };

    /// A TCx awaiting re-flood by the MPRs that have not yet been overheard.
    struct TcRecord
    {
        std::set<Ipv4Address> pendingForwarders; //!< MPRs not yet seen re-airing this TC.
        Time deadline;
    };

    OlsrTrustDefenseConfig m_cfg;
    RoutingProtocol* m_proto; //!< non-owning.
    Ipv4Address m_self;
    ForwardFailureCallback m_onFailure;

    std::map<uint64_t, DataRecord> m_dataPending; //!< keyed by ns-3 packet UID.
    std::list<TcRecord> m_tcPending;               //!< oldest-first.
    std::map<Mac48Address, Ipv4Address> m_macToIp; //!< learned from overheard OLSR control packets.
    std::map<Ipv4Address, uint32_t> m_failCount;   //!< consecutive forward-failures per MPR.

    EventId m_sweepEvent;
    bool m_running;
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_FORWARD_MONITOR_H */
