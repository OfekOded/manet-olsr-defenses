/*
 * Trust-based OLSR defense (Adnane et al., Computer Communications 36, 2013)
 *
 * olsr-alert-distributor.h -- the second countermeasure (paper Section 7):
 * distribute trust information so nodes that could not detect the attacker
 * locally still mistrust it network-wide.
 *
 * Per the paper the alert "is not a new type of message" -- it re-broadcasts the
 * control messages (the PROOF) that revealed the inconsistency, and each receiver
 * RE-RUNS the same reasoning before accepting. To respect the hard "no new OLSR
 * message / bare-OLSR" constraint, propagation is modelled by an IDEALIZED,
 * process-wide bus (OlsrTrustBus) under an idealized-authentication assumption --
 * i.e. it measures the effect of network-wide trust sharing without touching the
 * wire format or requiring real SOLSR signatures.
 *
 * Only FALSIFIABLE consistency detections (Formulas 6,7,8,12) are propagated; the
 * black-hole Formula 10 is a non-event with no provable artifact and is NOT
 * announced (it stays a local, independent detection at each victim).
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef OLSR_ALERT_DISTRIBUTOR_H
#define OLSR_ALERT_DISTRIBUTOR_H

#include "ns3/ipv4-address.h"
#include "ns3/nstime.h"

#include <functional>
#include <set>
#include <string>
#include <vector>

namespace ns3
{
namespace olsr
{

/**
 * \ingroup olsr
 * \brief The falsifiable evidence for a consistency detection (the "proof"
 * the alert carries). A receiver re-verifies it before accepting the mistrust.
 */
struct ConsistencyProof
{
    std::string formula;               //!< "6", "7", "8", "12".
    Ipv4Address accused;               //!< node the proof incriminates.
    std::vector<Ipv4Address> advertised; //!< e.g. the TC MPR-selector list of the accused.
    std::vector<Ipv4Address> reference;  //!< e.g. accused's HELLO sym-neighbours (6) / accuser's MPR set (7).

    /// Re-derive the inconsistency from the carried evidence (idealized auth: evidence is trusted authentic).
    bool Verify(Ipv4Address accuser) const;
};

/**
 * \ingroup olsr
 * \brief One alert in flight on the bus: who detected it and the proof.
 */
struct TrustAlert
{
    Ipv4Address accuser;
    ConsistencyProof proof;
};

class OlsrAlertDistributor;

/**
 * \ingroup olsr
 * \brief Idealized, process-wide propagation channel (models the §7 flood).
 *
 * Distributors register here; Broadcast() delivers an alert to every other
 * registered node (network-wide idealized flooding). Holds non-owning pointers;
 * distributors MUST Unregister on dispose (each sim run re-registers fresh).
 */
class OlsrTrustBus
{
  public:
    static OlsrTrustBus& Instance();

    void Register(OlsrAlertDistributor* d);
    void Unregister(OlsrAlertDistributor* d);
    /// Deliver \p a to all registered distributors except \p from.
    void Broadcast(const TrustAlert& a, OlsrAlertDistributor* from, Time now);

  private:
    OlsrTrustBus() = default;
    std::vector<OlsrAlertDistributor*> m_nodes;
};

/**
 * \ingroup olsr
 * \brief Per-node alert sender/receiver. Owned by OlsrTrustDefense.
 */
class OlsrAlertDistributor
{
  public:
    /// Called when a (re-verified) alert is accepted -> the owner mistrusts \p accused.
    using AcceptCallback =
        std::function<void(Ipv4Address accused, const std::string& formula, Ipv4Address accuser, Time now)>;

    OlsrAlertDistributor(Ipv4Address self, AcceptCallback onAccept);
    ~OlsrAlertDistributor();

    void Start(); //!< register on the bus.
    void Stop();  //!< unregister + clear.

    /// Local consistency detection -> broadcast the proof network-wide.
    void Announce(const ConsistencyProof& proof, Time now);

    /// Bus -> this node: dedup, re-verify the proof, then accept (mistrust accused).
    void Deliver(const TrustAlert& a, Time now);

    Ipv4Address Self() const { return m_self; }

  private:
    static std::string Key(const TrustAlert& a);

    Ipv4Address m_self;
    AcceptCallback m_onAccept;
    bool m_running;
    std::set<std::string> m_seen; //!< processed-alert dedup (per node, per run).
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_ALERT_DISTRIBUTOR_H */
