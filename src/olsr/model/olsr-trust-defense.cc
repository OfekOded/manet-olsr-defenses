/*
 * Trust-based OLSR defense (Adnane et al., Computer Communications 36, 2013)
 * olsr-trust-defense.cc
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "olsr-trust-defense.h"

#include "olsr-routing-protocol.h"
#include "defense/olsr-alert-distributor.h"
#include "defense/olsr-consistency-rules.h"
#include "defense/olsr-forward-monitor.h"
#include "defense/olsr-provable-identity.h"
#include "defense/olsr-trust-state.h"

#include "ns3/boolean.h"
#include "ns3/log.h"
#include "ns3/nstime.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"

#include <algorithm>
#include <sstream>

namespace ns3
{
namespace olsr
{

NS_LOG_COMPONENT_DEFINE("OlsrTrustDefense");
NS_OBJECT_ENSURE_REGISTERED(OlsrTrustDefense);

TypeId
OlsrTrustDefense::GetTypeId()
{
    // Defaults below MUST match OlsrTrustDefenseConfig (the canonical config location).
    static TypeId tid =
        TypeId("ns3::olsr::OlsrTrustDefense")
            .SetParent<OlsrDefenseStrategy>()
            .SetGroupName("Olsr")
            .AddConstructor<OlsrTrustDefense>()
            // --- per-sub-module enables ---
            .AddAttribute("EnableForwardMonitor",
                          "Enable the Formula-10 black-hole forward monitor.",
                          BooleanValue(true),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_enableForwardMonitor),
                          MakeBooleanChecker())
            .AddAttribute("EnableConsistencyRules",
                          "Enable the complementary consistency checks (Formulas 6,7,9b).",
                          BooleanValue(false),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_enableConsistencyRules),
                          MakeBooleanChecker())
            .AddAttribute("EnableProvableIdentity",
                          "Enable SOLSR provable identity (Formula 13, stub, off by default).",
                          BooleanValue(false),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_enableProvableIdentity),
                          MakeBooleanChecker())
            .AddAttribute("EnableAlertDistribution",
                          "Enable §7 trust-alert distribution (idealized bus; propagates falsifiable "
                          "consistency detections 6/7/8/12 network-wide, NOT black-hole Formula 10).",
                          BooleanValue(false),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_enableAlertDistribution),
                          MakeBooleanChecker())
            // --- forward monitor (Formula 10) ---
            .AddAttribute("ForwardTimeout",
                          "Awaiting period to overhear an MPR re-forward a TC/DATA before failure.",
                          TimeValue(Seconds(3.0)),
                          MakeTimeAccessor(&OlsrTrustDefense::m_forwardTimeout),
                          MakeTimeChecker())
            .AddAttribute("CheckInterval",
                          "Granularity of the forward-failure expiry sweep.",
                          TimeValue(Seconds(0.25)),
                          MakeTimeAccessor(&OlsrTrustDefense::m_checkInterval),
                          MakeTimeChecker())
            .AddAttribute("MonitorData",
                          "Watch DATA forwarding (DATAx branch of Formula 10).",
                          BooleanValue(true),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_monitorData),
                          MakeBooleanChecker())
            .AddAttribute("MonitorTc",
                          "Watch TC forwarding (TCx branch of Formula 10).",
                          BooleanValue(true),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_monitorTc),
                          MakeBooleanChecker())
            .AddAttribute("MonitorRelayedData",
                          "Also watch data x merely RELAYS (generalized watchdog); default false "
                          "== faithful Formula 10 (only DATAx originated by x).",
                          BooleanValue(false),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_monitorRelayedData),
                          MakeBooleanChecker())
            .AddAttribute("StrictMacAttribution",
                          "Only clear a DATA record when the overheard transmitter MAC resolves to "
                          "the expected MPR (default lenient).",
                          BooleanValue(false),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_strictMacAttribution),
                          MakeBooleanChecker())
            .AddAttribute("MinForwardFailures",
                          "Consecutive observed forward-failures before mistrust (1 == paper-exact, "
                          "fragile against transient wireless loss).",
                          UintegerValue(3),
                          MakeUintegerAccessor(&OlsrTrustDefense::m_minForwardFailures),
                          MakeUintegerChecker<uint32_t>(1))
            // --- trust state / countermeasures (Formula 15) ---
            .AddAttribute("ResponseEnabled",
                          "If false, DETECTION-ONLY: detect+log but IsMalicious() stays false so the "
                          "topology is never perturbed (measure detection in isolation).",
                          BooleanValue(true),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_responseEnabled),
                          MakeBooleanChecker())
            .AddAttribute("MistrustPermanent",
                          "Exact mistrust is permanent; if false it is temporary (rehabilitatable).",
                          BooleanValue(false),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_mistrustPermanent),
                          MakeBooleanChecker())
            .AddAttribute("MistrustDuration",
                          "Rehabilitation window for temporary mistrust (MistrustPermanent=false).",
                          TimeValue(Seconds(60.0)),
                          MakeTimeAccessor(&OlsrTrustDefense::m_mistrustDuration),
                          MakeTimeChecker())
            // --- Section 5.1 extended cross-check ---
            .AddAttribute("EnableCrossCheck",
                          "Enable the Section 5.1 extended rule: a TC selector whose own HELLO "
                          "never declared the TC originator convicts the originator.",
                          BooleanValue(true),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_enableCrossCheck),
                          MakeBooleanChecker())
            .AddAttribute("HelloValidity",
                          "How long a witness's HELLO declaration stays usable as evidence "
                          "(paper Section 4 message validity time).",
                          TimeValue(Seconds(6.0)),
                          MakeTimeAccessor(&OlsrTrustDefense::m_helloValidity),
                          MakeTimeChecker())
            .AddAttribute("CrossCheckPersistence",
                          "How many times the same (accused, witness) contradiction must repeat "
                          "before mistrust (paper Section 5.1 'continues to receive').",
                          UintegerValue(2),
                          MakeUintegerAccessor(&OlsrTrustDefense::m_crossCheckPersistence),
                          MakeUintegerChecker<uint32_t>(1))
            .AddAttribute("ConsistencyGrace",
                          "Suppress the consistency rules for this long after the defense starts "
                          "(paper Section 5.1 'after an initialization process').",
                          TimeValue(Seconds(15.0)),
                          MakeTimeAccessor(&OlsrTrustDefense::m_consistencyGrace),
                          MakeTimeChecker())
            .AddAttribute("TcAwaitingPeriod",
                          "How long a selected MPR may go without originating a TC before "
                          "Formula 9a mistrusts it.",
                          TimeValue(Seconds(15.0)),
                          MakeTimeAccessor(&OlsrTrustDefense::m_tcAwaitingPeriod),
                          MakeTimeChecker())
            .AddAttribute("TopologyValidity",
                          "How long a TC-derived MPR-selector set stays usable as evidence "
                          "(Formula 12).",
                          TimeValue(Seconds(15.0)),
                          MakeTimeAccessor(&OlsrTrustDefense::m_topologyValidity),
                          MakeTimeChecker())
            .AddAttribute("EnableFormula8",
                          "Enable Formula 8 (contradictory copies of one TC from two relays).",
                          BooleanValue(true),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_enableFormula8),
                          MakeBooleanChecker())
            .AddAttribute("EnableFormula9a",
                          "Enable Formula 9a (selected MPR that originates no TC).",
                          BooleanValue(true),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_enableFormula9a),
                          MakeBooleanChecker())
            .AddAttribute("EnableFormula12",
                          "Enable Formula 12 (nested neighbourhoods sharing an MPR selector).",
                          BooleanValue(true),
                          MakeBooleanAccessor(&OlsrTrustDefense::m_enableFormula12),
                          MakeBooleanChecker())
            .AddAttribute("PersistenceWindow",
                          "How long a contradiction streak stays alive; a streak that stops "
                          "recurring for this long is treated as a resolved transient.",
                          TimeValue(Seconds(15.0)),
                          MakeTimeAccessor(&OlsrTrustDefense::m_persistenceWindow),
                          MakeTimeChecker());
    return tid;
}

OlsrTrustDefense::OlsrTrustDefense()
    : m_proto(nullptr),
      m_setupDone(false),
      m_proofCursor(0),
      m_declaredEverSent(false),
      m_relayHintActive(false),
      m_relayHintUid(0)
{
    // Initialise the attribute mirror from the canonical struct defaults; the
    // ns-3 attribute system overwrites these with the (matching) AddAttribute
    // defaults or any user override during ConstructSelf().
    OlsrTrustDefenseConfig d;
    m_forwardTimeout = d.forwardTimeout;
    m_checkInterval = d.checkInterval;
    m_monitorData = d.monitorData;
    m_monitorTc = d.monitorTc;
    m_monitorRelayedData = d.monitorRelayedData;
    m_strictMacAttribution = d.strictMacAttribution;
    m_minForwardFailures = d.minForwardFailures;
    m_responseEnabled = d.responseEnabled;
    m_mistrustPermanent = d.mistrustPermanent;
    m_mistrustDuration = d.mistrustDuration;
    m_enableCrossCheck = d.enableCrossCheck;
    m_helloValidity = d.helloValidity;
    m_crossCheckPersistence = d.crossCheckPersistence;
    m_consistencyGrace = d.consistencyGrace;
    m_persistenceWindow = d.persistenceWindow;
    m_tcAwaitingPeriod = d.tcAwaitingPeriod;
    m_topologyValidity = d.topologyValidity;
    m_enableFormula8 = d.enableFormula8;
    m_enableFormula9a = d.enableFormula9a;
    m_enableFormula12 = d.enableFormula12;
    m_enableForwardMonitor = d.enableForwardMonitor;
    m_enableConsistencyRules = d.enableConsistencyRules;
    m_enableProvableIdentity = d.enableProvableIdentity;
    m_enableAlertDistribution = d.enableAlertDistribution;
}

OlsrTrustDefense::~OlsrTrustDefense() = default;

OlsrTrustDefenseConfig
OlsrTrustDefense::BuildConfig() const
{
    OlsrTrustDefenseConfig c;
    c.enableForwardMonitor = m_enableForwardMonitor;
    c.enableConsistencyRules = m_enableConsistencyRules;
    c.enableProvableIdentity = m_enableProvableIdentity;
    c.enableAlertDistribution = m_enableAlertDistribution;
    c.forwardTimeout = m_forwardTimeout;
    c.checkInterval = m_checkInterval;
    c.monitorData = m_monitorData;
    c.monitorTc = m_monitorTc;
    c.monitorRelayedData = m_monitorRelayedData;
    c.strictMacAttribution = m_strictMacAttribution;
    c.minForwardFailures = m_minForwardFailures;
    c.responseEnabled = m_responseEnabled;
    c.mistrustPermanent = m_mistrustPermanent;
    c.mistrustDuration = m_mistrustDuration;
    c.enableCrossCheck = m_enableCrossCheck;
    c.helloValidity = m_helloValidity;
    c.crossCheckPersistence = m_crossCheckPersistence;
    c.consistencyGrace = m_consistencyGrace;
    c.persistenceWindow = m_persistenceWindow;
    c.tcAwaitingPeriod = m_tcAwaitingPeriod;
    c.topologyValidity = m_topologyValidity;
    c.enableFormula8 = m_enableFormula8;
    c.enableFormula9a = m_enableFormula9a;
    c.enableFormula12 = m_enableFormula12;
    return c;
}

void
OlsrTrustDefense::SetConfig(const OlsrTrustDefenseConfig& cfg)
{
    m_cfg = cfg;
    // keep the attribute mirror in sync so a later Setup() BuildConfig() agrees.
    m_enableForwardMonitor = cfg.enableForwardMonitor;
    m_enableConsistencyRules = cfg.enableConsistencyRules;
    m_enableProvableIdentity = cfg.enableProvableIdentity;
    m_enableAlertDistribution = cfg.enableAlertDistribution;
    m_forwardTimeout = cfg.forwardTimeout;
    m_checkInterval = cfg.checkInterval;
    m_monitorData = cfg.monitorData;
    m_monitorTc = cfg.monitorTc;
    m_monitorRelayedData = cfg.monitorRelayedData;
    m_strictMacAttribution = cfg.strictMacAttribution;
    m_minForwardFailures = cfg.minForwardFailures;
    m_responseEnabled = cfg.responseEnabled;
    m_mistrustPermanent = cfg.mistrustPermanent;
    m_mistrustDuration = cfg.mistrustDuration;
    m_enableCrossCheck = cfg.enableCrossCheck;
    m_helloValidity = cfg.helloValidity;
    m_crossCheckPersistence = cfg.crossCheckPersistence;
    m_consistencyGrace = cfg.consistencyGrace;
    m_persistenceWindow = cfg.persistenceWindow;
    m_tcAwaitingPeriod = cfg.tcAwaitingPeriod;
    m_topologyValidity = cfg.topologyValidity;
    m_enableFormula8 = cfg.enableFormula8;
    m_enableFormula9a = cfg.enableFormula9a;
    m_enableFormula12 = cfg.enableFormula12;
}

void
OlsrTrustDefense::Setup(RoutingProtocol* proto, Ipv4Address nodeAddress)
{
    m_proto = proto;
    m_self = nodeAddress;
    if (m_setupDone)
    {
        return; // ReactivateDefenseStrategy() may call Setup() again; keep accumulated state.
    }

    m_cfg = BuildConfig();
    NS_LOG_INFO("node " << m_self << " trust defense setup (forwardMonitor="
                        << m_cfg.enableForwardMonitor
                        << " consistency=" << m_cfg.enableConsistencyRules
                        << " provableIdentity=" << m_cfg.enableProvableIdentity
                        << " alert=" << m_cfg.enableAlertDistribution
                        << " response=" << m_cfg.responseEnabled << ")");

    m_trust = std::make_unique<OlsrTrustState>(m_cfg, m_self);
    m_identity = std::make_unique<OlsrProvableIdentity>(m_cfg);
    if (m_cfg.enableProvableIdentity)
    {
        m_identity->GenerateKey(m_self);
    }

    if (m_cfg.enableForwardMonitor)
    {
        m_forward = std::make_unique<OlsrForwardMonitor>(
            m_cfg, m_proto, m_self,
            [this](Ipv4Address mpr, ForwardFailureType t, uint32_t c, Time now) {
                OnForwardFailure(mpr, t, c, now);
            });
        m_forward->Start();
    }

    if (m_cfg.enableAlertDistribution)
    {
        // Created whenever distribution is on, so this node can RECEIVE alerts even
        // if its own consistency detection is disabled. Announcing still requires a
        // local consistency detection (which needs enableConsistencyRules).
        m_alert = std::make_unique<OlsrAlertDistributor>(
            m_self, [this](const ConsistencyProof& proof, Ipv4Address accuser, Time now) {
                OnAlertReceived(proof, accuser, now);
            });
        m_alert->Start();
    }

    if (m_cfg.enableConsistencyRules)
    {
        m_consistency = std::make_unique<OlsrConsistencyRules>(
            m_cfg, m_proto, m_self,
            [this](const std::set<Ipv4Address>& g, bool e, const std::string& f, const std::string& r,
                   const ConsistencyProof& proof, Time now) {
                OnConsistencyMistrust(g, e, f, r, proof, now);
            });
    }

    m_setupDone = true;
}

void
OlsrTrustDefense::DoDispose()
{
    if (m_forward)
    {
        m_forward->Stop();
    }
    if (m_alert)
    {
        m_alert->Stop(); // unregister from the process-wide bus (critical across runs).
    }
    m_forward.reset();
    m_consistency.reset();
    m_identity.reset();
    m_alert.reset();
    m_trust.reset();
    m_proto = nullptr;
    m_setupDone = false;

    // The identity store was just destroyed, so the neighbourhood declaration this node
    // published is gone with it. Forget having published it, otherwise the node would
    // never re-issue a proof and every peer's store would stay empty for good.
    m_lastDeclared.clear();
    m_declaredEverSent = false;
    m_proofCursor = 0;
    m_f14Streaks.clear();
}

bool
OlsrTrustDefense::IsMalicious(Ipv4Address addr)
{
    // RESPONSE side: only exact mistrust triggers a countermeasure, and only when
    // response is enabled (detection-only mode returns false here while still logging).
    return m_cfg.responseEnabled && m_trust && m_trust->IsExactMistrusted(addr);
}

std::set<Ipv4Address>
OlsrTrustDefense::GetBlacklist() const
{
    // DETECTION side: always reflects what was detected, regardless of response, so
    // detection performance can be measured independently of the countermeasure.
    return m_trust ? m_trust->GetMistrusted() : std::set<Ipv4Address>{};
}

std::set<Ipv4Address>
OlsrTrustDefense::GetPartialMistrusted() const
{
    return m_trust ? m_trust->GetPartialMistrusted() : std::set<Ipv4Address>{};
}

void
OlsrTrustDefense::OnRecvProof(const MessageHeader::Proof& proof)
{
    // Formula 13 (identity binding + usurpation) and the signature check both live in
    // AcceptProof; a proof that fails either is simply not stored, so Formula 14 can
    // never rely on unauthenticated data.
    if (m_identity && m_identity->Enabled())
    {
        m_identity->AcceptProof(proof, Simulator::Now());
    }
}

void
OlsrTrustDefense::OnRecvHello(Ipv4Address,
                              Ptr<const Packet>,
                              const MessageHeader& msg,
                              const MessageHeader::Hello& hello)
{
    const Ipv4Address b = msg.GetOriginatorAddress();
    const Time now = Simulator::Now();

    if (m_consistency)
    {
        m_consistency->OnRecvHello(b, msg, hello, now);
    }

    // ---- Formula (14): every symmetric link B claims must be PROVEN by A's own ----
    //   signed HELLO naming B. An unproven link is simply not accepted into the
    //   trusted 2-hop neighbourhood; a CONTRADICTED one convicts B.
    if (!m_identity || !m_identity->Enabled() || b == m_self)
    {
        return;
    }
    for (const auto& lm : hello.linkMessages)
    {
        const uint8_t linkType = lm.linkCode & 0x03;
        const uint8_t neighType = (lm.linkCode >> 2) & 0x03;
        if (!(linkType == 2 || neighType == 1 || neighType == 2))
        {
            continue;
        }
        for (const auto& a : lm.neighborInterfaceAddresses)
        {
            if (a == m_self || a == b)
            {
                continue;
            }
            bool known = false;
            if (m_identity->ProveNeighborhood(b, a, now, known) || !known)
            {
                continue; // proven, or we hold no valid declaration to judge against.
            }
            // Section 5.1: a's declaration and b's claim are refreshed on different
            // timers, so a single mismatch is ordinary churn. Only a claim that KEEPS
            // going unproven convicts.
            auto& st = m_f14Streaks[std::make_pair(b, a)];
            if (st.first > 0 && (now - st.second) > m_cfg.persistenceWindow)
            {
                st.first = 0;
            }
            ++st.first;
            st.second = now;
            if (st.first < m_cfg.crossCheckPersistence)
            {
                continue;
            }
            // a's authenticated declaration keeps not naming b: the link is a lie.
            if (m_trust)
            {
                m_trust->MistrustExact(b, "14",
                                       "claimed a symmetric link with a node whose own signed "
                                       "declaration does not name it (no proof of neighbourhood)",
                                       now);
            }
            return;
        }
    }
}

void
OlsrTrustDefense::OnRecvTc(Ipv4Address senderIfaceAddr,
                           Ptr<const Packet>,
                           const MessageHeader& msg,
                           const MessageHeader::Tc& tc)
{
    if (m_consistency)
    {
        // Formula 8 needs the RELAY this copy came from (not the originator) and the
        // message sequence number, so two contradictory copies of one TC can be paired.
        const Ipv4Address relay =
            m_proto ? m_proto->GetMainAddress(senderIfaceAddr) : senderIfaceAddr;
        m_consistency->OnRecvTc(msg.GetOriginatorAddress(), relay, msg, tc, Simulator::Now());
    }
}

void
OlsrTrustDefense::OnTcGenerated(const MessageHeader::Tc&)
{
    if (m_forward)
    {
        m_forward->OnTcGenerated(Simulator::Now());
    }
}

void
OlsrTrustDefense::OnHelloGenerated(const MessageHeader::Hello& hello)
{
    // Section 6: publish the neighbourhood we just declared, so a neighbour that
    // claims a link with us can be checked against our OWN signed HELLO (Formula 14).
    if (!m_identity || !m_identity->Enabled())
    {
        return;
    }
    if (!m_proto)
    {
        return;
    }
    // A std::set gives the canonical form directly: sorted, no duplicates. The same
    // sequence is what gets signed and what the change detection compares, so there is
    // only ever one notion of "the declaration".
    std::set<Ipv4Address> symSet;
    for (const auto& lm : hello.linkMessages)
    {
        const uint8_t linkType = lm.linkCode & 0x03;
        const uint8_t neighType = (lm.linkCode >> 2) & 0x03;
        // SYM_LINK == 2, SYM_NEIGH == 1, MPR_NEIGH == 2 (RFC 3626 link-code layout).
        if (linkType == 2 || neighType == 1 || neighType == 2)
        {
            symSet.insert(lm.neighborInterfaceAddresses.begin(),
                          lm.neighborInterfaceAddresses.end());
        }
    }
    const std::vector<Ipv4Address> declared = OlsrProvableIdentity::Canonicalise(symSet);

    // Section 6.2: the proof is sent ONCE per change of the symmetric neighbourhood,
    // not on every HELLO. In a settled network that means nothing is sent at all.
    if (m_declaredEverSent && declared == m_lastDeclared)
    {
        return;
    }
    m_lastDeclared = declared;
    m_declaredEverSent = true;

    // Our own signed declaration: "HELLOA + signHelloA + KPubA".
    MessageHeader::Proof mine;
    mine.originator = m_self;
    mine.declared = declared;
    mine.pubKey = m_identity->PublicKey();
    mine.signature = m_identity->Sign(OlsrProvableIdentity::Digest(m_self, declared));
    m_proto->SendProof(mine);

    // ProofB proper: "to prove the validity of the OTHER symmetrical links to the new
    // neighbor" -- relay the declarations of the neighbours we claim, so anyone hearing
    // our claim can check it. Only on a change, for the same reason as above.
    for (const auto& a : m_lastDeclared)
    {
        if (a == m_self)
        {
            continue;
        }
        if (const MessageHeader::Proof* q = m_identity->HeldProof(a))
        {
            m_proto->SendProof(*q);
        }
    }
}

void
OlsrTrustDefense::OnDataPacketReceived(Ptr<const Packet> packet,
                                       Ipv4Address,
                                       Ipv4Address,
                                       Ipv4Address)
{
    // RouteInput relay path: the next OnDataPacketForwarded for this UID is a RELAY,
    // not an origination. Tag it so the forward monitor honours the DATAx scope.
    m_relayHintActive = true;
    m_relayHintUid = packet->GetUid();
}

void
OlsrTrustDefense::OnDataPacketForwarded(Ptr<const Packet> packet,
                                        Ipv4Address nextHop,
                                        Ipv4Address finalDest)
{
    bool originatedHere = true;
    if (m_relayHintActive && m_relayHintUid == packet->GetUid())
    {
        originatedHere = false;
    }
    m_relayHintActive = false;
    if (m_forward)
    {
        m_forward->OnDataForward(packet, nextHop, finalDest, originatedHere, Simulator::Now());
    }
}

void
OlsrTrustDefense::OnDataPacketDropped(Ptr<const Packet> packet,
                                      Ipv4Address,
                                      Ipv4Address,
                                      DropReason)
{
    m_relayHintActive = false;
    if (m_forward)
    {
        m_forward->OnLocalDrop(packet); // we dropped it ourselves: do not blame an MPR.
    }
}

void
OlsrTrustDefense::OnNeighborForwardedPacket(Mac48Address transmitter,
                                            Mac48Address receiver,
                                            Ptr<const Packet> packet)
{
    if (m_forward)
    {
        m_forward->OnOverheard(transmitter, receiver, packet, Simulator::Now());
    }
}

void
OlsrTrustDefense::OnForwardFailure(Ipv4Address mpr, ForwardFailureType type, uint32_t, Time now)
{
    // Internal forward-failure (the paper's "x ->8 TC/DATA" event) -> Formula (10).
    const std::string formula = (type == ForwardFailureType::Data) ? "10-DATA" : "10-TC";
    const std::string reason = (type == ForwardFailureType::Data)
                                   ? "selected MPR did not forward DATA I originated within the awaiting period"
                                   : "selected MPR did not re-flood a TC I originated within the awaiting period";
    if (m_trust)
    {
        m_trust->MistrustExact(mpr, formula, reason, now);
    }
}

bool
OlsrTrustDefense::IsAnnounceable(const std::string& formula)
{
    // Only consistency detections with a third-party-verifiable proof (paper §7).
    // Paper Section 7: an alert "must provide reliable proofs of the attack that cannot
    // be falsified". Formula 7 does NOT qualify -- its evidence is the accuser's OWN MPR
    // set, self-asserted and uncheckable by anyone else, which is precisely why the code
    // already keeps Formula 9b local. Announcing it turns one node's transient false
    // positive into a network-wide conviction.
    return formula == "6" || formula == "8" || formula == "12" || formula == "5.1e";
}

void
OlsrTrustDefense::OnConsistencyMistrust(const std::set<Ipv4Address>& group,
                                        bool exact,
                                        const std::string& formula,
                                        const std::string& reason,
                                        const ConsistencyProof& proof,
                                        Time now)
{
    if (!m_trust)
    {
        return;
    }
    if (exact && !group.empty())
    {
        m_trust->MistrustExact(*group.begin(), formula, reason, now);
        // §7: share the falsifiable proof so distant nodes that could not detect
        // locally also mistrust the attacker. Black-hole (Formula 10) is never
        // announced (no provable artifact); 9b is local-only (not third-party verifiable).
        // Section 7: the alert IS the retransmission of the control messages that
        // revealed the inconsistency. Every receiver re-runs its own reasoning on them;
        // no verdict is transferred, and nothing but real OLSR broadcast carries it.
        if (m_alert && m_proto && IsAnnounceable(formula) && !proof.evidence.empty() &&
            m_alert->ShouldAnnounce(proof, now))
        {
            m_proto->BroadcastTrustAlert(proof.evidence);
        }
    }
    else
    {
        m_trust->MistrustPartial(group, formula, reason, now);
    }
}

void
OlsrTrustDefense::OnAlertReceived(const ConsistencyProof& proof, Ipv4Address accuser, Time now)
{
    if (!m_trust)
    {
        return;
    }
    // Section 7: "if y has already detected x as malicious node, then it should not
    // broadcast the alert generated by x" -- a node we mistrust cannot convict anyone.
    if (m_trust->IsExactMistrusted(accuser))
    {
        NS_LOG_LOGIC("node " << m_self << " ignores alert from mistrusted accuser " << accuser);
        return;
    }
    // Section 7: "compare the information provided in the alert with the local vision ...
    // to detect false alerts". Absence of local evidence is not contradiction, but an
    // outright conflict with our own valid observations means the alert is false.
    if (m_consistency && m_consistency->ContradictsLocalVision(proof, now))
    {
        NS_LOG_INFO("[" << now.As(Time::S) << "] node " << m_self
                        << " REJECTS false alert about " << proof.accused << " from " << accuser
                        << " (contradicted by local vision)");
        return;
    }
    std::ostringstream r;
    r << "trust alert (Formula " << proof.formula << ") from " << accuser;
    m_trust->MistrustExact(proof.accused, "ALERT-" + proof.formula, r.str(), now);
}

void
OlsrTrustDefense::PeriodicCheck()
{
    Time now = Simulator::Now();
    if (m_trust)
    {
        m_trust->Expire(now);
    }
    if (m_consistency)
    {
        m_consistency->PeriodicCheck(now);
    }
}

} // namespace olsr
} // namespace ns3
