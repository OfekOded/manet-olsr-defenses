/*
 * Trust-based OLSR defense (Adnane et al., Computer Communications 36, 2013)
 *
 * olsr-provable-identity.h -- OPTIONAL SOLSR-style provable identity
 * (paper Section 6, Formula 13). OFF by default (config.enableProvableIdentity)
 * so black-hole experiments run without any crypto overhead.
 *
 * This is a deliberate STUB: it declares the TabIP / TabH tables and the
 * verification entry points described in the paper, but performs no real
 * signing/verification yet. Per the task it must NOT change the OLSR message
 * structure or routing table; a real implementation would attach the signature
 * and public key as a separate packet (paper Fig. 4) rather than modifying the
 * existing message formats.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef OLSR_PROVABLE_IDENTITY_H
#define OLSR_PROVABLE_IDENTITY_H

#include "olsr-trust-config.h"

#include "ns3/ipv4-address.h"

#include <cstdint>
#include <map>

namespace ns3
{
namespace olsr
{

/**
 * \ingroup olsr
 * \brief SOLSR provable-identity binding (stub).
 *
 * Formula (13): KPub_A == TabIP_n[@IP_A]  and  @IP_A == TabH_n[H(KPub_A)]
 *               <=> IdP_A == H(KPub_A)
 */
class OlsrProvableIdentity
{
  public:
    explicit OlsrProvableIdentity(const OlsrTrustDefenseConfig& cfg)
        : m_cfg(cfg)
    {
    }

    bool Enabled() const { return m_cfg.enableProvableIdentity; }

    /**
     * \brief Verify the provable identity of a sender (paper Formula 13).
     * STUB: always accepts when disabled (default). When enabled but unimplemented,
     * also accepts -- wire real signature verification here.
     * \return true if the identity is consistent (or checking is disabled).
     */
    bool VerifyIdentity(Ipv4Address /*addr*/, uint64_t /*pubKeyHash*/) const { return true; }

  private:
    OlsrTrustDefenseConfig m_cfg;
    std::map<Ipv4Address, uint64_t> m_tabIp; //!< TabIP: @IP -> H(KPub)  (Table 1).
    std::map<uint64_t, Ipv4Address> m_tabH;  //!< TabH:  H(KPub) -> @IP  (Table 2).
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_PROVABLE_IDENTITY_H */
