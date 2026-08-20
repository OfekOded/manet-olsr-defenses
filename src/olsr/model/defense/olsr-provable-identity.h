/*
 * Trust-based OLSR defense (Adnane et al., Computer Communications 36, 2013)
 *
 * olsr-provable-identity.h -- Section 6: provable identity (Formula 13) and the
 * proof of neighbourhood (Formula 14).
 *
 * Formula (13):  KPubA == TabIPn(@IPA)  and  @IPA == TabHn(H(KPubA))
 *                <=> IdPA = H(KPubA)
 * Formula (14):  z <- HELLOb, [A in NSb u MPRSb], z <- Proofb, [B not in NSa u MPRSa]
 *                => z !trusts(B)
 *
 * Everything here is carried by a real OLSR message (MessageHeader::PROOF_MESSAGE,
 * paper Fig. 5) and authenticated by a real public-key signature: signing needs the
 * private key, verification needs only the public key that travels in the message.
 * The RSA modulus is small -- these are simulation-grade keys, not secure ones -- but
 * the asymmetry, and therefore the protocol behaviour, is genuine: no node can
 * fabricate another node's declaration.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef OLSR_PROVABLE_IDENTITY_H
#define OLSR_PROVABLE_IDENTITY_H

#include "olsr-trust-config.h"

#include "../olsr-header.h"

#include "ns3/ipv4-address.h"
#include "ns3/nstime.h"

#include <cstdint>
#include <map>
#include <set>
#include <vector>

namespace ns3
{
namespace olsr
{

/**
 * \ingroup olsr
 * \brief Per-node provable identity: the TabIP / TabH pair of Formula 13, the
 * signing key, and the authenticated declarations gathered from received proofs.
 */
class OlsrProvableIdentity
{
  public:
    explicit OlsrProvableIdentity(const OlsrTrustDefenseConfig& cfg)
        : m_cfg(cfg),
          m_modulus(0),
          m_privateExp(0)
    {
    }

    bool Enabled() const { return m_cfg.enableProvableIdentity; }

    /// Derive this node's keypair. Deterministic, so a cold start keeps the identity.
    void GenerateKey(Ipv4Address self);

    uint64_t PublicKey() const { return m_modulus; }

    /// H(KPub): the provable identity IdP.
    static uint64_t Hash(uint64_t kpub);

    /// Digest of a declaration, the value that actually gets signed. Defined over the
    /// CANONICAL form only (see IsCanonical).
    static uint64_t Digest(Ipv4Address originator, const std::vector<Ipv4Address>& declared);

    /// A declaration is canonical when it is strictly increasing, i.e. sorted with no
    /// duplicates. Enforcing it on receipt denies a relay the freedom to reorder or
    /// repeat entries, which is what makes the signature bind the exact set.
    static bool IsCanonical(const std::vector<Ipv4Address>& declared);

    /// Put a declaration into canonical form.
    static std::vector<Ipv4Address> Canonicalise(const std::set<Ipv4Address>& declared);

    /// Sign a digest with THIS node's private key.
    uint64_t Sign(uint64_t digest) const;

    /// Verify a signature against a public key (public exponent is fixed at 3).
    static bool Verify(uint64_t digest, uint64_t signature, uint64_t pubKey);

    /**
     * \brief Formula 13 + signature check on a received proof. Binds the originator's
     * address to its key and rejects a second node claiming the same address.
     * \return false if the proof is forged or the address is usurped.
     */
    bool AcceptProof(const MessageHeader::Proof& proof, Time now);

    /**
     * \brief Formula 14. \p b claims \p a as a symmetric neighbour.
     * \return true when a's AUTHENTICATED declaration names b.
     * \param known false when no valid proof for a has been received, in which case the
     *        link is merely unproven rather than contradicted.
     */
    bool ProveNeighborhood(Ipv4Address b, Ipv4Address a, Time now, bool& known) const;

    /// Proof of \p a we hold and can relay onwards (ProofB), or nullptr.
    const MessageHeader::Proof* HeldProof(Ipv4Address a) const;

    /// Every originator we hold a proof for, so they can be relayed in turn.
    std::vector<Ipv4Address> ProvenNodes() const;

  private:
    OlsrTrustDefenseConfig m_cfg;
    uint64_t m_modulus;    //!< n, published as the public key.
    uint64_t m_privateExp; //!< d, never leaves the node.

    std::map<Ipv4Address, uint64_t> m_tabIp; //!< TabIP: @IP -> KPub   (Table 1).
    std::map<uint64_t, Ipv4Address> m_tabH;  //!< TabH:  H(KPub) -> @IP (Table 2).

    /// One authenticated declaration and when it arrived (Section 4 validity).
    struct Held
    {
        MessageHeader::Proof proof;
        Time received;
    };

    /// Authenticated declarations, keyed by originator: the proofs we may rely on.
    std::map<Ipv4Address, Held> m_proofs;
};

} // namespace olsr
} // namespace ns3

#endif /* OLSR_PROVABLE_IDENTITY_H */
