/*
 * Trust-based OLSR defense (Adnane et al., Computer Communications 36, 2013)
 * olsr-provable-identity.cc -- Section 6, Formulas (13) and (14).
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "olsr-provable-identity.h"

#include "ns3/log.h"

#include <algorithm>

namespace ns3
{
namespace olsr
{

NS_LOG_COMPONENT_DEFINE("OlsrProvableIdentity");

namespace
{
/// Fixed public exponent, as in textbook RSA.
constexpr uint64_t PUB_EXP = 3;

/// (base^exp) mod m, with 128-bit intermediates so the products cannot wrap.
uint64_t
PowMod(uint64_t base, uint64_t exp, uint64_t m)
{
    unsigned __int128 result = 1;
    unsigned __int128 b = base % m;
    while (exp > 0)
    {
        if (exp & 1u)
        {
            result = (result * b) % m;
        }
        b = (b * b) % m;
        exp >>= 1;
    }
    return static_cast<uint64_t>(result);
}

/// Primes for the simulation-grade RSA keys. Every entry satisfies p == 2 (mod 3),
/// so gcd(e, p-1) == 1 for the fixed public exponent e = 3 and the private exponent
/// really is the modular inverse. A table containing primes with p == 1 (mod 3) would
/// silently produce keys whose signatures never verify.
const uint32_t PRIMES[] = {
    10007, 10037, 10061, 10067, 10079, 10091, 10103, 10133, 10139, 10151,
    10163, 10169, 10181, 10193, 10211, 10223, 10247, 10253, 10259, 10271,
    10289, 10301, 10313, 10331, 10337, 10343, 10391, 10427, 10433, 10457,
    10463, 10487, 10499, 10529, 10559, 10589, 10601, 10607, 10613, 10631,
    10667, 10691, 10709, 10733, 10739, 10781, 10799, 10847, 10853, 10859,
    10883, 10889, 10937, 10949, 10973, 10979, 11003, 11027, 11057, 11069,
    11087, 11093, 11117, 11159, 11171, 11177, 11213, 11243, 11261, 11273,
    11279, 11321, 11351, 11369, 11393, 11399, 11411, 11423, 11447, 11471,
    11483, 11489, 11519, 11549, 11579, 11597, 11621, 11633, 11657, 11681,
    11699, 11717, 11777, 11783, 11789, 11801, 11807, 11813, 11831, 11867,
    11897, 11903, 11909, 11927, 11933, 11939, 11969, 11981, 11987, 12011,
    12041, 12071, 12101, 12107, 12113, 12119, 12143, 12149, 12161, 12197,
};
constexpr uint32_t NPRIMES = sizeof(PRIMES) / sizeof(PRIMES[0]);

/// Modular inverse of a modulo m (extended Euclid), for deriving d from e.
uint64_t
InvMod(uint64_t a, uint64_t m)
{
    int64_t t = 0, newt = 1;
    int64_t r = static_cast<int64_t>(m), newr = static_cast<int64_t>(a);
    while (newr != 0)
    {
        const int64_t q = r / newr;
        int64_t tmp = t - q * newt;
        t = newt;
        newt = tmp;
        tmp = r - q * newr;
        r = newr;
        newr = tmp;
    }
    if (t < 0)
    {
        t += static_cast<int64_t>(m);
    }
    return static_cast<uint64_t>(t);
}
} // namespace

void
OlsrProvableIdentity::GenerateKey(Ipv4Address self)
{
    // Deterministic per address, and distinct per node: a cold start keeps the same
    // identity, which is what makes a mistrust survive one (paper Section 7).
    const uint32_t h = self.Get();
    uint32_t ip = h % NPRIMES;
    uint32_t iq = (h / NPRIMES + 7) % NPRIMES;
    if (iq == ip)
    {
        iq = (iq + 1) % NPRIMES;
    }
    const uint64_t p = PRIMES[ip];
    const uint64_t q = PRIMES[iq];
    m_modulus = p * q;
    const uint64_t phi = (p - 1) * (q - 1);
    m_privateExp = InvMod(PUB_EXP, phi);

    // The table is chosen so this always holds; assert it rather than trust it, because
    // a key whose exponent is not the true inverse fails silently -- every signature it
    // produces is rejected and the node simply stops being able to prove anything.
    NS_ASSERT_MSG((static_cast<unsigned __int128>(m_privateExp) * PUB_EXP) % phi == 1,
                  "provable-identity key generation produced a non-invertible exponent");
}

uint64_t
OlsrProvableIdentity::Hash(uint64_t kpub)
{
    uint64_t z = kpub + 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

bool
OlsrProvableIdentity::IsCanonical(const std::vector<Ipv4Address>& declared)
{
    for (std::size_t i = 1; i < declared.size(); ++i)
    {
        if (!(declared[i - 1] < declared[i]))
        {
            return false; // unsorted, or a duplicate.
        }
    }
    return true;
}

std::vector<Ipv4Address>
OlsrProvableIdentity::Canonicalise(const std::set<Ipv4Address>& declared)
{
    return std::vector<Ipv4Address>(declared.begin(), declared.end());
}

uint64_t
OlsrProvableIdentity::Digest(Ipv4Address originator, const std::vector<Ipv4Address>& declared)
{
    // Position-dependent fold over the canonical sequence, plus the length.
    //
    // An order-independent combiner (XOR) would be forgeable: appending the SAME address
    // twice cancels, leaving the digest -- and therefore the signature -- valid while
    // adding that address to the declaration. Folding sequentially and mixing in the
    // count makes any insertion, deletion or reordering change the digest.
    uint64_t acc = Hash(originator.Get());
    for (const auto& a : declared)
    {
        acc = Hash((acc * 0x100000001B3ULL) ^ Hash(a.Get()));
    }
    return Hash(acc ^ (static_cast<uint64_t>(declared.size()) << 32));
}

uint64_t
OlsrProvableIdentity::Sign(uint64_t digest) const
{
    if (m_modulus == 0)
    {
        return 0;
    }
    return PowMod(digest % m_modulus, m_privateExp, m_modulus);
}

bool
OlsrProvableIdentity::Verify(uint64_t digest, uint64_t signature, uint64_t pubKey)
{
    if (pubKey == 0)
    {
        return false;
    }
    return PowMod(signature, PUB_EXP, pubKey) == (digest % pubKey);
}

bool
OlsrProvableIdentity::AcceptProof(const MessageHeader::Proof& proof, Time now)
{
    if (!Enabled())
    {
        return true;
    }
    // The declaration must arrive in canonical form; anything else is a relay having
    // reordered or padded it, and is rejected before the signature is even considered.
    if (!IsCanonical(proof.declared))
    {
        NS_LOG_LOGIC("rejected proof of " << proof.originator << ": non-canonical declaration");
        return false;
    }
    // The signature must check out under the key that travels with it. A relay cannot
    // alter the declaration, and no node can fabricate one for somebody else.
    const uint64_t digest = Digest(proof.originator, proof.declared);
    if (!Verify(digest, proof.signature, proof.pubKey))
    {
        NS_LOG_LOGIC("rejected proof of " << proof.originator << ": bad signature");
        return false;
    }

    // Formula 13, TabIP: is this address already bound to a DIFFERENT key?
    auto ip = m_tabIp.find(proof.originator);
    if (ip != m_tabIp.end() && ip->second != proof.pubKey)
    {
        NS_LOG_INFO("identity usurpation on " << proof.originator
                                              << ": key differs from the bound one");
        return false;
    }

    // Formula 13, TabH: same identity at a new address -> rebind rather than reject.
    const uint64_t idp = Hash(proof.pubKey);
    auto h = m_tabH.find(idp);
    if (h != m_tabH.end() && h->second != proof.originator)
    {
        m_tabIp.erase(h->second);
        m_proofs.erase(h->second);
        h->second = proof.originator;
    }
    else if (h == m_tabH.end())
    {
        m_tabH[idp] = proof.originator;
    }
    m_tabIp[proof.originator] = proof.pubKey;
    m_proofs[proof.originator] = Held{proof, now};
    return true;
}

bool
OlsrProvableIdentity::ProveNeighborhood(Ipv4Address b,
                                        Ipv4Address a,
                                        Time now,
                                        bool& known) const
{
    known = false;
    if (!Enabled())
    {
        return true;
    }
    auto it = m_proofs.find(a);
    if (it == m_proofs.end())
    {
        return false; // no authenticated declaration for a: unproven, not contradicted.
    }
    // Deliberately no time expiry. Section 6.2 issues a proof once per change of the
    // neighbourhood, so a proof stays the node's current statement until it issues a
    // newer one (AcceptProof overwrites the entry). Expiring it on a timer would make
    // every declaration unusable in a settled network, which is exactly when the
    // neighbourhood claims being checked are most stable.
    (void)now;
    known = true;
    for (const auto& n : it->second.proof.declared)
    {
        if (n == b)
        {
            return true;
        }
    }
    return false;
}

const MessageHeader::Proof*
OlsrProvableIdentity::HeldProof(Ipv4Address a) const
{
    auto it = m_proofs.find(a);
    return (it == m_proofs.end()) ? nullptr : &it->second.proof;
}

std::vector<Ipv4Address>
OlsrProvableIdentity::ProvenNodes() const
{
    std::vector<Ipv4Address> out;
    out.reserve(m_proofs.size());
    for (const auto& kv : m_proofs)
    {
        out.push_back(kv.first);
    }
    return out;
}

} // namespace olsr
} // namespace ns3
