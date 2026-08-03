#include "bbcore/bbcore.h"

#include "api/IdentityHandle.h"
#include "crypto/Aead.h"
#include "crypto/Shake.h"

#include <openssl/rand.h>

#include <array>
#include <cstring>
#include <limits>

namespace {

constexpr std::uint8_t kMagic[] = {'b', 'b', 'k', '1', 's', 't'};
constexpr std::uint8_t kVersion = 1;
constexpr std::size_t  kIdentityOffset = 8;
constexpr std::size_t  kNonceOffset = kIdentityOffset + BB_ID_LEN;
constexpr std::size_t  kHeaderLen = kNonceOffset + BB_NONCE_LEN;
constexpr char         kKeyLabel[] = "bbk/1/state-key";

bool DeriveStateKey(const bb::Identity& identity, bb::AeadKey& out)
{
    bb::Shake256 shake;
    shake.Update(identity.KeyInstance().data(), identity.KeyInstance().size());
    shake.Update(kKeyLabel, sizeof kKeyLabel - 1);
    return shake.Finish(out.data(), out.size());
}

const bb::Identity* PrivateIdentity(const bb_identity* identity)
{
    if (identity == nullptr || !identity->impl.IsValid()
     || !identity->impl.HasPrivateKey()) {
        return nullptr;
    }
    return &identity->impl;
}

}  // namespace

BB_API bb_status BB_CALL bb_identity_state_seal(
    const bb_identity* identity, const uint8_t* plain, size_t plain_len,
    uint8_t* out, size_t cap, size_t* out_len)
{
    const bb::Identity* impl = PrivateIdentity(identity);
    if (impl == nullptr || (plain == nullptr && plain_len != 0)) {
        return BB_ERR_INVALID_ARG;
    }
    if (plain_len > std::numeric_limits<std::size_t>::max() - kHeaderLen - BB_TAG_LEN) {
        return BB_ERR_INVALID_ARG;
    }
    const std::size_t needed = kHeaderLen + plain_len + BB_TAG_LEN;
    if (out_len != nullptr) *out_len = needed;
    if ((out == nullptr && needed != 0) || cap < needed) return BB_ERR_BUFFER_TOO_SMALL;

    std::memcpy(out, kMagic, sizeof kMagic);
    out[6] = kVersion;
    out[7] = 0;
    std::memcpy(out + kIdentityOffset, impl->Id().data(), BB_ID_LEN);
    if (RAND_bytes(out + kNonceOffset, BB_NONCE_LEN) != 1) return BB_ERR_INTERNAL;

    bb::AeadKey key{};
    bb::AeadNonce nonce{};
    std::memcpy(nonce.data(), out + kNonceOffset, nonce.size());
    if (!DeriveStateKey(*impl, key)) return BB_ERR_INTERNAL;

    std::size_t produced = 0;
    const bool ok = bb::AeadSeal(key, nonce, out, kHeaderLen,
                                 plain, plain_len, out + kHeaderLen,
                                 cap - kHeaderLen, &produced)
                 && produced == plain_len + BB_TAG_LEN;
    bb_secure_zero(key.data(), key.size());
    bb_secure_zero(nonce.data(), nonce.size());
    if (!ok) {
        bb_secure_zero(out, needed);
        return BB_ERR_INTERNAL;
    }
    return BB_OK;
}

BB_API bb_status BB_CALL bb_identity_state_open(
    const bb_identity* identity, const uint8_t* sealed, size_t sealed_len,
    uint8_t* out, size_t cap, size_t* out_len)
{
    const bb::Identity* impl = PrivateIdentity(identity);
    if (impl == nullptr || sealed == nullptr || sealed_len < kHeaderLen + BB_TAG_LEN) {
        return BB_ERR_INVALID_ARG;
    }
    const std::size_t needed = sealed_len - kHeaderLen - BB_TAG_LEN;
    if (out_len != nullptr) *out_len = needed;
    if (out == nullptr || cap < needed) return BB_ERR_BUFFER_TOO_SMALL;

    if (std::memcmp(sealed, kMagic, sizeof kMagic) != 0
     || sealed[6] != kVersion || sealed[7] != 0
     || std::memcmp(sealed + kIdentityOffset, impl->Id().data(), BB_ID_LEN) != 0) {
        return BB_ERR_DECRYPT_FAILED;
    }

    bb::AeadKey key{};
    bb::AeadNonce nonce{};
    std::memcpy(nonce.data(), sealed + kNonceOffset, nonce.size());
    if (!DeriveStateKey(*impl, key)) return BB_ERR_INTERNAL;

    std::size_t produced = 0;
    const bool ok = bb::AeadOpen(key, nonce, sealed, kHeaderLen,
                                 sealed + kHeaderLen, sealed_len - kHeaderLen,
                                 out, cap, &produced)
                 && produced == needed;
    bb_secure_zero(key.data(), key.size());
    bb_secure_zero(nonce.data(), nonce.size());
    if (!ok) {
        if (out != nullptr && cap != 0) bb_secure_zero(out, cap);
        return BB_ERR_DECRYPT_FAILED;
    }
    return BB_OK;
}
