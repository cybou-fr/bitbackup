#include "core/ShardCodec.h"

#include "crypto/Aead.h"

#include <limits>
#include <string_view>

namespace bb {
namespace {

constexpr std::string_view kAadLabel = "bbk/1/shard-aad";

std::vector<std::uint8_t> BuildAad(const Hash256& identity_id,
                                   const Hash256& file_id,
                                   std::uint32_t stripe,
                                   std::uint16_t position,
                                   std::uint32_t plain_len)
{
    std::vector<std::uint8_t> aad;
    aad.reserve(kAadLabel.size() + identity_id.size() + file_id.size() + 4 + 2 + 4);
    aad.insert(aad.end(), kAadLabel.begin(), kAadLabel.end());
    aad.insert(aad.end(), identity_id.begin(), identity_id.end());
    aad.insert(aad.end(), file_id.begin(), file_id.end());
    aad.push_back(static_cast<std::uint8_t>(stripe >> 24));
    aad.push_back(static_cast<std::uint8_t>(stripe >> 16));
    aad.push_back(static_cast<std::uint8_t>(stripe >> 8));
    aad.push_back(static_cast<std::uint8_t>(stripe));
    aad.push_back(static_cast<std::uint8_t>(position >> 8));
    aad.push_back(static_cast<std::uint8_t>(position));
    aad.push_back(static_cast<std::uint8_t>(plain_len >> 24));
    aad.push_back(static_cast<std::uint8_t>(plain_len >> 16));
    aad.push_back(static_cast<std::uint8_t>(plain_len >> 8));
    aad.push_back(static_cast<std::uint8_t>(plain_len));
    return aad;
}

}  // namespace

bb_status ShardSeal(const FileKey& k_file,
                    const Hash256& identity_id,
                    const Hash256& file_id,
                    std::uint32_t stripe,
                    std::uint16_t position,
                    const std::uint8_t* plain,
                    std::size_t plain_len,
                    std::vector<std::uint8_t>& out_core)
{
    out_core.clear();
    if ((plain == nullptr && plain_len != 0)
     || plain_len > std::numeric_limits<std::uint32_t>::max()) return BB_ERR_INVALID_ARG;

    AeadKey key{};
    AeadNonce nonce{};
    if (!DeriveShardKey(k_file, stripe, position, key, nonce)) return BB_ERR_INTERNAL;
    const std::vector<std::uint8_t> aad = BuildAad(
        identity_id, file_id, stripe, position, static_cast<std::uint32_t>(plain_len));
    out_core.resize(AeadSealedLen(plain_len));
    std::size_t produced = 0;
    const bool ok = AeadSeal(key, nonce, aad.data(), aad.size(), plain, plain_len,
                             out_core.data(), out_core.size(), &produced)
                 && produced == out_core.size();
    bb_secure_zero(key.data(), key.size());
    bb_secure_zero(nonce.data(), nonce.size());
    if (!ok) {
        if (!out_core.empty()) bb_secure_zero(out_core.data(), out_core.size());
        out_core.clear();
        return BB_ERR_INTERNAL;
    }
    return BB_OK;
}

bb_status ShardOpen(const FileKey& k_file,
                    const Hash256& identity_id,
                    const Hash256& file_id,
                    std::uint32_t stripe,
                    std::uint16_t position,
                    const std::uint8_t* core,
                    std::size_t core_len,
                    std::vector<std::uint8_t>& out_plain)
{
    out_plain.clear();
    if (core == nullptr || core_len < kAeadTagLen
     || core_len - kAeadTagLen > std::numeric_limits<std::uint32_t>::max()) {
        return BB_ERR_INVALID_ARG;
    }
    const std::size_t plain_len = core_len - kAeadTagLen;
    AeadKey key{};
    AeadNonce nonce{};
    if (!DeriveShardKey(k_file, stripe, position, key, nonce)) return BB_ERR_INTERNAL;
    const std::vector<std::uint8_t> aad = BuildAad(
        identity_id, file_id, stripe, position, static_cast<std::uint32_t>(plain_len));
    out_plain.resize(plain_len);
    std::uint8_t empty = 0;
    std::uint8_t* target = plain_len == 0 ? &empty : out_plain.data();
    std::size_t produced = 0;
    const bool ok = AeadOpen(key, nonce, aad.data(), aad.size(), core, core_len,
                             target, out_plain.size(), &produced)
                 && produced == plain_len;
    bb_secure_zero(key.data(), key.size());
    bb_secure_zero(nonce.data(), nonce.size());
    if (!ok) {
        if (!out_plain.empty()) bb_secure_zero(out_plain.data(), out_plain.size());
        out_plain.clear();
        return BB_ERR_DECRYPT_FAILED;
    }
    return BB_OK;
}

}  // namespace bb
