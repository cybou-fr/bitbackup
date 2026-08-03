#include "core/KeySchedule.h"

#include "crypto/Shake.h"

#include <string_view>

namespace bb {
namespace {

constexpr std::string_view kLabelFileKey  = "bbk/1/filekey";
constexpr std::string_view kLabelName     = "bbk/1/name";
constexpr std::string_view kLabelData     = "bbk/1/data";
constexpr std::string_view kLabelNonce    = "bbk/1/nonce";
constexpr std::string_view kLabelMetadata = "bbk/1/metadata";
constexpr std::string_view kLabelMetaNonce = "bbk/1/metanonce";

/// SHAKE256(K_file || u32be(index) || label, out_len) — форма §5 и §14.
bool DeriveByIndex(const FileKey& k_file, std::uint32_t index,
                   std::string_view label,
                   std::uint8_t* out, std::size_t out_len)
{
    Shake256 shake;
    shake.Update(k_file.data(), k_file.size());
    shake.UpdateU32(index);
    shake.Update(label);
    return shake.Finish(out, out_len);
}

/// SHAKE256(K_file || u32be(stripe) || u16be(position) || label, out_len) — §9.
bool DeriveByPosition(const FileKey& k_file,
                      std::uint32_t stripe, std::uint16_t position,
                      std::string_view label,
                      std::uint8_t* out, std::size_t out_len)
{
    Shake256 shake;
    shake.Update(k_file.data(), k_file.size());
    shake.UpdateU32(stripe);
    shake.UpdateU16(position);
    shake.Update(label);
    return shake.Finish(out, out_len);
}

}  // namespace

bool DeriveFileKey(const Hash256& k_filekey,
                   const Hash256& file_id,
                   FileKey&       out_k_file)
{
    Shake256 shake;
    shake.Update(k_filekey.data(), k_filekey.size());
    shake.Update(file_id.data(), file_id.size());
    shake.Update(kLabelFileKey);
    return shake.Finish(out_k_file.data(), out_k_file.size());
}

bool DeriveObjectName(const FileKey& k_file, std::uint32_t index,
                      ObjectName& out_name)
{
    return DeriveByIndex(k_file, index, kLabelName,
                         out_name.data(), out_name.size());
}

bool DeriveShardKey(const FileKey& k_file,
                    std::uint32_t  stripe,
                    std::uint16_t  position,
                    AeadKey&       out_key,
                    AeadNonce&     out_nonce)
{
    return DeriveByPosition(k_file, stripe, position, kLabelData,
                            out_key.data(), out_key.size())
        && DeriveByPosition(k_file, stripe, position, kLabelNonce,
                            out_nonce.data(), out_nonce.size());
}

bool DeriveMetadataKey(const FileKey& k_file, std::uint32_t index,
                       AeadKey& out_key, AeadNonce& out_nonce)
{
    return DeriveByIndex(k_file, index, kLabelMetadata,
                         out_key.data(), out_key.size())
        && DeriveByIndex(k_file, index, kLabelMetaNonce,
                         out_nonce.data(), out_nonce.size());
}

}  // namespace bb
