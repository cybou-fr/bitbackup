#include "core/FileIdentity.h"

#include "util/Cbor.h"

namespace bb {
namespace {

constexpr std::string_view kProcessingLabel = "bbk/1/processing";
constexpr std::string_view kInstanceLabel = "bbk/1/file-instance";
constexpr std::string_view kFileIdLabel = "bbk/1/file-id";

void UpdateU16(Blake3& hash, std::uint16_t value)
{
    const std::uint8_t bytes[] = {
        static_cast<std::uint8_t>(value >> 8), static_cast<std::uint8_t>(value)};
    hash.Update(bytes, sizeof bytes);
}

void UpdateU32(Blake3& hash, std::uint32_t value)
{
    const std::uint8_t bytes[] = {
        static_cast<std::uint8_t>(value >> 24), static_cast<std::uint8_t>(value >> 16),
        static_cast<std::uint8_t>(value >> 8), static_cast<std::uint8_t>(value)};
    hash.Update(bytes, sizeof bytes);
}

bool IsSafeComponent(std::string_view value)
{
    return !value.empty() && value != "." && value != ".."
        && value.find('/') == std::string_view::npos
        && value.find('\\') == std::string_view::npos
        && value.find('\0') == std::string_view::npos && Utf8IsValid(value);
}

bool IsSafeRelativePath(std::string_view path)
{
    if (path.empty() || path.front() == '/' || path.find('\\') != std::string_view::npos
     || path.find('\0') != std::string_view::npos || !Utf8IsValid(path)) return false;
    std::size_t start = 0;
    while (start <= path.size()) {
        const std::size_t end = path.find('/', start);
        const std::string_view part = path.substr(
            start, end == std::string_view::npos ? path.size() - start : end - start);
        if (part.empty() || part == "." || part == "..") return false;
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return true;
}

}  // namespace

bool ProcessingProfileIsValid(const ProcessingProfile& profile)
{
    const std::uint32_t rs_total = static_cast<std::uint32_t>(profile.rs_data)
                                 + static_cast<std::uint32_t>(profile.rs_parity);
    return profile.version == kProcessingProfileVersion
        && profile.metadata_schema == kMetadataSchemaVersion
        && profile.shard_codec == kShardCodecVersion
        && profile.rs_codec == kReedSolomonCodecVersion
        && profile.rs_data != 0 && profile.rs_parity != 0 && rs_total <= 255
        && SplitProfileIsValid(profile.split);
}

bool DeriveProcessingId(const ProcessingProfile& profile, Hash256& out)
{
    if (!ProcessingProfileIsValid(profile)) return false;
    Blake3 hash;
    hash.Update(kProcessingLabel);
    UpdateU16(hash, profile.version);
    hash.Update(profile.transform_id.data(), profile.transform_id.size());
    UpdateU32(hash, profile.split.min);
    UpdateU32(hash, profile.split.avg);
    UpdateU32(hash, profile.split.max);
    UpdateU32(hash, profile.split.align);
    UpdateU16(hash, profile.rs_data);
    UpdateU16(hash, profile.rs_parity);
    hash.UpdateU8(profile.pad_shards ? 1 : 0);
    UpdateU16(hash, profile.metadata_schema);
    UpdateU16(hash, profile.shard_codec);
    UpdateU16(hash, profile.rs_codec);
    return hash.Finish(out);
}

bool DeriveFileInstanceId(const IdentityKey& k_instance,
                          std::string_view root_label,
                          std::string_view relative_path,
                          InstanceId& out)
{
    if (!IsSafeComponent(root_label) || !IsSafeRelativePath(relative_path)
     || root_label.size() > 0xFFFFFFFFu || relative_path.size() > 0xFFFFFFFFu) return false;
    Blake3 hash(k_instance);
    hash.Update(kInstanceLabel);
    UpdateU32(hash, static_cast<std::uint32_t>(root_label.size()));
    hash.Update(root_label);
    UpdateU32(hash, static_cast<std::uint32_t>(relative_path.size()));
    hash.Update(relative_path);
    return hash.Finish(out);
}

bool DeriveFileId(const IdentityKey& k_fileid,
                  const InstanceId& file_instance,
                  const Hash256& content_hash,
                  const Hash256& processing_id,
                  Hash256& out)
{
    Blake3 hash(k_fileid);
    hash.Update(kFileIdLabel);
    hash.Update(file_instance.data(), file_instance.size());
    hash.Update(content_hash.data(), content_hash.size());
    hash.Update(processing_id.data(), processing_id.size());
    return hash.Finish(out);
}

}  // namespace bb
