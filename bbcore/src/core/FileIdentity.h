#ifndef BBCORE_CORE_FILEIDENTITY_H
#define BBCORE_CORE_FILEIDENTITY_H

#include "core/MetadataCodec.h"
#include "crypto/Hash.h"
#include "identity/Identity.h"

#include <cstdint>
#include <string_view>

namespace bb {

inline constexpr std::uint16_t kProcessingProfileVersion = 1;
inline constexpr std::uint16_t kMetadataSchemaVersion = 1;
inline constexpr std::uint16_t kShardCodecVersion = 1;
inline constexpr std::uint16_t kReedSolomonCodecVersion = 1;

struct ProcessingProfile {
    std::uint16_t version = kProcessingProfileVersion;
    TransformId transform_id{};
    SplitProfile split = kDefaultSplitProfile;
    std::uint16_t rs_data = BB_RS_DATA;
    std::uint16_t rs_parity = BB_RS_PARITY;
    bool pad_shards = false;
    std::uint16_t metadata_schema = kMetadataSchemaVersion;
    std::uint16_t shard_codec = kShardCodecVersion;
    std::uint16_t rs_codec = kReedSolomonCodecVersion;
};

bool ProcessingProfileIsValid(const ProcessingProfile& profile);
bool DeriveProcessingId(const ProcessingProfile& profile, Hash256& out);
bool DeriveFileInstanceId(const IdentityKey& k_instance,
                          std::string_view root_label,
                          std::string_view relative_path,
                          InstanceId& out);
bool DeriveFileId(const IdentityKey& k_fileid,
                  const InstanceId& file_instance,
                  const Hash256& content_hash,
                  const Hash256& processing_id,
                  Hash256& out);

}  // namespace bb

#endif
