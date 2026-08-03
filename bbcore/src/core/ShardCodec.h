#ifndef BBCORE_CORE_SHARDCODEC_H
#define BBCORE_CORE_SHARDCODEC_H

#include "core/KeySchedule.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bb {

/// Encrypt one data fragment. Parity cores are computed over these sealed cores and are
/// not passed through this function.
bb_status ShardSeal(const FileKey& k_file,
                    const Hash256& identity_id,
                    const Hash256& file_id,
                    std::uint32_t stripe,
                    std::uint16_t position,
                    const std::uint8_t* plain,
                    std::size_t plain_len,
                    std::vector<std::uint8_t>& out_core);

bb_status ShardOpen(const FileKey& k_file,
                    const Hash256& identity_id,
                    const Hash256& file_id,
                    std::uint32_t stripe,
                    std::uint16_t position,
                    const std::uint8_t* core,
                    std::size_t core_len,
                    std::vector<std::uint8_t>& out_plain);

}  // namespace bb

#endif
