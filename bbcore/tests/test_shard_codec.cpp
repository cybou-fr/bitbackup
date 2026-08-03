#include "Testing.h"

#include "core/ShardCodec.h"

#include <cstring>

namespace {

template <typename T>
T Pattern(std::uint8_t start)
{
    T value{};
    for (std::size_t i = 0; i < value.size(); ++i)
        value[i] = static_cast<std::uint8_t>(start + i);
    return value;
}

}  // namespace

BB_TEST(shard_codec_roundtrips_data_and_empty_fragment)
{
    const bb::FileKey key = Pattern<bb::FileKey>(1);
    const bb::Hash256 identity = Pattern<bb::Hash256>(33);
    const bb::Hash256 file = Pattern<bb::Hash256>(65);
    for (std::size_t length : {std::size_t{0}, std::size_t{1}, std::size_t{4097}}) {
        std::vector<std::uint8_t> plain(length);
        for (std::size_t i = 0; i < length; ++i) plain[i] = static_cast<std::uint8_t>(i);
        std::vector<std::uint8_t> core;
        BB_CHECK_EQ(bb::ShardSeal(key, identity, file, 7, 2,
                                  plain.data(), plain.size(), core), BB_OK);
        BB_CHECK_EQ(core.size(), plain.size() + BB_TAG_LEN);
        std::vector<std::uint8_t> opened;
        BB_CHECK_EQ(bb::ShardOpen(key, identity, file, 7, 2,
                                  core.data(), core.size(), opened), BB_OK);
        BB_CHECK(opened == plain);
    }
}

BB_TEST(shard_codec_authenticates_core_and_context)
{
    const bb::FileKey key = Pattern<bb::FileKey>(1);
    const bb::Hash256 identity = Pattern<bb::Hash256>(33);
    const bb::Hash256 file = Pattern<bb::Hash256>(65);
    const std::uint8_t plain[] = {1, 2, 3, 4, 5};
    std::vector<std::uint8_t> core;
    BB_CHECK_EQ(bb::ShardSeal(key, identity, file, 7, 2, plain, sizeof plain, core), BB_OK);
    std::vector<std::uint8_t> opened;
    for (std::size_t i = 0; i < core.size(); ++i) {
        auto damaged = core; damaged[i] ^= 1;
        BB_CHECK_EQ(bb::ShardOpen(key, identity, file, 7, 2,
                                  damaged.data(), damaged.size(), opened), BB_ERR_DECRYPT_FAILED);
    }
    auto other_identity = identity; other_identity[0] ^= 1;
    auto other_file = file; other_file[0] ^= 1;
    BB_CHECK_EQ(bb::ShardOpen(key, other_identity, file, 7, 2, core.data(), core.size(), opened),
                BB_ERR_DECRYPT_FAILED);
    BB_CHECK_EQ(bb::ShardOpen(key, identity, other_file, 7, 2, core.data(), core.size(), opened),
                BB_ERR_DECRYPT_FAILED);
    BB_CHECK_EQ(bb::ShardOpen(key, identity, file, 8, 2, core.data(), core.size(), opened),
                BB_ERR_DECRYPT_FAILED);
    BB_CHECK_EQ(bb::ShardOpen(key, identity, file, 7, 3, core.data(), core.size(), opened),
                BB_ERR_DECRYPT_FAILED);
}

BB_TEST(shard_codec_is_deterministic_for_one_position)
{
    const bb::FileKey key = Pattern<bb::FileKey>(1);
    const bb::Hash256 identity = Pattern<bb::Hash256>(33);
    const bb::Hash256 file = Pattern<bb::Hash256>(65);
    const std::uint8_t plain[] = {0, 1, 2, 3};
    std::vector<std::uint8_t> first, second;
    BB_CHECK_EQ(bb::ShardSeal(key, identity, file, 0, 0, plain, sizeof plain, first), BB_OK);
    BB_CHECK_EQ(bb::ShardSeal(key, identity, file, 0, 0, plain, sizeof plain, second), BB_OK);
    BB_CHECK(first == second);
}
