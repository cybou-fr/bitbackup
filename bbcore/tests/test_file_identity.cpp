#include "Testing.h"

#include "core/FileIdentity.h"

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

BB_TEST(file_identity_derivation_is_deterministic)
{
    const bb::IdentityKey k_instance = Pattern<bb::IdentityKey>(1);
    const bb::IdentityKey k_fileid = Pattern<bb::IdentityKey>(33);
    const bb::Hash256 content = Pattern<bb::Hash256>(65);
    bb::ProcessingProfile profile;
    bb::Hash256 processing{};
    bb::InstanceId instance{};
    bb::Hash256 file_id{};
    BB_CHECK(bb::DeriveProcessingId(profile, processing));
    BB_CHECK(bb::DeriveFileInstanceId(k_instance, "Documents", "Private/report.pdf", instance));
    BB_CHECK(bb::DeriveFileId(k_fileid, instance, content, processing, file_id));
    BB_CHECK_STR(bb::test::Hex(processing.data(), processing.size()).c_str(),
                 "b01ab8934bf3683f7180d2f2d5af5926fb94a6c3e9eeacd1da671c6d40230deb");
    BB_CHECK_STR(bb::test::Hex(instance.data(), instance.size()).c_str(),
                 "32440f96eb91e45d4bf41521622b2c6aeff84e0993f63efbe628cb2f5115e51f");
    BB_CHECK_STR(bb::test::Hex(file_id.data(), file_id.size()).c_str(),
                 "2d1a4d0f2668503b8063588021e3137f54374385f0e47bb767e5e6c18fd62160");
}

BB_TEST(file_identity_changes_with_every_processing_field)
{
    bb::ProcessingProfile base;
    bb::Hash256 expected{};
    BB_CHECK(bb::DeriveProcessingId(base, expected));
    auto differs = [&](bb::ProcessingProfile changed) {
        bb::Hash256 actual{};
        BB_CHECK(bb::DeriveProcessingId(changed, actual));
        BB_CHECK(actual != expected);
    };
    { auto p = base; p.transform_id[3] = 1; differs(p); }
    { auto p = base; p.split.min += p.split.align; differs(p); }
    { auto p = base; p.split.avg += p.split.align; differs(p); }
    { auto p = base; p.split.max += p.split.align; differs(p); }
    { auto p = base; p.split.align *= 2; differs(p); }
    { auto p = base; p.rs_data = 4; differs(p); }
    { auto p = base; p.rs_parity = 2; differs(p); }
    { auto p = base; p.pad_shards = true; differs(p); }
}

BB_TEST(file_instance_rejects_unsafe_or_ambiguous_paths)
{
    const bb::IdentityKey key = Pattern<bb::IdentityKey>(1);
    bb::InstanceId out{};
    BB_CHECK(!bb::DeriveFileInstanceId(key, "", "file", out));
    BB_CHECK(!bb::DeriveFileInstanceId(key, "A/B", "file", out));
    BB_CHECK(!bb::DeriveFileInstanceId(key, "Root", "/file", out));
    BB_CHECK(!bb::DeriveFileInstanceId(key, "Root", "../file", out));
    BB_CHECK(!bb::DeriveFileInstanceId(key, "Root", "a//file", out));
    BB_CHECK(!bb::DeriveFileInstanceId(key, "Root", "a\\file", out));
}

BB_TEST(processing_profile_rejects_unregistered_versions_and_invalid_layout)
{
    bb::ProcessingProfile profile;
    profile.metadata_schema = 2;
    BB_CHECK(!bb::ProcessingProfileIsValid(profile));
    profile = bb::ProcessingProfile{}; profile.shard_codec = 2;
    BB_CHECK(!bb::ProcessingProfileIsValid(profile));
    profile = bb::ProcessingProfile{}; profile.rs_codec = 2;
    BB_CHECK(!bb::ProcessingProfileIsValid(profile));
    profile = bb::ProcessingProfile{}; profile.rs_data = 254; profile.rs_parity = 2;
    BB_CHECK(!bb::ProcessingProfileIsValid(profile));
}

BB_TEST(file_id_changes_with_identity_content_and_profile)
{
    bb::IdentityKey key = Pattern<bb::IdentityKey>(1);
    bb::InstanceId instance = Pattern<bb::InstanceId>(33);
    bb::Hash256 content = Pattern<bb::Hash256>(65);
    bb::Hash256 processing = Pattern<bb::Hash256>(97);
    bb::Hash256 base{};
    BB_CHECK(bb::DeriveFileId(key, instance, content, processing, base));
    auto changed_key = key; changed_key[0] ^= 1;
    auto changed_instance = instance; changed_instance[0] ^= 1;
    auto changed_content = content; changed_content[0] ^= 1;
    auto changed_processing = processing; changed_processing[0] ^= 1;
    bb::Hash256 actual{};
    BB_CHECK(bb::DeriveFileId(changed_key, instance, content, processing, actual)); BB_CHECK(actual != base);
    BB_CHECK(bb::DeriveFileId(key, changed_instance, content, processing, actual)); BB_CHECK(actual != base);
    BB_CHECK(bb::DeriveFileId(key, instance, changed_content, processing, actual)); BB_CHECK(actual != base);
    BB_CHECK(bb::DeriveFileId(key, instance, content, changed_processing, actual)); BB_CHECK(actual != base);
}
