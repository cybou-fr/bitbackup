#include "Testing.h"

#include "bbcore/bbcore.h"

#include <cstring>
#include <vector>

namespace {

constexpr const char* kMnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

bb_identity* Open(std::uint32_t index = 0)
{
    bb_identity* identity = nullptr;
    return bb_identity_open(kMnemonic, "", index, &identity) == BB_OK ? identity : nullptr;
}

}  // namespace

BB_TEST(state_roundtrip_and_size_negotiation)
{
    bb_identity* identity = Open();
    BB_CHECK(identity != nullptr);
    const std::uint8_t plain[] = {0, 1, 2, 3, 0, 255};

    std::size_t sealed_len = 0;
    BB_CHECK_EQ(bb_identity_state_seal(identity, plain, sizeof plain,
                                       nullptr, 0, &sealed_len), BB_ERR_BUFFER_TOO_SMALL);
    BB_CHECK_EQ(sealed_len, sizeof plain + std::size_t{68});
    std::vector<std::uint8_t> sealed(sealed_len);
    BB_CHECK_EQ(bb_identity_state_seal(identity, plain, sizeof plain,
                                       sealed.data(), sealed.size(), &sealed_len), BB_OK);

    std::size_t opened_len = 0;
    BB_CHECK_EQ(bb_identity_state_open(identity, sealed.data(), sealed.size(),
                                       nullptr, 0, &opened_len), BB_ERR_BUFFER_TOO_SMALL);
    BB_CHECK_EQ(opened_len, sizeof plain);
    std::vector<std::uint8_t> opened(opened_len);
    BB_CHECK_EQ(bb_identity_state_open(identity, sealed.data(), sealed.size(),
                                       opened.data(), opened.size(), &opened_len), BB_OK);
    BB_CHECK_EQ(std::memcmp(opened.data(), plain, sizeof plain), 0);
    bb_identity_free(identity);
}

BB_TEST(state_rejects_corruption_and_other_identity)
{
    bb_identity* identity = Open(0);
    bb_identity* other = Open(1);
    BB_CHECK(identity != nullptr && other != nullptr);
    const std::uint8_t plain[] = {9, 8, 7};
    std::size_t size = 0;
    BB_CHECK_EQ(bb_identity_state_seal(identity, plain, sizeof plain, nullptr, 0, &size),
                BB_ERR_BUFFER_TOO_SMALL);
    std::vector<std::uint8_t> sealed(size);
    BB_CHECK_EQ(bb_identity_state_seal(identity, plain, sizeof plain,
                                       sealed.data(), sealed.size(), &size), BB_OK);

    std::vector<std::uint8_t> out(sizeof plain, 0xAA);
    std::size_t out_len = 0;
    BB_CHECK_EQ(bb_identity_state_open(other, sealed.data(), sealed.size(),
                                       out.data(), out.size(), &out_len), BB_ERR_DECRYPT_FAILED);
    for (std::size_t i = 0; i < sealed.size(); ++i) {
        std::vector<std::uint8_t> damaged = sealed;
        damaged[i] ^= 1;
        BB_CHECK_EQ(bb_identity_state_open(identity, damaged.data(), damaged.size(),
                                           out.data(), out.size(), &out_len), BB_ERR_DECRYPT_FAILED);
    }
    bb_identity_free(other);
    bb_identity_free(identity);
}

BB_TEST(state_requires_private_identity)
{
    bb_identity* full = Open();
    BB_CHECK(full != nullptr);
    std::size_t blob_len = 0;
    BB_CHECK_EQ(bb_identity_export_public(full, nullptr, 0, &blob_len), BB_ERR_BUFFER_TOO_SMALL);
    std::vector<std::uint8_t> blob(blob_len);
    BB_CHECK_EQ(bb_identity_export_public(full, blob.data(), blob.size(), &blob_len), BB_OK);
    bb_identity* public_identity = nullptr;
    BB_CHECK_EQ(bb_identity_open_public(blob.data(), blob.size(), &public_identity), BB_OK);
    std::size_t out_len = 0;
    BB_CHECK_EQ(bb_identity_state_seal(public_identity, nullptr, 0, nullptr, 0, &out_len),
                BB_ERR_INVALID_ARG);
    bb_identity_free(public_identity);
    bb_identity_free(full);
}
