#include "bbcore/bbcore.h"

#include "util/Base32.h"

#include <cstring>

namespace {

constexpr std::size_t kIdText   = BB_ID_B32_LEN;    // 52
constexpr std::size_t kNameText = BB_NAME_B32_LEN;  // 52
constexpr char        kSuffix[] = ".bbk";
constexpr std::size_t kSuffixLen = 4;

// "<52>.<52>.bbk" — без завершающего нуля.
constexpr std::size_t kFullLen = kIdText + 1 + kNameText + kSuffixLen;

static_assert(kFullLen + 1 <= BB_OBJECT_NAME_MAX,
              "BB_OBJECT_NAME_MAX must fit a formatted object name");
static_assert(bb::Base32EncodedLen(BB_ID_LEN) == BB_ID_B32_LEN,
              "BB_ID_B32_LEN out of sync with BB_ID_LEN");
static_assert(bb::Base32EncodedLen(BB_NAME_LEN) == BB_NAME_B32_LEN,
              "BB_NAME_B32_LEN out of sync with BB_NAME_LEN");

}  // namespace

BB_API bb_status BB_CALL bb_base32_encode(
    const uint8_t* data, size_t len, char* out, size_t cap, size_t* out_len)
{
    std::size_t needed = 0;
    if (!bb::Base32Encode(data, len, out, cap, &needed)) {
        if (out_len != nullptr) {
            *out_len = needed;
        }
        return (out != nullptr && cap < needed) ? BB_ERR_BUFFER_TOO_SMALL
                                                : BB_ERR_INVALID_ARG;
    }
    if (out_len != nullptr) {
        *out_len = needed;
    }
    return BB_OK;
}

BB_API bb_status BB_CALL bb_base32_decode(
    const char* text, uint8_t* out, size_t cap, size_t* out_len)
{
    if (text == nullptr) {
        return BB_ERR_INVALID_ARG;
    }

    const std::size_t text_len = std::strlen(text);
    std::size_t       needed   = 0;

    if (!bb::Base32Decode(text, text_len, out, cap, &needed)) {
        if (out_len != nullptr) {
            *out_len = needed;
        }
        return (cap < needed) ? BB_ERR_BUFFER_TOO_SMALL : BB_ERR_INVALID_ARG;
    }
    if (out_len != nullptr) {
        *out_len = needed;
    }
    return BB_OK;
}

BB_API bb_status BB_CALL bb_object_name_format(
    const uint8_t identity_id[BB_ID_LEN],
    const uint8_t object_name[BB_NAME_LEN],
    char*         out,
    size_t        cap)
{
    if (identity_id == nullptr || object_name == nullptr || out == nullptr) {
        return BB_ERR_INVALID_ARG;
    }
    if (cap < kFullLen + 1) {
        return BB_ERR_BUFFER_TOO_SMALL;
    }

    if (!bb::Base32Encode(identity_id, BB_ID_LEN, out, cap, nullptr)) {
        return BB_ERR_INTERNAL;
    }
    out[kIdText] = '.';

    if (!bb::Base32Encode(object_name, BB_NAME_LEN,
                          out + kIdText + 1, cap - kIdText - 1, nullptr)) {
        return BB_ERR_INTERNAL;
    }

    std::memcpy(out + kIdText + 1 + kNameText, kSuffix, kSuffixLen);
    out[kFullLen] = '\0';

    return BB_OK;
}

BB_API bb_status BB_CALL bb_object_name_parse(
    const char* text,
    uint8_t     out_identity_id[BB_ID_LEN],
    uint8_t     out_object_name[BB_NAME_LEN])
{
    if (text == nullptr) {
        return BB_ERR_INVALID_ARG;
    }
    if (std::strlen(text) != kFullLen) {
        return BB_ERR_INVALID_ARG;
    }
    if (text[kIdText] != '.') {
        return BB_ERR_INVALID_ARG;
    }
    if (std::memcmp(text + kIdText + 1 + kNameText, kSuffix, kSuffixLen) != 0) {
        return BB_ERR_INVALID_ARG;
    }

    uint8_t id_buf[BB_ID_LEN];
    uint8_t name_buf[BB_NAME_LEN];

    if (!bb::Base32Decode(text, kIdText, id_buf, sizeof id_buf, nullptr)) {
        return BB_ERR_INVALID_ARG;
    }
    if (!bb::Base32Decode(text + kIdText + 1, kNameText,
                          name_buf, sizeof name_buf, nullptr)) {
        return BB_ERR_INVALID_ARG;
    }

    if (out_identity_id != nullptr) {
        std::memcpy(out_identity_id, id_buf, BB_ID_LEN);
    }
    if (out_object_name != nullptr) {
        std::memcpy(out_object_name, name_buf, BB_NAME_LEN);
    }
    return BB_OK;
}
