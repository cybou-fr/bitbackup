#include "Testing.h"

#include "bbcore/bbcore.h"

#include <cstring>

namespace {

void FillPattern(uint8_t* data, size_t len, uint8_t start)
{
    for (size_t i = 0; i < len; ++i) {
        data[i] = static_cast<uint8_t>(start + i * 3);
    }
}

}  // namespace

BB_TEST(object_name_roundtrip)
{
    uint8_t id[BB_ID_LEN];
    uint8_t name[BB_NAME_LEN];
    FillPattern(id, sizeof id, 0x11);
    FillPattern(name, sizeof name, 0x80);

    char formatted[BB_OBJECT_NAME_MAX] = {0};
    BB_CHECK_EQ(bb_object_name_format(id, name, formatted, sizeof formatted),
                BB_OK);

    uint8_t id_back[BB_ID_LEN]     = {0};
    uint8_t name_back[BB_NAME_LEN] = {0};
    BB_CHECK_EQ(bb_object_name_parse(formatted, id_back, name_back), BB_OK);

    BB_CHECK_EQ(std::memcmp(id, id_back, sizeof id), 0);
    BB_CHECK_EQ(std::memcmp(name, name_back, sizeof name), 0);
}

BB_TEST(object_name_layout_fits_windows_path_limits)
{
    uint8_t id[BB_ID_LEN]     = {0};
    uint8_t name[BB_NAME_LEN] = {0};

    char formatted[BB_OBJECT_NAME_MAX] = {0};
    BB_CHECK_EQ(bb_object_name_format(id, name, formatted, sizeof formatted),
                BB_OK);

    // 52 + '.' + 52 + ".bbk" = 109. Запас до MAX_PATH 260 и до лимита
    // имени 255 на FAT32 — это и есть смысл base32 вместо hex.
    BB_CHECK_EQ(std::strlen(formatted), static_cast<size_t>(109));
    BB_CHECK_EQ(formatted[52], '.');
    BB_CHECK_STR(formatted + 105, ".bbk");
}

BB_TEST(object_name_all_zero_and_all_ones)
{
    uint8_t zero[BB_ID_LEN];
    uint8_t ones[BB_NAME_LEN];
    std::memset(zero, 0x00, sizeof zero);
    std::memset(ones, 0xFF, sizeof ones);

    char formatted[BB_OBJECT_NAME_MAX] = {0};
    BB_CHECK_EQ(bb_object_name_format(zero, ones, formatted, sizeof formatted),
                BB_OK);

    uint8_t id_back[BB_ID_LEN]     = {0};
    uint8_t name_back[BB_NAME_LEN] = {0};
    BB_CHECK_EQ(bb_object_name_parse(formatted, id_back, name_back), BB_OK);
    BB_CHECK_EQ(std::memcmp(zero, id_back, sizeof zero), 0);
    BB_CHECK_EQ(std::memcmp(ones, name_back, sizeof ones), 0);
}

BB_TEST(object_name_parse_rejects_malformed)
{
    uint8_t id[BB_ID_LEN];
    uint8_t name[BB_NAME_LEN];
    FillPattern(id, sizeof id, 0x11);
    FillPattern(name, sizeof name, 0x80);

    char good[BB_OBJECT_NAME_MAX] = {0};
    BB_CHECK_EQ(bb_object_name_format(id, name, good, sizeof good), BB_OK);

    char broken[BB_OBJECT_NAME_MAX];

    // Неверный разделитель.
    std::memcpy(broken, good, sizeof broken);
    broken[52] = '-';
    BB_CHECK_EQ(bb_object_name_parse(broken, nullptr, nullptr),
                BB_ERR_INVALID_ARG);

    // Неверное расширение.
    std::memcpy(broken, good, sizeof broken);
    broken[106] = 'x';
    BB_CHECK_EQ(bb_object_name_parse(broken, nullptr, nullptr),
                BB_ERR_INVALID_ARG);

    // Символ вне алфавита.
    std::memcpy(broken, good, sizeof broken);
    broken[3] = '0';
    BB_CHECK_EQ(bb_object_name_parse(broken, nullptr, nullptr),
                BB_ERR_INVALID_ARG);

    // Обрезанное имя.
    std::memcpy(broken, good, sizeof broken);
    broken[100] = '\0';
    BB_CHECK_EQ(bb_object_name_parse(broken, nullptr, nullptr),
                BB_ERR_INVALID_ARG);

    BB_CHECK_EQ(bb_object_name_parse("", nullptr, nullptr), BB_ERR_INVALID_ARG);
    BB_CHECK_EQ(bb_object_name_parse(nullptr, nullptr, nullptr),
                BB_ERR_INVALID_ARG);
}

BB_TEST(object_name_format_rejects_small_buffer)
{
    uint8_t id[BB_ID_LEN]     = {0};
    uint8_t name[BB_NAME_LEN] = {0};
    char    small[64]         = {0};

    BB_CHECK_EQ(bb_object_name_format(id, name, small, sizeof small),
                BB_ERR_BUFFER_TOO_SMALL);
}

BB_TEST(status_text_is_defined_for_every_code)
{
    const bb_status codes[] = {
        BB_OK, BB_ERR_INVALID_ARG, BB_ERR_BUFFER_TOO_SMALL, BB_ERR_OUT_OF_MEMORY,
        BB_ERR_UNSUPPORTED, BB_ERR_BAD_MNEMONIC, BB_ERR_BAD_CONTAINER,
        BB_ERR_DECRYPT_FAILED, BB_ERR_WRONG_IDENTITY, BB_ERR_INTEGRITY,
        BB_ERR_UNRECOVERABLE, BB_ERR_STORAGE, BB_ERR_IO, BB_ERR_CANCELLED,
        BB_ERR_INTERNAL,
    };

    for (bb_status code : codes) {
        const char* text = bb_status_text(code);
        BB_CHECK(text != nullptr);
        BB_CHECK(std::strcmp(text, "unknown status") != 0);
    }
}
