#include "Testing.h"

#include "bbcore/bbcore.h"

#include <cstring>
#include <string>

namespace {

std::string Encode(const std::string& input, bb_status* status = nullptr)
{
    char   out[256] = {0};
    size_t len      = 0;

    const bb_status st = bb_base32_encode(
        reinterpret_cast<const uint8_t*>(input.data()), input.size(),
        out, sizeof out, &len);

    if (status != nullptr) {
        *status = st;
    }
    return std::string(out, (st == BB_OK) ? len : 0);
}

}  // namespace

// Тест-векторы RFC 4648 §10, приведённые к строчному алфавиту и без padding.
BB_TEST(base32_rfc4648_vectors)
{
    BB_CHECK(Encode("")       == "");
    BB_CHECK(Encode("f")      == "my");
    BB_CHECK(Encode("fo")     == "mzxq");
    BB_CHECK(Encode("foo")    == "mzxw6");
    BB_CHECK(Encode("foob")   == "mzxw6yq");
    BB_CHECK(Encode("fooba")  == "mzxw6ytb");
    BB_CHECK(Encode("foobar") == "mzxw6ytboi");
}

BB_TEST(base32_roundtrip_all_lengths)
{
    uint8_t input[64];
    for (size_t i = 0; i < sizeof input; ++i) {
        input[i] = static_cast<uint8_t>(i * 7 + 13);
    }

    for (size_t len = 0; len <= sizeof input; ++len) {
        char   text[128] = {0};
        size_t text_len  = 0;

        BB_CHECK_EQ(bb_base32_encode(input, len, text, sizeof text, &text_len),
                    BB_OK);
        BB_CHECK_EQ(text_len, BB_B32_LEN(len));

        uint8_t decoded[64] = {0};
        size_t  decoded_len = 0;

        BB_CHECK_EQ(bb_base32_decode(text, decoded, sizeof decoded, &decoded_len),
                    BB_OK);
        BB_CHECK_EQ(decoded_len, len);
        BB_CHECK_EQ(std::memcmp(decoded, input, len), 0);
    }
}

BB_TEST(base32_encoded_length_of_32_bytes_is_52)
{
    uint8_t input[BB_ID_LEN] = {0};
    char    text[BB_ID_B32_LEN + 1] = {0};
    size_t  len = 0;

    BB_CHECK_EQ(bb_base32_encode(input, sizeof input, text, sizeof text, &len),
                BB_OK);
    BB_CHECK_EQ(len, static_cast<size_t>(BB_ID_B32_LEN));
}

BB_TEST(base32_rejects_uppercase)
{
    uint8_t out[16];
    size_t  len = 0;

    // Каноническая форма ровно одна: имя объекта участвует в AAD.
    BB_CHECK_EQ(bb_base32_decode("MY", out, sizeof out, &len), BB_ERR_INVALID_ARG);
    BB_CHECK_EQ(bb_base32_decode("mY", out, sizeof out, &len), BB_ERR_INVALID_ARG);
}

BB_TEST(base32_rejects_padding_and_foreign_symbols)
{
    uint8_t out[16];
    size_t  len = 0;

    BB_CHECK_EQ(bb_base32_decode("my======", out, sizeof out, &len),
                BB_ERR_INVALID_ARG);
    BB_CHECK_EQ(bb_base32_decode("mz0q", out, sizeof out, &len),
                BB_ERR_INVALID_ARG);  // '0' вне алфавита
    BB_CHECK_EQ(bb_base32_decode("mz-q", out, sizeof out, &len),
                BB_ERR_INVALID_ARG);
}

BB_TEST(base32_rejects_impossible_tail_lengths)
{
    uint8_t out[16];
    size_t  len = 0;

    // Остатки 1, 3 и 6 символов не могут получиться при кодировании.
    BB_CHECK_EQ(bb_base32_decode("m", out, sizeof out, &len), BB_ERR_INVALID_ARG);
    BB_CHECK_EQ(bb_base32_decode("mzx", out, sizeof out, &len), BB_ERR_INVALID_ARG);
    BB_CHECK_EQ(bb_base32_decode("mzxw6y", out, sizeof out, &len),
                BB_ERR_INVALID_ARG);
}

BB_TEST(base32_rejects_noncanonical_trailing_bits)
{
    uint8_t out[16];
    size_t  len = 0;

    // "my" декодируется в 'f'. "mz" несёт тот же байт, но с ненулевым
    // остатком — второе написание того же значения, и оно запрещено.
    BB_CHECK_EQ(bb_base32_decode("my", out, sizeof out, &len), BB_OK);
    BB_CHECK_EQ(bb_base32_decode("mz", out, sizeof out, &len), BB_ERR_INVALID_ARG);
}

BB_TEST(base32_reports_required_size_when_buffer_too_small)
{
    const uint8_t input[BB_ID_LEN] = {0};
    char          small[8]         = {0};
    size_t        needed           = 0;

    BB_CHECK_EQ(bb_base32_encode(input, sizeof input, small, sizeof small, &needed),
                BB_ERR_BUFFER_TOO_SMALL);
    BB_CHECK_EQ(needed, static_cast<size_t>(BB_ID_B32_LEN));
}
