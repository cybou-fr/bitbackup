#include "Testing.h"

#include "crypto/Shake.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

std::string HexOf(const std::vector<std::uint8_t>& v)
{
    return bb::test::Hex(v.data(), v.size());
}

std::vector<std::uint8_t> ShakeOf(const std::string& input, std::size_t out_len)
{
    std::vector<std::uint8_t> out(out_len);
    bb::Shake256 shake;
    shake.Update(input.data(), input.size());
    if (!shake.Finish(out.data(), out.size())) {
        out.clear();
    }
    return out;
}

}  // namespace

// FIPS 202 / NIST CAVP: SHAKE256 пустого сообщения.
BB_TEST(shake256_empty_message_vector)
{
    std::vector<std::uint8_t> out(32);
    bb::Shake256 shake;
    BB_CHECK(shake.Finish(out.data(), out.size()));

    BB_CHECK_STR(
        HexOf(out).c_str(),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
}

BB_TEST(shake256_abc_vector)
{
    const std::vector<std::uint8_t> out = ShakeOf("abc", 32);
    BB_CHECK(!out.empty());
    BB_CHECK_STR(
        HexOf(out).c_str(),
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");
}

// XOF: короткий вывод обязан быть префиксом длинного. На этом держится то,
// что из одного identity_root можно выводить ключи разной длины.
BB_TEST(shake256_output_is_prefix_stable)
{
    const std::vector<std::uint8_t> short_out = ShakeOf("bitbackup", 16);
    const std::vector<std::uint8_t> long_out  = ShakeOf("bitbackup", 128);

    BB_CHECK(!short_out.empty());
    BB_CHECK(!long_out.empty());
    BB_CHECK_EQ(std::memcmp(short_out.data(), long_out.data(), short_out.size()), 0);
}

// Конкатенация через несколько Update обязана совпадать с одним Update по
// целому буферу — вся спецификация записана как SHAKE256(a || b || c).
BB_TEST(shake256_chunked_update_equals_single_update)
{
    std::vector<std::uint8_t> whole(64);
    {
        bb::Shake256 shake;
        const std::string all = "bbk/1/filekeyabcdef";
        shake.Update(all.data(), all.size());
        BB_CHECK(shake.Finish(whole.data(), whole.size()));
    }

    std::vector<std::uint8_t> pieces(64);
    {
        bb::Shake256 shake;
        shake.Update(std::string_view("bbk/1/filekey"));
        shake.Update(std::string_view("abc"));
        shake.Update(std::string_view("def"));
        BB_CHECK(shake.Finish(pieces.data(), pieces.size()));
    }

    BB_CHECK_EQ(std::memcmp(whole.data(), pieces.data(), whole.size()), 0);
}

BB_TEST(shake256_integer_updates_are_big_endian)
{
    std::vector<std::uint8_t> via_int(32);
    {
        bb::Shake256 shake;
        shake.UpdateU32(0x01020304u);
        BB_CHECK(shake.Finish(via_int.data(), via_int.size()));
    }

    std::vector<std::uint8_t> via_bytes(32);
    {
        const std::uint8_t be[4] = {0x01, 0x02, 0x03, 0x04};
        bb::Shake256 shake;
        shake.Update(be, sizeof be);
        BB_CHECK(shake.Finish(via_bytes.data(), via_bytes.size()));
    }

    BB_CHECK_EQ(std::memcmp(via_int.data(), via_bytes.data(), via_int.size()), 0);
}

BB_TEST(shake256_domain_labels_separate)
{
    const std::vector<std::uint8_t> a = ShakeOf("bbk/1/filekey", 32);
    const std::vector<std::uint8_t> b = ShakeOf("bbk/1/split", 32);

    BB_CHECK(!a.empty());
    BB_CHECK(std::memcmp(a.data(), b.data(), a.size()) != 0);
}

BB_TEST(shake256_cannot_finish_twice)
{
    std::uint8_t out[32];
    bb::Shake256 shake;
    shake.Update(std::string_view("x"));
    BB_CHECK(shake.Finish(out, sizeof out));
    BB_CHECK(!shake.Finish(out, sizeof out));
}
