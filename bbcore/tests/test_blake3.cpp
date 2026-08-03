// Векторы BLAKE3 — официальные, из test_vectors/test_vectors.json репозитория
// BLAKE3-team/BLAKE3 (версия 1.8.5). Вход длины n там задан как байты i mod 251,
// ключ — ASCII-строка "whats the Elvish word for friend", поле hash хранит 131
// байт расширенного вывода, из которых обычный 32-байтовый хеш это префикс.
//
// Значения не пересчитываются под код: если тест упал, сломан код.

#include "Testing.h"

#include "crypto/Hash.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

// Вход официальных векторов: повторяющаяся последовательность 0..250.
std::vector<std::uint8_t> VectorInput(std::size_t len)
{
    std::vector<std::uint8_t> input(len);
    for (std::size_t i = 0; i < len; ++i) {
        input[i] = static_cast<std::uint8_t>(i % 251);
    }
    return input;
}

const bb::Blake3Key& VectorKey()
{
    static const bb::Blake3Key key = [] {
        bb::Blake3Key k{};
        const char* text = "whats the Elvish word for friend";  // ровно 32 байта
        std::memcpy(k.data(), text, k.size());
        return k;
    }();
    return key;
}

std::string HashHex(std::size_t input_len, std::size_t out_len)
{
    const std::vector<std::uint8_t> input = VectorInput(input_len);
    std::vector<std::uint8_t>       out(out_len);
    if (!bb::Blake3Hash(input.data(), input.size(), out.data(), out.size())) {
        return std::string();
    }
    return bb::test::Hex(out.data(), out.size());
}

std::string KeyedHex(std::size_t input_len, std::size_t out_len)
{
    const std::vector<std::uint8_t> input = VectorInput(input_len);
    std::vector<std::uint8_t>       out(out_len);
    if (!bb::Blake3KeyedHash(VectorKey(), input.data(), input.size(),
                             out.data(), out.size())) {
        return std::string();
    }
    return bb::test::Hex(out.data(), out.size());
}

}  // namespace

BB_TEST(blake3_official_vectors_unkeyed)
{
    BB_CHECK_STR(HashHex(0, 32).c_str(),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    BB_CHECK_STR(HashHex(1, 32).c_str(),
        "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213");
    BB_CHECK_STR(HashHex(2, 32).c_str(),
        "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63");
    BB_CHECK_STR(HashHex(3, 32).c_str(),
        "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f");

    // Границы блока и чанка BLAKE3 — 64 и 1024 байта. Ошибки в буферизации
    // проявляются именно здесь, поэтому вокруг 1024 берутся три длины.
    BB_CHECK_STR(HashHex(1023, 32).c_str(),
        "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11");
    BB_CHECK_STR(HashHex(1024, 32).c_str(),
        "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7");
    BB_CHECK_STR(HashHex(1025, 32).c_str(),
        "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444");

    // 2049 — больше двух чанков, дерево перестаёт быть тривиальным.
    BB_CHECK_STR(HashHex(2049, 32).c_str(),
        "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030");
}

BB_TEST(blake3_official_vectors_keyed)
{
    BB_CHECK_STR(KeyedHex(0, 32).c_str(),
        "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26");
    BB_CHECK_STR(KeyedHex(1, 32).c_str(),
        "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b");
    BB_CHECK_STR(KeyedHex(2, 32).c_str(),
        "5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a");
    BB_CHECK_STR(KeyedHex(3, 32).c_str(),
        "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9");
    BB_CHECK_STR(KeyedHex(1023, 32).c_str(),
        "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e");
    BB_CHECK_STR(KeyedHex(1024, 32).c_str(),
        "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4");
    BB_CHECK_STR(KeyedHex(1025, 32).c_str(),
        "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69");
    BB_CHECK_STR(KeyedHex(2049, 32).c_str(),
        "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5");
}

// identity_id берёт 32 байта из XOF-потока (§4). Проверяется полный вектор в
// 131 байт: усечение потока в реализации так не спрячется.
BB_TEST(blake3_official_vectors_extended_output)
{
    BB_CHECK_STR(HashHex(0, 131).c_str(),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        "e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a"
        "26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda"
        "7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421"
        "cce14d");

    BB_CHECK_STR(KeyedHex(0, 131).c_str(),
        "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"
        "b18171a2f22a4b94822c701f107153dba24918c4bae4d2945c20ece13387627d"
        "3b73cbf97b797d5e59948c7ef788f54372df45e45e4293c7dc18c1d41144a975"
        "8be58960856be1eabbe22c2653190de560ca3b2ac4aa692a9210694254c371e8"
        "51bc8f");

    BB_CHECK_STR(HashHex(1024, 131).c_str(),
        "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7"
        "1cf8107265ecdaf8505b95d8fcec83a98a6a96ea5109d2c179c47a387ffbb404"
        "756f6eeae7883b446b70ebb144527c2075ab8ab204c0086bb22b7c93d465efc5"
        "7f8d917f0b385c6df265e77003b85102967486ed57db5c5ca170ba441427ed9a"
        "fa684e");
}

// Короткий вывод обязан быть префиксом длинного — иначе identity_id зависел бы
// от того, сколько байт запросили.
BB_TEST(blake3_output_is_prefix_stable)
{
    const std::string short_out = HashHex(64, 16);
    const std::string long_out  = HashHex(64, 128);

    BB_CHECK(!short_out.empty());
    BB_CHECK(!long_out.empty());
    BB_CHECK_EQ(long_out.compare(0, short_out.size(), short_out), 0);
}

// Вся спецификация записана как BLAKE3(a || b || c): несколько Update обязаны
// совпадать с одним по целому буферу. На этом стоит потоковый content_hash,
// который считается по файлу кусками.
BB_TEST(blake3_chunked_update_equals_single_update)
{
    const std::vector<std::uint8_t> input = VectorInput(3000);

    bb::Hash256 whole{};
    BB_CHECK(bb::Blake3Hash(input.data(), input.size(), whole.data(), whole.size()));

    bb::Hash256 pieces{};
    {
        bb::Blake3 hasher;
        std::size_t offset = 0;
        for (std::size_t step : {1u, 63u, 64u, 1u, 1024u, 847u}) {
            hasher.Update(input.data() + offset, step);
            offset += step;
        }
        hasher.Update(input.data() + offset, input.size() - offset);
        BB_CHECK(hasher.Finish(pieces));
    }

    BB_CHECK_EQ(std::memcmp(whole.data(), pieces.data(), whole.size()), 0);
}

BB_TEST(blake3_keyed_differs_from_unkeyed)
{
    const std::vector<std::uint8_t> input = VectorInput(100);

    bb::Hash256 plain{};
    bb::Hash256 keyed{};
    BB_CHECK(bb::Blake3Hash(input.data(), input.size(), plain.data(), plain.size()));
    BB_CHECK(bb::Blake3KeyedHash(VectorKey(), input.data(), input.size(),
                                 keyed.data(), keyed.size()));

    BB_CHECK(std::memcmp(plain.data(), keyed.data(), plain.size()) != 0);
}

// Разные ключи дают разные результаты: file_instance_id по k_instance и file_id
// по k_fileid не должны совпасть при одинаковом входе (§6).
BB_TEST(blake3_keyed_separates_by_key)
{
    bb::Blake3Key first = VectorKey();
    bb::Blake3Key second = first;
    second[31] ^= 0x01;

    const std::string data = "bbk/1/instanceDocuments/report.txt";

    bb::Hash256 a{};
    bb::Hash256 b{};
    BB_CHECK(bb::Blake3KeyedHash(first, data.data(), data.size(), a.data(), a.size()));
    BB_CHECK(bb::Blake3KeyedHash(second, data.data(), data.size(), b.data(), b.size()));

    BB_CHECK(std::memcmp(a.data(), b.data(), a.size()) != 0);
}

// Merkle-узлы различаются доменным байтом: BLAKE3(0x00 || core) для листа и
// BLAKE3(0x01 || left || right) для внутреннего (§11). Без разделения лист из
// 64 байт был бы неотличим от внутреннего узла.
BB_TEST(blake3_merkle_domain_bytes_separate)
{
    std::vector<std::uint8_t> body(64, 0xAB);

    bb::Hash256 leaf{};
    {
        bb::Blake3 hasher;
        hasher.UpdateU8(0x00);
        hasher.Update(body.data(), body.size());
        BB_CHECK(hasher.Finish(leaf));
    }

    bb::Hash256 internal{};
    {
        bb::Blake3 hasher;
        hasher.UpdateU8(0x01);
        hasher.Update(body.data(), body.size());
        BB_CHECK(hasher.Finish(internal));
    }

    BB_CHECK(std::memcmp(leaf.data(), internal.data(), leaf.size()) != 0);
}

BB_TEST(blake3_cannot_finish_twice)
{
    bb::Hash256 out{};
    bb::Blake3  hasher;
    hasher.Update(std::string_view("x"));
    BB_CHECK(hasher.Finish(out));
    BB_CHECK(!hasher.Finish(out));
}

BB_TEST(blake3_rejects_null_input_and_zero_output)
{
    bb::Hash256 out{};

    {
        bb::Blake3 hasher;
        hasher.Update(nullptr, 16);
        BB_CHECK(!hasher.Finish(out));
    }

    // Нулевая длина без данных — не ошибка: BLAKE3 пустого входа определён.
    {
        bb::Blake3 hasher;
        hasher.Update(nullptr, 0);
        BB_CHECK(hasher.Finish(out));
        BB_CHECK_STR(bb::test::Hex(out.data(), out.size()).c_str(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    }

    {
        bb::Blake3 hasher;
        BB_CHECK(!hasher.Finish(out.data(), 0));
    }
}
