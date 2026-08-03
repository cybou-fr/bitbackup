// Ключевое расписание от K_file — §5, §6, §9, §14.
//
// Все ожидаемые значения посчитаны независимой реализацией на Python
// (hashlib.shake_256): деривации целиком сводятся к SHAKE, вторая реализация
// возможна, и совпадение означает, что реализована спецификация.
//
// K_file в векторах — байты (11 * 61 + i * 7) mod 256, тот же Fill, что в
// тестах гибридного envelope.

#include "Testing.h"

#include "core/KeySchedule.h"

#include <cstring>
#include <string>

namespace {

template <typename Array>
Array Field(std::uint8_t tag)
{
    Array value{};
    for (std::size_t i = 0; i < value.size(); ++i) {
        value[i] = static_cast<std::uint8_t>((tag * 61 + i * 7) & 0xFF);
    }
    return value;
}

bb::FileKey TestFileKey()
{
    return Field<bb::FileKey>(11);
}

std::string NameHex(std::uint32_t index)
{
    bb::ObjectName name{};
    if (!bb::DeriveObjectName(TestFileKey(), index, name)) {
        return std::string();
    }
    return bb::test::Hex(name.data(), name.size());
}

}  // namespace

BB_TEST(key_schedule_file_key_matches_independent_implementation)
{
    const bb::Hash256 k_filekey = Field<bb::Hash256>(3);
    const bb::Hash256 file_id   = Field<bb::Hash256>(4);

    bb::FileKey k_file{};
    BB_CHECK(bb::DeriveFileKey(k_filekey, file_id, k_file));
    BB_CHECK_STR(bb::test::Hex(k_file.data(), k_file.size()).c_str(),
        "2b1d2266db3a718c8c0240691c1f9462d7d2e61e1d7905247e4cf6bacffc92d3");
}

BB_TEST(key_schedule_object_names_match_independent_implementation)
{
    BB_CHECK_STR(NameHex(0).c_str(),
        "951cbcae78aca3bef320a79777b539c678f2404bd1faedc248ce8ab736f413c0");
    BB_CHECK_STR(NameHex(1).c_str(),
        "98cb57048d27179d653bb3fa7b891baceec6183f184fbda288d613d51bfb6e61");
    BB_CHECK_STR(NameHex(7).c_str(),
        "ef8687cc9a5af058be48404818ccc4733db4cbbfffdde9ffc25a243e24631122");
    BB_CHECK_STR(NameHex(8).c_str(),
        "8de79b8ba2a01ec0a630e1c02499b9d355e5842a4fcb20e213a6e44416690ed3");
    BB_CHECK_STR(NameHex(12345).c_str(),
        "73f35ad882e32f37f1083f45b86bb07af88bf9d45434d69c2de852cb2f342e57");
}

BB_TEST(key_schedule_shard_keys_match_independent_implementation)
{
    struct Case {
        std::uint32_t stripe;
        std::uint16_t position;
        const char*   key_hex;
        const char*   nonce_hex;
    };

    const Case cases[] = {
        {0, 0,
         "7bf90275bdcbf302470f73f4f0520c6c6a1a85261a3647e9febd07744a7ebfa2",
         "000258c5b38f33e1bc785005"},
        {0, 7,
         "da22a96a0239d3c021add10ed61658e6f299931ee5e9999c7e3d1c7d9dfd3d1d",
         "885ac7b27fb5eb2b72434417"},
        {3, 10,
         "5119815f77de9ecf83312b8a1b6b770c426b5494000fe72b4934474fd21438bd",
         "730ad5aedffa22de1283eb03"},
        {700, 2,
         "a0f9aa8e4183779258c6611fc1cd48df57a8dff508a2c0f5827cec9deac5bf94",
         "cf40087cae033b5378966b36"},
    };

    for (const Case& c : cases) {
        bb::AeadKey   key{};
        bb::AeadNonce nonce{};
        BB_CHECK(bb::DeriveShardKey(TestFileKey(), c.stripe, c.position, key, nonce));
        BB_CHECK_STR(bb::test::Hex(key.data(), key.size()).c_str(), c.key_hex);
        BB_CHECK_STR(bb::test::Hex(nonce.data(), nonce.size()).c_str(), c.nonce_hex);
    }
}

BB_TEST(key_schedule_metadata_keys_match_independent_implementation)
{
    bb::AeadKey   key{};
    bb::AeadNonce nonce{};

    BB_CHECK(bb::DeriveMetadataKey(TestFileKey(), 0, key, nonce));
    BB_CHECK_STR(bb::test::Hex(key.data(), key.size()).c_str(),
        "038a5e57c9572c867024442c40256c0ed615b1e23837e9b48b8feee61b545248");
    BB_CHECK_STR(bb::test::Hex(nonce.data(), nonce.size()).c_str(),
        "3d04a632379069d54996b052");

    BB_CHECK(bb::DeriveMetadataKey(TestFileKey(), 5, key, nonce));
    BB_CHECK_STR(bb::test::Hex(key.data(), key.size()).c_str(),
        "0cb4a62f37745697727d1787d76934c2e083f20070a118d96ac2417678faa6c1");
    BB_CHECK_STR(bb::test::Hex(nonce.data(), nonce.size()).c_str(),
        "b7ff82ca68409800992f0da2");
}

// Метки доменного разделения существуют ровно ради этого: один и тот же индекс
// не должен давать одинаковый материал в разных ролях. Совпадение ключа шарда
// с ключом метаданных означало бы шифрование двух разных сообщений одним
// ключом и нонсом.
BB_TEST(key_schedule_roles_never_collide)
{
    const bb::FileKey k_file = TestFileKey();

    bb::AeadKey   shard_key{};
    bb::AeadNonce shard_nonce{};
    bb::AeadKey   meta_key{};
    bb::AeadNonce meta_nonce{};
    bb::ObjectName name{};

    BB_CHECK(bb::DeriveShardKey(k_file, 0, 0, shard_key, shard_nonce));
    BB_CHECK(bb::DeriveMetadataKey(k_file, 0, meta_key, meta_nonce));
    BB_CHECK(bb::DeriveObjectName(k_file, 0, name));

    BB_CHECK(std::memcmp(shard_key.data(), meta_key.data(), shard_key.size()) != 0);
    BB_CHECK(std::memcmp(shard_nonce.data(), meta_nonce.data(), shard_nonce.size()) != 0);
    BB_CHECK(std::memcmp(shard_key.data(), name.data(), shard_key.size()) != 0);
    BB_CHECK(std::memcmp(meta_key.data(), name.data(), meta_key.size()) != 0);
}

// stripe и position входят в деривацию раздельно, поэтому (1, 0) и (0, 1) —
// разные шарды. Склеенный счётчик дал бы коллизию.
BB_TEST(key_schedule_stripe_and_position_are_independent)
{
    const bb::FileKey k_file = TestFileKey();

    bb::AeadKey   a_key{};
    bb::AeadNonce a_nonce{};
    bb::AeadKey   b_key{};
    bb::AeadNonce b_nonce{};

    BB_CHECK(bb::DeriveShardKey(k_file, 1, 0, a_key, a_nonce));
    BB_CHECK(bb::DeriveShardKey(k_file, 0, 1, b_key, b_nonce));
    BB_CHECK(std::memcmp(a_key.data(), b_key.data(), a_key.size()) != 0);

    // И соседние позиции внутри stripe тоже независимы.
    BB_CHECK(bb::DeriveShardKey(k_file, 5, 3, a_key, a_nonce));
    BB_CHECK(bb::DeriveShardKey(k_file, 5, 4, b_key, b_nonce));
    BB_CHECK(std::memcmp(a_key.data(), b_key.data(), a_key.size()) != 0);
    BB_CHECK(std::memcmp(a_nonce.data(), b_nonce.data(), a_nonce.size()) != 0);
}

// Разные файлы — разные имена объектов при том же индексе, иначе хранилище
// увидело бы, что два файла лежат «в одних и тех же ячейках».
BB_TEST(key_schedule_different_file_keys_give_different_names)
{
    bb::FileKey other = TestFileKey();
    other[0] ^= 0x01;

    bb::ObjectName a{};
    bb::ObjectName b{};
    BB_CHECK(bb::DeriveObjectName(TestFileKey(), 42, a));
    BB_CHECK(bb::DeriveObjectName(other, 42, b));

    BB_CHECK(std::memcmp(a.data(), b.data(), a.size()) != 0);
}
