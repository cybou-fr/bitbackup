// Деривация identity — ARCHITECTURE.md §4.
//
// Про происхождение ожидаемых значений, потому что оно разное:
//
//   k_fileid, k_filekey, k_instance, ikm_sig и pk_x25519 посчитаны независимой
//   реализацией §4 (Python: hashlib.pbkdf2_hmac, hashlib.shake_256,
//   cryptography.x25519) — не выводом этого кода. Совпадение означает, что
//   реализована спецификация, а не то, что код воспроизводит сам себя.
//
//   identity_id так проверить нельзя: в него входит публичный ключ ML-KEM-1024,
//   а второй реализации ML-KEM под рукой нет. Значение зафиксировано выводом
//   этого кода один раз и дальше не пересчитывается — оно ловит регрессию, но
//   не доказывает соответствие спецификации. Детерминированность самой
//   генерации ML-KEM из seed проверена отдельно, векторами FIPS 203.
//
// Исходная мнемоника — вектор Trezor на 24 слова с нулевой энтропией.

#include "Testing.h"

#include "bbcore/bbcore.h"
#include "identity/Identity.h"
#include "util/Bip39.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

const char* const kMnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon art";

std::string HexOf(const bb::IdentityKey& key)
{
    return bb::test::Hex(key.data(), key.size());
}

}  // namespace

BB_TEST(identity_derivation_matches_independent_implementation)
{
    bb::Identity identity;
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 0, identity));
    BB_CHECK(identity.IsValid());
    BB_CHECK(identity.HasPrivateKey());

    BB_CHECK_STR(HexOf(identity.KeyFileId()).c_str(),
        "ec9687e886f2522d7537a77e55589e224e2909ed87444811984646d1d57a3f76");
    BB_CHECK_STR(HexOf(identity.KeyFileKey()).c_str(),
        "23c73b1d23af42f9a4f9a1406431f4a254914013111bf6f17e2257ecce64d2a7");
    BB_CHECK_STR(HexOf(identity.KeyInstance()).c_str(),
        "d197f3719e6e75daaffad0b7d8a43939b92b0f10e5c298f2b6539d1f773abb48");
    BB_CHECK_STR(HexOf(identity.SigningSeed()).c_str(),
        "f5c3de85959c2ecedd3516313b97cdb626856d8ff1e9a1fdef34888dc2409b03");
}

// Индекс входит в identity_root, поэтому у index = 1 обязан быть свой полный
// набор ключей, а не сдвинутый вариант нулевого.
BB_TEST(identity_index_one_matches_independent_implementation)
{
    bb::Identity identity;
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 1, identity));

    BB_CHECK_STR(HexOf(identity.KeyFileId()).c_str(),
        "9447d952d7e5d3bb376085571666663c959a900627d85d05c915717135b4330f");
    BB_CHECK_STR(HexOf(identity.KeyFileKey()).c_str(),
        "4e5c116ba5661fcc5763890fd71c38ef795c0d3bc85c48d9909e4f598c69207c");
    BB_CHECK_STR(HexOf(identity.KeyInstance()).c_str(),
        "866e4b372ef22a34068e7a44a44e0ac3bfda320c4771ed4ed9204c69673fdaec");
    BB_CHECK_STR(HexOf(identity.SigningSeed()).c_str(),
        "36fbb0e00979be9d55274fa4e8a581770f8e71b6847b54a1a4020da07820a999");
}

// §4: X25519 берёт ПОСЛЕДНИЕ 32 байта ikm_kem, а ML-KEM — первые 64. Взять
// байты 64..96 было бы естественной ошибкой, и вектор её ловит.
BB_TEST(identity_x25519_public_key_matches_independent_implementation)
{
    bb::Identity identity;
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 0, identity));

    bb::X25519PublicKey pk{};
    BB_CHECK(identity.Classic().ExportPublicKey(pk));
    BB_CHECK_STR(bb::test::Hex(pk.data(), pk.size()).c_str(),
        "fcae8e14acf73c35abfb75e3f48b8ac4054fdbd8b741e2965abc545796ce7b78");
}

// Зафиксированный вывод этого кода. Меняться не должен никогда: смена
// identity_id означает, что все ранее залитые чанки перестали адресоваться.
BB_TEST(identity_id_is_frozen)
{
    bb::Identity identity;
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 0, identity));

    BB_CHECK_STR(bb::test::Hex(identity.Id().data(), identity.Id().size()).c_str(),
        "ac17c92f17a2d5d07eee0d2ccde9b15994311df2f7ae4c34d9984cc3fb4dd1a9");
}

BB_TEST(identity_is_deterministic_across_openings)
{
    bb::Identity first;
    bb::Identity second;
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 0, first));
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 0, second));

    BB_CHECK_EQ(std::memcmp(first.Id().data(), second.Id().data(), first.Id().size()), 0);

    // Ключевые пары тоже, иначе имена объектов разъедутся между запусками.
    bb::MlKemPublicKey a{};
    bb::MlKemPublicKey b{};
    BB_CHECK(first.Kem().ExportPublicKey(a));
    BB_CHECK(second.Kem().ExportPublicKey(b));
    BB_CHECK_EQ(std::memcmp(a.data(), b.data(), a.size()), 0);
}

// Хранилище не должно уметь связать две identity одного человека (§4).
BB_TEST(identity_indices_are_independent)
{
    bb::Identity zero;
    bb::Identity one;
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 0, zero));
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 1, one));

    BB_CHECK(std::memcmp(zero.Id().data(), one.Id().data(), zero.Id().size()) != 0);
    BB_CHECK(std::memcmp(zero.KeyFileId().data(), one.KeyFileId().data(),
                         zero.KeyFileId().size()) != 0);
}

BB_TEST(identity_passphrase_selects_a_different_identity)
{
    bb::Identity plain;
    bb::Identity guarded;
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 0, plain));
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "correct horse", 0, guarded));

    BB_CHECK(std::memcmp(plain.Id().data(), guarded.Id().data(), plain.Id().size()) != 0);
}

BB_TEST(identity_rejects_invalid_mnemonic)
{
    bb::Identity identity;

    BB_CHECK(!bb::Identity::FromMnemonic("", "", 0, identity));
    BB_CHECK(!bb::Identity::FromMnemonic("abandon abandon abandon", "", 0, identity));
    BB_CHECK(!bb::Identity::FromMnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon zoo",
        "", 0, identity));   // контрольная сумма не сходится

    BB_CHECK(!identity.IsValid());
}

BB_TEST(identity_public_blob_roundtrip)
{
    bb::Identity full;
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 0, full));

    std::size_t needed = 0;
    BB_CHECK(!full.ExportPublicBlob(nullptr, 0, &needed));
    BB_CHECK_EQ(needed, bb::kPublicBlobLen);

    std::vector<std::uint8_t> blob(needed);
    BB_CHECK(full.ExportPublicBlob(blob.data(), blob.size(), &needed));
    BB_CHECK_EQ(needed, bb::kPublicBlobLen);

    bb::Identity received;
    BB_CHECK(bb::Identity::FromPublicBlob(blob.data(), blob.size(), received));

    // Тот же получатель: identity_id выводится из ключей, а не читается из блоба.
    BB_CHECK_EQ(std::memcmp(full.Id().data(), received.Id().data(), full.Id().size()), 0);

    BB_CHECK(received.IsValid());
    BB_CHECK(!received.HasPrivateKey());
    BB_CHECK(full.HasPrivateKey());

    // Публичная identity умеет инкапсулировать, но не вскрывать.
    bb::MlKemCiphertext ct{};
    bb::MlKemShared     shared{};
    BB_CHECK(received.Kem().Encapsulate(ct, shared));
    BB_CHECK(!received.Kem().Decapsulate(ct, shared));
}

BB_TEST(identity_public_blob_rejects_malformed)
{
    bb::Identity full;
    BB_CHECK(bb::Identity::FromMnemonic(kMnemonic, "", 0, full));

    std::vector<std::uint8_t> blob(bb::kPublicBlobLen);
    BB_CHECK(full.ExportPublicBlob(blob.data(), blob.size(), nullptr));

    bb::Identity out;
    BB_CHECK(!bb::Identity::FromPublicBlob(nullptr, blob.size(), out));
    BB_CHECK(!bb::Identity::FromPublicBlob(blob.data(), blob.size() - 1, out));
    BB_CHECK(!bb::Identity::FromPublicBlob(blob.data(), blob.size() + 1, out));

    {
        std::vector<std::uint8_t> bad = blob;
        bad[0] = 'x';                       // magic
        BB_CHECK(!bb::Identity::FromPublicBlob(bad.data(), bad.size(), out));
    }
    {
        std::vector<std::uint8_t> bad = blob;
        bad[6] = 2;                         // версия из будущего
        BB_CHECK(!bb::Identity::FromPublicBlob(bad.data(), bad.size(), out));
    }
    {
        std::vector<std::uint8_t> bad = blob;
        bad[7] = 0x01;                      // заявлен ML-DSA, которого нет
        BB_CHECK(!bb::Identity::FromPublicBlob(bad.data(), bad.size(), out));
    }
    {
        std::vector<std::uint8_t> bad = blob;
        bad[7] = 0x80;                      // неизвестный флаг
        BB_CHECK(!bb::Identity::FromPublicBlob(bad.data(), bad.size(), out));
    }
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

BB_TEST(abi_identity_open_and_describe)
{
    bb_identity* identity = nullptr;
    BB_CHECK_EQ(bb_identity_open(kMnemonic, nullptr, 0, &identity), BB_OK);
    BB_CHECK(identity != nullptr);
    BB_CHECK_EQ(bb_identity_has_private(identity), 1);

    std::uint8_t raw[BB_ID_LEN] = {};
    BB_CHECK_EQ(bb_identity_id(identity, raw), BB_OK);

    char text[BB_ID_B32_LEN + 1] = {};
    BB_CHECK_EQ(bb_identity_id_text(identity, text, sizeof text), BB_OK);
    BB_CHECK_EQ(std::strlen(text), static_cast<std::size_t>(BB_ID_B32_LEN));

    // Текстовая форма обязана быть тем же самым идентификатором.
    std::uint8_t decoded[BB_ID_LEN] = {};
    BB_CHECK_EQ(bb_base32_decode(text, decoded, sizeof decoded, nullptr), BB_OK);
    BB_CHECK_EQ(std::memcmp(raw, decoded, sizeof raw), 0);

    // NULL-парольная фраза эквивалентна пустой.
    bb_identity* same = nullptr;
    BB_CHECK_EQ(bb_identity_open(kMnemonic, "", 0, &same), BB_OK);
    std::uint8_t raw_same[BB_ID_LEN] = {};
    BB_CHECK_EQ(bb_identity_id(same, raw_same), BB_OK);
    BB_CHECK_EQ(std::memcmp(raw, raw_same, sizeof raw), 0);

    bb_identity_free(same);
    bb_identity_free(identity);
    bb_identity_free(nullptr);   // должно быть безопасно
}

BB_TEST(abi_identity_open_reports_bad_mnemonic)
{
    bb_identity* identity = reinterpret_cast<bb_identity*>(1);

    BB_CHECK_EQ(bb_identity_open("not a mnemonic", nullptr, 0, &identity),
                BB_ERR_BAD_MNEMONIC);
    BB_CHECK(identity == nullptr);

    BB_CHECK_EQ(bb_identity_open(nullptr, nullptr, 0, &identity), BB_ERR_INVALID_ARG);
    BB_CHECK_EQ(bb_identity_open(kMnemonic, nullptr, 0, nullptr), BB_ERR_INVALID_ARG);
}

BB_TEST(abi_mnemonic_new_and_validate)
{
    char        buffer[256] = {};
    std::size_t len         = 0;

    BB_CHECK_EQ(bb_mnemonic_new(24, buffer, sizeof buffer, &len), BB_OK);
    BB_CHECK(len > 1 && len <= sizeof buffer);
    BB_CHECK_EQ(std::strlen(buffer) + 1, len);
    BB_CHECK_EQ(bb_mnemonic_validate(buffer), BB_OK);

    BB_CHECK_EQ(bb_mnemonic_new(13, buffer, sizeof buffer, &len), BB_ERR_INVALID_ARG);

    // Требуемый размер сообщается, даже когда буфер мал.
    char small[4] = {};
    len = 0;
    BB_CHECK_EQ(bb_mnemonic_new(12, small, sizeof small, &len), BB_ERR_BUFFER_TOO_SMALL);
    BB_CHECK(len > sizeof small);

    BB_CHECK_EQ(bb_mnemonic_validate("zoo zoo zoo"), BB_ERR_BAD_MNEMONIC);
    BB_CHECK_EQ(bb_mnemonic_validate(nullptr), BB_ERR_INVALID_ARG);
}

BB_TEST(abi_identity_export_and_open_public)
{
    bb_identity* full = nullptr;
    BB_CHECK_EQ(bb_identity_open(kMnemonic, nullptr, 0, &full), BB_OK);

    std::size_t needed = 0;
    BB_CHECK_EQ(bb_identity_export_public(full, nullptr, 0, &needed),
                BB_ERR_BUFFER_TOO_SMALL);
    BB_CHECK_EQ(needed, bb::kPublicBlobLen);

    std::vector<std::uint8_t> blob(needed);
    BB_CHECK_EQ(bb_identity_export_public(full, blob.data(), blob.size(), &needed), BB_OK);

    bb_identity* received = nullptr;
    BB_CHECK_EQ(bb_identity_open_public(blob.data(), blob.size(), &received), BB_OK);
    BB_CHECK_EQ(bb_identity_has_private(received), 0);

    std::uint8_t id_full[BB_ID_LEN] = {};
    std::uint8_t id_recv[BB_ID_LEN] = {};
    BB_CHECK_EQ(bb_identity_id(full, id_full), BB_OK);
    BB_CHECK_EQ(bb_identity_id(received, id_recv), BB_OK);
    BB_CHECK_EQ(std::memcmp(id_full, id_recv, BB_ID_LEN), 0);

    blob[6] = 9;
    bb_identity* rejected = nullptr;
    BB_CHECK_EQ(bb_identity_open_public(blob.data(), blob.size(), &rejected),
                BB_ERR_UNSUPPORTED);
    BB_CHECK(rejected == nullptr);

    bb_identity_free(received);
    bb_identity_free(full);
}
