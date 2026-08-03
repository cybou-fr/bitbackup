#include "Testing.h"

#include "crypto/Kem.h"

#include <cstring>

namespace {

bb::MlKemSeed SeedFilled(std::uint8_t start)
{
    bb::MlKemSeed seed{};
    for (std::size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<std::uint8_t>(start + i * 3);
    }
    return seed;
}

}  // namespace

BB_TEST(mlkem_encapsulate_decapsulate_roundtrip)
{
    bb::MlKemKeyPair kp;
    BB_CHECK(bb::MlKemKeyPair::FromSeed(SeedFilled(0x01), kp));
    BB_CHECK(kp.IsValid());
    BB_CHECK(kp.HasPrivateKey());

    bb::MlKemCiphertext ct{};
    bb::MlKemShared     sent{};
    BB_CHECK(kp.Encapsulate(ct, sent));

    bb::MlKemShared received{};
    BB_CHECK(kp.Decapsulate(ct, received));

    BB_CHECK_EQ(std::memcmp(sent.data(), received.data(), sent.size()), 0);
}

// Основание всей схемы identity: та же мнемоника обязана дать те же ключи
// на любой машине. Без этого архив нельзя восстановить после переустановки.
BB_TEST(mlkem_keygen_from_seed_is_deterministic)
{
    const bb::MlKemSeed seed = SeedFilled(0x42);

    bb::MlKemKeyPair a;
    bb::MlKemKeyPair b;
    BB_CHECK(bb::MlKemKeyPair::FromSeed(seed, a));
    BB_CHECK(bb::MlKemKeyPair::FromSeed(seed, b));

    bb::MlKemPublicKey pk_a{};
    bb::MlKemPublicKey pk_b{};
    BB_CHECK(a.ExportPublicKey(pk_a));
    BB_CHECK(b.ExportPublicKey(pk_b));

    BB_CHECK_EQ(std::memcmp(pk_a.data(), pk_b.data(), pk_a.size()), 0);

    // И приватные половины тоже: секрет, инкапсулированный к одной,
    // обязан раскрываться другой.
    bb::MlKemCiphertext ct{};
    bb::MlKemShared     sent{};
    BB_CHECK(a.Encapsulate(ct, sent));

    bb::MlKemShared received{};
    BB_CHECK(b.Decapsulate(ct, received));
    BB_CHECK_EQ(std::memcmp(sent.data(), received.data(), sent.size()), 0);
}

BB_TEST(mlkem_different_seeds_give_different_keys)
{
    bb::MlKemKeyPair a;
    bb::MlKemKeyPair b;
    BB_CHECK(bb::MlKemKeyPair::FromSeed(SeedFilled(0x01), a));
    BB_CHECK(bb::MlKemKeyPair::FromSeed(SeedFilled(0x02), b));

    bb::MlKemPublicKey pk_a{};
    bb::MlKemPublicKey pk_b{};
    BB_CHECK(a.ExportPublicKey(pk_a));
    BB_CHECK(b.ExportPublicKey(pk_b));

    BB_CHECK(std::memcmp(pk_a.data(), pk_b.data(), pk_a.size()) != 0);
}

// Адресация файлов чужой identity: отправитель имеет только публичный ключ.
BB_TEST(mlkem_public_only_key_can_encapsulate_but_not_decapsulate)
{
    bb::MlKemKeyPair full;
    BB_CHECK(bb::MlKemKeyPair::FromSeed(SeedFilled(0x77), full));

    bb::MlKemPublicKey pk{};
    BB_CHECK(full.ExportPublicKey(pk));

    bb::MlKemKeyPair pub_only;
    BB_CHECK(bb::MlKemKeyPair::FromPublicKey(pk, pub_only));
    BB_CHECK(pub_only.IsValid());
    BB_CHECK(!pub_only.HasPrivateKey());

    bb::MlKemCiphertext ct{};
    bb::MlKemShared     sent{};
    BB_CHECK(pub_only.Encapsulate(ct, sent));

    bb::MlKemShared attempt{};
    BB_CHECK(!pub_only.Decapsulate(ct, attempt));

    // А владелец приватного ключа — раскрывает.
    bb::MlKemShared received{};
    BB_CHECK(full.Decapsulate(ct, received));
    BB_CHECK_EQ(std::memcmp(sent.data(), received.data(), sent.size()), 0);
}

// FIPS 203 предписывает implicit rejection: на повреждённом ciphertext
// декапсуляция не падает, а возвращает псевдослучайный секрет. Проверяем
// именно это поведение, чтобы уровнем выше никто не пытался использовать
// код возврата как признак подлинности — её даёт AEAD.
BB_TEST(mlkem_corrupted_ciphertext_yields_different_secret_not_error)
{
    bb::MlKemKeyPair kp;
    BB_CHECK(bb::MlKemKeyPair::FromSeed(SeedFilled(0x11), kp));

    bb::MlKemCiphertext ct{};
    bb::MlKemShared     sent{};
    BB_CHECK(kp.Encapsulate(ct, sent));

    ct[100] = static_cast<std::uint8_t>(ct[100] ^ 0x01);

    bb::MlKemShared received{};
    BB_CHECK(kp.Decapsulate(ct, received));
    BB_CHECK(std::memcmp(sent.data(), received.data(), sent.size()) != 0);
}

BB_TEST(mlkem_sizes_match_fips203)
{
    // FIPS 203, таблица 3. Проверяем на этапе компиляции: эти длины зашиты
    // в формат контейнера, и разъехаться они не имеют права.
    static_assert(bb::kMlKemPublicKeyLen  == 1568, "ML-KEM-1024 ek");
    static_assert(bb::kMlKemCiphertextLen == 1568, "ML-KEM-1024 ct");
    static_assert(bb::kMlKemSharedLen     == 32,   "ML-KEM shared secret");
    static_assert(bb::kMlKemSeedLen       == 64,   "ML-KEM seed d || z");

    bb::MlKemKeyPair kp;
    BB_CHECK(bb::MlKemKeyPair::FromSeed(SeedFilled(0x05), kp));

    bb::MlKemPublicKey pk{};
    BB_CHECK(kp.ExportPublicKey(pk));  // упадёт, если длина не 1568
}
