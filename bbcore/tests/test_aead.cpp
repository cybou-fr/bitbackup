// Свойства AEAD-обёртки, которых нет в векторах RFC 8452: обнаружение порчи,
// привязка к AAD, поведение на маленьком буфере и отсутствие утечки открытого
// текста при неудачной проверке тега.
//
// Векторы лежат в test_aead_vectors.cpp.

#include "Testing.h"

#include "crypto/Aead.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

bb::AeadKey TestKey(std::uint8_t fill = 0x11)
{
    bb::AeadKey key{};
    key.fill(fill);
    return key;
}

bb::AeadNonce TestNonce(std::uint8_t fill = 0x22)
{
    bb::AeadNonce nonce{};
    nonce.fill(fill);
    return nonce;
}

std::vector<std::uint8_t> Pattern(std::size_t len)
{
    std::vector<std::uint8_t> data(len);
    for (std::size_t i = 0; i < len; ++i) {
        data[i] = static_cast<std::uint8_t>(i * 7 + 3);
    }
    return data;
}

// Полный проход seal → open с одним и тем же AAD.
bool Roundtrip(const std::vector<std::uint8_t>& plain,
               const std::vector<std::uint8_t>& aad,
               std::vector<std::uint8_t>&       sealed)
{
    sealed.assign(bb::AeadSealedLen(plain.size()), 0);
    std::size_t produced = 0;

    if (!bb::AeadSeal(TestKey(), TestNonce(), aad.data(), aad.size(),
                      plain.data(), plain.size(),
                      sealed.data(), sealed.size(), &produced)) {
        return false;
    }
    if (produced != sealed.size()) {
        return false;
    }

    std::vector<std::uint8_t> opened(plain.size());
    if (!bb::AeadOpen(TestKey(), TestNonce(), aad.data(), aad.size(),
                      sealed.data(), sealed.size(),
                      opened.data(), opened.size(), &produced)) {
        return false;
    }

    return produced == plain.size()
        && (plain.empty() || std::memcmp(opened.data(), plain.data(), plain.size()) == 0);
}

}  // namespace

BB_TEST(aead_roundtrip_various_lengths)
{
    const std::vector<std::uint8_t> aad = Pattern(37);

    for (std::size_t len : {std::size_t{0}, std::size_t{1}, std::size_t{15},
                            std::size_t{16}, std::size_t{17}, std::size_t{1024},
                            std::size_t{4096}, std::size_t{65537}}) {
        std::vector<std::uint8_t> sealed;
        BB_CHECK(Roundtrip(Pattern(len), aad, sealed));
        BB_CHECK_EQ(sealed.size(), len + bb::kAeadTagLen);
    }
}

BB_TEST(aead_roundtrip_without_aad)
{
    std::vector<std::uint8_t> sealed;
    BB_CHECK(Roundtrip(Pattern(64), {}, sealed));
}

// Правило проекта: порча ЛЮБОГО единственного байта обязана быть обнаружена.
// Проверяется каждый байт шифротекста и каждый байт тега.
BB_TEST(aead_detects_corruption_of_every_byte)
{
    const std::vector<std::uint8_t> plain = Pattern(96);
    const std::vector<std::uint8_t> aad   = Pattern(20);

    std::vector<std::uint8_t> sealed;
    BB_CHECK(Roundtrip(plain, aad, sealed));

    for (std::size_t i = 0; i < sealed.size(); ++i) {
        std::vector<std::uint8_t> damaged = sealed;
        damaged[i] ^= 0x01;

        std::vector<std::uint8_t> opened(plain.size());
        std::size_t               produced = 0;

        const bool accepted =
            bb::AeadOpen(TestKey(), TestNonce(), aad.data(), aad.size(),
                         damaged.data(), damaged.size(),
                         opened.data(), opened.size(), &produced);
        BB_CHECK(!accepted);
        if (accepted) {
            std::printf("    byte %zu of %zu survived corruption\n", i, sealed.size());
            return;
        }
    }
}

// Ради этого AAD и существует: чанк, переставленный на чужую позицию, не
// должен открываться, даже если ключ угадан (§9).
BB_TEST(aead_binds_ciphertext_to_aad)
{
    const std::vector<std::uint8_t> plain = Pattern(48);
    const std::vector<std::uint8_t> aad   = Pattern(32);

    std::vector<std::uint8_t> sealed;
    BB_CHECK(Roundtrip(plain, aad, sealed));

    std::vector<std::uint8_t> other = aad;
    other[31] ^= 0x01;

    std::vector<std::uint8_t> opened(plain.size());
    std::size_t               produced = 0;

    BB_CHECK(!bb::AeadOpen(TestKey(), TestNonce(), other.data(), other.size(),
                           sealed.data(), sealed.size(),
                           opened.data(), opened.size(), &produced));

    // Пустой AAD вместо непустого — тоже подмена.
    BB_CHECK(!bb::AeadOpen(TestKey(), TestNonce(), nullptr, 0,
                           sealed.data(), sealed.size(),
                           opened.data(), opened.size(), &produced));

    // Тот же AAD, укороченный на байт.
    BB_CHECK(!bb::AeadOpen(TestKey(), TestNonce(), aad.data(), aad.size() - 1,
                           sealed.data(), sealed.size(),
                           opened.data(), opened.size(), &produced));
}

BB_TEST(aead_rejects_wrong_key_and_nonce)
{
    const std::vector<std::uint8_t> plain = Pattern(64);
    const std::vector<std::uint8_t> aad   = Pattern(16);

    std::vector<std::uint8_t> sealed;
    BB_CHECK(Roundtrip(plain, aad, sealed));

    std::vector<std::uint8_t> opened(plain.size());
    std::size_t               produced = 0;

    BB_CHECK(!bb::AeadOpen(TestKey(0x12), TestNonce(), aad.data(), aad.size(),
                           sealed.data(), sealed.size(),
                           opened.data(), opened.size(), &produced));

    BB_CHECK(!bb::AeadOpen(TestKey(), TestNonce(0x23), aad.data(), aad.size(),
                           sealed.data(), sealed.size(),
                           opened.data(), opened.size(), &produced));
}

// Неаутентифицированный открытый текст не должен покидать функцию ни при
// каких условиях, даже частично расшифрованным.
BB_TEST(aead_does_not_leak_plaintext_on_failure)
{
    const std::vector<std::uint8_t> plain = Pattern(256);
    const std::vector<std::uint8_t> aad   = Pattern(8);

    std::vector<std::uint8_t> sealed;
    BB_CHECK(Roundtrip(plain, aad, sealed));

    sealed[10] ^= 0x80;

    std::vector<std::uint8_t> opened(plain.size(), 0xEE);
    std::size_t               produced = 0;

    BB_CHECK(!bb::AeadOpen(TestKey(), TestNonce(), aad.data(), aad.size(),
                           sealed.data(), sealed.size(),
                           opened.data(), opened.size(), &produced));

    for (std::uint8_t byte : opened) {
        BB_CHECK_EQ(static_cast<int>(byte), 0);
    }
}

// SIV детерминирован: те же ключ, nonce, AAD и открытый текст дают тот же
// шифротекст. Ровно на это опирается пропуск уже загруженных чанков (§24).
BB_TEST(aead_is_deterministic)
{
    const std::vector<std::uint8_t> plain = Pattern(100);
    const std::vector<std::uint8_t> aad   = Pattern(24);

    std::vector<std::uint8_t> first;
    std::vector<std::uint8_t> second;
    BB_CHECK(Roundtrip(plain, aad, first));
    BB_CHECK(Roundtrip(plain, aad, second));

    BB_CHECK_EQ(first.size(), second.size());
    BB_CHECK_EQ(std::memcmp(first.data(), second.data(), first.size()), 0);
}

BB_TEST(aead_different_aad_gives_different_ciphertext)
{
    const std::vector<std::uint8_t> plain = Pattern(100);

    std::vector<std::uint8_t> first;
    std::vector<std::uint8_t> second;
    BB_CHECK(Roundtrip(plain, Pattern(24), first));
    BB_CHECK(Roundtrip(plain, Pattern(25), second));

    BB_CHECK(std::memcmp(first.data(), second.data(), first.size()) != 0);
}

BB_TEST(aead_seal_reports_required_size)
{
    const std::vector<std::uint8_t> plain = Pattern(50);
    std::size_t                     needed = 0;

    BB_CHECK(!bb::AeadSeal(TestKey(), TestNonce(), nullptr, 0,
                           plain.data(), plain.size(), nullptr, 0, &needed));
    BB_CHECK_EQ(needed, plain.size() + bb::kAeadTagLen);

    std::vector<std::uint8_t> small(plain.size());
    needed = 0;
    BB_CHECK(!bb::AeadSeal(TestKey(), TestNonce(), nullptr, 0,
                           plain.data(), plain.size(),
                           small.data(), small.size(), &needed));
    BB_CHECK_EQ(needed, plain.size() + bb::kAeadTagLen);
}

BB_TEST(aead_open_rejects_truncated_input)
{
    const std::vector<std::uint8_t> plain = Pattern(32);
    const std::vector<std::uint8_t> aad;

    std::vector<std::uint8_t> sealed;
    BB_CHECK(Roundtrip(plain, aad, sealed));

    std::vector<std::uint8_t> opened(plain.size());
    std::size_t               produced = 0;

    // Короче тега — сообщения нет вовсе.
    for (std::size_t len = 0; len < bb::kAeadTagLen; ++len) {
        BB_CHECK(!bb::AeadOpen(TestKey(), TestNonce(), nullptr, 0,
                               sealed.data(), len,
                               opened.data(), opened.size(), &produced));
    }

    // Обрезано на байт — тег на месте, но не тот.
    BB_CHECK(!bb::AeadOpen(TestKey(), TestNonce(), nullptr, 0,
                           sealed.data(), sealed.size() - 1,
                           opened.data(), opened.size(), &produced));

    BB_CHECK(!bb::AeadOpen(TestKey(), TestNonce(), nullptr, 0,
                           nullptr, sealed.size(),
                           opened.data(), opened.size(), &produced));
}

BB_TEST(aead_open_reports_plaintext_size)
{
    const std::vector<std::uint8_t> plain = Pattern(70);

    std::vector<std::uint8_t> sealed;
    BB_CHECK(Roundtrip(plain, {}, sealed));

    std::size_t needed = 0;
    BB_CHECK(!bb::AeadOpen(TestKey(), TestNonce(), nullptr, 0,
                           sealed.data(), sealed.size(), nullptr, 0, &needed));
    BB_CHECK_EQ(needed, plain.size());
}

BB_TEST(aead_seal_rejects_null_plaintext_with_nonzero_length)
{
    std::vector<std::uint8_t> sealed(bb::AeadSealedLen(16));
    std::size_t               produced = 0;

    BB_CHECK(!bb::AeadSeal(TestKey(), TestNonce(), nullptr, 0,
                           nullptr, 16, sealed.data(), sealed.size(), &produced));

    // А вот пустой открытый текст с nullptr — законный случай: получится тег.
    BB_CHECK(bb::AeadSeal(TestKey(), TestNonce(), nullptr, 0,
                          nullptr, 0, sealed.data(), sealed.size(), &produced));
    BB_CHECK_EQ(produced, bb::kAeadTagLen);
}
