#include "Testing.h"

#include "crypto/X25519.h"

#include <cstring>

namespace {

bb::X25519PrivateKey PrivFilled(std::uint8_t start)
{
    bb::X25519PrivateKey sk{};
    for (std::size_t i = 0; i < sk.size(); ++i) {
        sk[i] = static_cast<std::uint8_t>(start + i);
    }
    return sk;
}

}  // namespace

// RFC 7748 §6.1: Alice и Bob приходят к одному секрету.
BB_TEST(x25519_rfc7748_shared_secret)
{
    const bb::X25519PrivateKey alice_sk = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};

    const bb::X25519PrivateKey bob_sk = {
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb};

    bb::X25519KeyPair alice;
    bb::X25519KeyPair bob;
    BB_CHECK(bb::X25519KeyPair::FromPrivateKey(alice_sk, alice));
    BB_CHECK(bb::X25519KeyPair::FromPrivateKey(bob_sk, bob));

    bb::X25519PublicKey alice_pk{};
    bb::X25519PublicKey bob_pk{};
    BB_CHECK(alice.ExportPublicKey(alice_pk));
    BB_CHECK(bob.ExportPublicKey(bob_pk));

    BB_CHECK_STR(
        bb::test::Hex(alice_pk.data(), alice_pk.size()).c_str(),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    BB_CHECK_STR(
        bb::test::Hex(bob_pk.data(), bob_pk.size()).c_str(),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

    bb::X25519KeyPair alice_pub;
    bb::X25519KeyPair bob_pub;
    BB_CHECK(bb::X25519KeyPair::FromPublicKey(alice_pk, alice_pub));
    BB_CHECK(bb::X25519KeyPair::FromPublicKey(bob_pk, bob_pub));

    bb::X25519Shared s1{};
    bb::X25519Shared s2{};
    BB_CHECK(alice.Agree(bob_pub, s1));
    BB_CHECK(bob.Agree(alice_pub, s2));

    BB_CHECK_STR(
        bb::test::Hex(s1.data(), s1.size()).c_str(),
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    BB_CHECK_EQ(std::memcmp(s1.data(), s2.data(), s1.size()), 0);
}

// Тот же приватный ключ обязан давать тот же публичный: identity выводится
// из мнемоники, а не генерируется.
BB_TEST(x25519_keygen_from_private_is_deterministic)
{
    const bb::X25519PrivateKey sk = PrivFilled(0x31);

    bb::X25519KeyPair a;
    bb::X25519KeyPair b;
    BB_CHECK(bb::X25519KeyPair::FromPrivateKey(sk, a));
    BB_CHECK(bb::X25519KeyPair::FromPrivateKey(sk, b));

    bb::X25519PublicKey pk_a{};
    bb::X25519PublicKey pk_b{};
    BB_CHECK(a.ExportPublicKey(pk_a));
    BB_CHECK(b.ExportPublicKey(pk_b));
    BB_CHECK_EQ(std::memcmp(pk_a.data(), pk_b.data(), pk_a.size()), 0);
}

BB_TEST(x25519_ephemeral_keys_differ)
{
    bb::X25519KeyPair a;
    bb::X25519KeyPair b;
    BB_CHECK(bb::X25519KeyPair::Generate(a));
    BB_CHECK(bb::X25519KeyPair::Generate(b));

    bb::X25519PublicKey pk_a{};
    bb::X25519PublicKey pk_b{};
    BB_CHECK(a.ExportPublicKey(pk_a));
    BB_CHECK(b.ExportPublicKey(pk_b));
    BB_CHECK(std::memcmp(pk_a.data(), pk_b.data(), pk_a.size()) != 0);
}

// Точки малого порядка обязаны отвергаться, а не давать нулевой секрет,
// который потом молча ушёл бы в combiner.
BB_TEST(x25519_rejects_small_order_points)
{
    bb::X25519KeyPair mine;
    BB_CHECK(bb::X25519KeyPair::FromPrivateKey(PrivFilled(0x09), mine));

    // Точки порядка 1, 2 и 4 из RFC 7748 / известного набора Bernstein.
    const bb::X25519PublicKey small_order[] = {
        {},  // все нули — порядок 1
        {0x01},
        {0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
         0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
         0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
         0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
    };

    for (const bb::X25519PublicKey& pk : small_order) {
        bb::X25519KeyPair peer;
        BB_CHECK(bb::X25519KeyPair::FromPublicKey(pk, peer));

        bb::X25519Shared shared{};
        BB_CHECK(!mine.Agree(peer, shared));
    }
}

BB_TEST(x25519_public_only_cannot_agree)
{
    bb::X25519KeyPair full;
    BB_CHECK(bb::X25519KeyPair::FromPrivateKey(PrivFilled(0x55), full));

    bb::X25519PublicKey pk{};
    BB_CHECK(full.ExportPublicKey(pk));

    bb::X25519KeyPair pub_only;
    BB_CHECK(bb::X25519KeyPair::FromPublicKey(pk, pub_only));
    BB_CHECK(!pub_only.HasPrivateKey());

    bb::X25519Shared shared{};
    BB_CHECK(!pub_only.Agree(full, shared));
}
