// Гибридный envelope — ARCHITECTURE.md §15.
//
// Combiner здесь собственный, не стандартизованный, поэтому проверяется строже
// прочего. Golden-вектор посчитан независимой реализацией §15 на Python
// (hashlib.shake_256): конструкция целиком сводится к SHAKE, вторая реализация
// возможна, и совпадение означает, что реализована спецификация.
//
// Поля вектора заполнены правилом byte_i = (tag * 61 + i * 7) mod 256 с разным
// tag у каждого поля — перестановка двух полей в transcript так обнаружится.
//
// Ниже же лежат семь обязательных негативных векторов из §15. Их номера
// сохранены в именах тестов.

#include "Testing.h"

#include "crypto/HybridKem.h"
#include "crypto/Shake.h"
#include "identity/Identity.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

const char* const kMnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon art";

// Второй словарный вектор Trezor — другая мнемоника, другой человек.
const char* const kOtherMnemonic =
    "legal winner thank year wave sausage worth useful legal winner thank year "
    "wave sausage worth useful legal will";

void Fill(std::uint8_t* data, std::size_t len, std::uint8_t tag)
{
    for (std::size_t i = 0; i < len; ++i) {
        data[i] = static_cast<std::uint8_t>((tag * 61 + i * 7) & 0xFF);
    }
}

template <typename Array>
Array Field(std::uint8_t tag)
{
    Array value{};
    Fill(value.data(), value.size(), tag);
    return value;
}

bool OpenIdentity(const char* mnemonic, std::uint32_t index, bb::Identity& out)
{
    return bb::Identity::FromMnemonic(mnemonic, "", index, out);
}

/// Полный цикл: запечатать для получателя и вскрыть его же ключами.
bb_status SealFor(const bb::Identity& recipient,
                  const bb::FileKey&  k_file,
                  const bb::Hash256&  file_id,
                  bb::HybridEnvelope& out)
{
    return bb::HybridSeal(recipient.Kem(), recipient.Classic(), recipient.Id(),
                          BB_SUITE_ID, k_file, file_id, out);
}

bb_status OpenAs(const bb::Identity&       self,
                 const bb::HybridEnvelope& envelope,
                 bb::FileKey&              out_k_file,
                 bb::Hash256&              out_file_id,
                 std::uint16_t             suite_id = BB_SUITE_ID)
{
    return bb::HybridOpen(self.Kem(), self.Classic(), self.Id(),
                          suite_id, self.Id().data(), envelope,
                          out_k_file, out_file_id);
}

}  // namespace

// ---------------------------------------------------------------------------
// Golden-вектор combiner'а
// ---------------------------------------------------------------------------

BB_TEST(hybrid_combiner_golden_vector)
{
    const bb::MlKemShared     ss_mlkem  = Field<bb::MlKemShared>(1);
    const bb::X25519Shared    ss_x25519 = Field<bb::X25519Shared>(2);
    const bb::Hash256         identity  = Field<bb::Hash256>(3);
    const bb::MlKemPublicKey  pk_mlkem  = Field<bb::MlKemPublicKey>(4);
    const bb::X25519PublicKey pk_x25519 = Field<bb::X25519PublicKey>(5);
    const bb::MlKemCiphertext ct_mlkem  = Field<bb::MlKemCiphertext>(6);
    const bb::X25519PublicKey epk       = Field<bb::X25519PublicKey>(7);

    bb::AeadKey   key{};
    bb::AeadNonce nonce{};
    BB_CHECK(bb::HybridCombine(ss_mlkem, ss_x25519, identity, BB_SUITE_ID,
                               pk_mlkem, pk_x25519, ct_mlkem, epk, key, nonce));

    BB_CHECK_STR(bb::test::Hex(key.data(), key.size()).c_str(),
        "a0467dd348cdd74de4330bca096944806cdf7d8bb48bbb9c89bd7255fbc80d04");
    BB_CHECK_STR(bb::test::Hex(nonce.data(), nonce.size()).c_str(),
        "154d6a56711e8b31f118e25d");
}

// Нонс выводится продолжением того же XOF, и на K_env это влиять не должно:
// короткий вывод SHAKE обязан быть префиксом длинного. Если бы влияло, наше
// дополнение молча изменило бы конструкцию §15.
BB_TEST(hybrid_combiner_key_is_unchanged_by_nonce_extension)
{
    const bb::MlKemShared     ss_mlkem  = Field<bb::MlKemShared>(1);
    const bb::X25519Shared    ss_x25519 = Field<bb::X25519Shared>(2);
    const bb::Hash256         identity  = Field<bb::Hash256>(3);
    const bb::MlKemPublicKey  pk_mlkem  = Field<bb::MlKemPublicKey>(4);
    const bb::X25519PublicKey pk_x25519 = Field<bb::X25519PublicKey>(5);
    const bb::MlKemCiphertext ct_mlkem  = Field<bb::MlKemCiphertext>(6);
    const bb::X25519PublicKey epk       = Field<bb::X25519PublicKey>(7);

    bb::AeadKey   key{};
    bb::AeadNonce nonce{};
    BB_CHECK(bb::HybridCombine(ss_mlkem, ss_x25519, identity, BB_SUITE_ID,
                               pk_mlkem, pk_x25519, ct_mlkem, epk, key, nonce));

    // Ровно та же цепочка, но выдавливается 32 байта, как записано в §15.
    auto encode = [](bb::Shake256& shake, const void* data, std::size_t len) {
        shake.UpdateU32(static_cast<std::uint32_t>(len));
        shake.Update(data, len);
    };

    std::uint8_t spec_key[32];
    {
        bb::Shake256 shake;
        encode(shake, ss_mlkem.data(), ss_mlkem.size());
        encode(shake, ss_x25519.data(), ss_x25519.size());
        encode(shake, "bbk/1/kem", 9);
        shake.UpdateU16(BB_FORMAT_VERSION);
        shake.UpdateU16(BB_SUITE_ID);
        encode(shake, identity.data(), identity.size());
        encode(shake, pk_mlkem.data(), pk_mlkem.size());
        encode(shake, pk_x25519.data(), pk_x25519.size());
        encode(shake, ct_mlkem.data(), ct_mlkem.size());
        encode(shake, epk.data(), epk.size());
        BB_CHECK(shake.Finish(spec_key, sizeof spec_key));
    }

    BB_CHECK_EQ(std::memcmp(key.data(), spec_key, sizeof spec_key), 0);
}

// Каждое поле transcript обязано влиять на результат: поле, выпавшее из
// хеширования, — это ровно та ошибка, ради которой combiner и связывает
// ciphertext'ы с публичными ключами получателя.
BB_TEST(hybrid_combiner_depends_on_every_field)
{
    auto derive = [](std::uint8_t bump) {
        bb::MlKemShared     ss_mlkem  = Field<bb::MlKemShared>(1);
        bb::X25519Shared    ss_x25519 = Field<bb::X25519Shared>(2);
        bb::Hash256         identity  = Field<bb::Hash256>(3);
        bb::MlKemPublicKey  pk_mlkem  = Field<bb::MlKemPublicKey>(4);
        bb::X25519PublicKey pk_x25519 = Field<bb::X25519PublicKey>(5);
        bb::MlKemCiphertext ct_mlkem  = Field<bb::MlKemCiphertext>(6);
        bb::X25519PublicKey epk       = Field<bb::X25519PublicKey>(7);

        switch (bump) {
            case 1: ss_mlkem[0]  ^= 1; break;
            case 2: ss_x25519[0] ^= 1; break;
            case 3: identity[0]  ^= 1; break;
            case 4: pk_mlkem[0]  ^= 1; break;
            case 5: pk_x25519[0] ^= 1; break;
            case 6: ct_mlkem[0]  ^= 1; break;
            case 7: epk[0]       ^= 1; break;
            default: break;
        }

        bb::AeadKey   key{};
        bb::AeadNonce nonce{};
        bb::HybridCombine(ss_mlkem, ss_x25519, identity, BB_SUITE_ID,
                          pk_mlkem, pk_x25519, ct_mlkem, epk, key, nonce);
        return key;
    };

    const bb::AeadKey base = derive(0);
    for (std::uint8_t field = 1; field <= 7; ++field) {
        const bb::AeadKey changed = derive(field);
        BB_CHECK(std::memcmp(base.data(), changed.data(), base.size()) != 0);
    }
}

// ---------------------------------------------------------------------------
// Вектор 1: успешная decapsulation
// ---------------------------------------------------------------------------

BB_TEST(hybrid_vector_1_successful_decapsulation)
{
    bb::Identity self;
    BB_CHECK(OpenIdentity(kMnemonic, 0, self));

    bb::FileKey k_file{};
    bb::Hash256 file_id{};
    Fill(k_file.data(), k_file.size(), 11);
    Fill(file_id.data(), file_id.size(), 12);

    bb::HybridEnvelope envelope;
    BB_CHECK_EQ(SealFor(self, k_file, file_id, envelope), BB_OK);

    bb::FileKey opened_key{};
    bb::Hash256 opened_id{};
    BB_CHECK_EQ(OpenAs(self, envelope, opened_key, opened_id), BB_OK);

    BB_CHECK_EQ(std::memcmp(opened_key.data(), k_file.data(), k_file.size()), 0);
    BB_CHECK_EQ(std::memcmp(opened_id.data(), file_id.data(), file_id.size()), 0);
}

// ---------------------------------------------------------------------------
// Векторы 2 и 3: повреждённый ct_mlkem и повреждённый epk_x25519
//
// §15 требует не просто отказа, а ОДИНАКОВОГО отказа: различие дало бы оракул,
// отличающий сломанную классическую половину гибрида от сломанной post-quantum.
// ---------------------------------------------------------------------------

BB_TEST(hybrid_vectors_2_and_3_corruption_is_indistinguishable)
{
    bb::Identity self;
    BB_CHECK(OpenIdentity(kMnemonic, 0, self));

    bb::FileKey k_file{};
    bb::Hash256 file_id{};
    Fill(k_file.data(), k_file.size(), 11);
    Fill(file_id.data(), file_id.size(), 12);

    bb::HybridEnvelope envelope;
    BB_CHECK_EQ(SealFor(self, k_file, file_id, envelope), BB_OK);

    bb::FileKey opened_key{};
    bb::Hash256 opened_id{};

    bb::HybridEnvelope bad_ct = envelope;
    bad_ct.ct_mlkem[0] ^= 0x01;
    const bb_status ct_status = OpenAs(self, bad_ct, opened_key, opened_id);

    bb::HybridEnvelope bad_epk = envelope;
    bad_epk.epk_x25519[0] ^= 0x01;
    const bb_status epk_status = OpenAs(self, bad_epk, opened_key, opened_id);

    BB_CHECK_EQ(ct_status, BB_ERR_DECRYPT_FAILED);
    BB_CHECK_EQ(epk_status, BB_ERR_DECRYPT_FAILED);
    BB_CHECK_EQ(ct_status, epk_status);

    // Порча самой обёртки — тот же код: три разных способа сломать чанк
    // снаружи неразличимы.
    bb::HybridEnvelope bad_wrapped = envelope;
    bad_wrapped.wrapped[0] ^= 0x01;
    BB_CHECK_EQ(OpenAs(self, bad_wrapped, opened_key, opened_id),
                BB_ERR_DECRYPT_FAILED);
}

// Повреждение ЛЮБОГО байта envelope обязано быть обнаружено. Байтов много,
// поэтому проверяются границы каждого поля и выборка внутри.
BB_TEST(hybrid_detects_corruption_across_the_envelope)
{
    bb::Identity self;
    BB_CHECK(OpenIdentity(kMnemonic, 0, self));

    bb::FileKey k_file{};
    bb::Hash256 file_id{};
    Fill(k_file.data(), k_file.size(), 11);
    Fill(file_id.data(), file_id.size(), 12);

    bb::HybridEnvelope envelope;
    BB_CHECK_EQ(SealFor(self, k_file, file_id, envelope), BB_OK);

    bb::FileKey opened_key{};
    bb::Hash256 opened_id{};

    for (std::size_t i = 0; i < envelope.ct_mlkem.size(); i += 97) {
        bb::HybridEnvelope damaged = envelope;
        damaged.ct_mlkem[i] ^= 0x80;
        BB_CHECK_EQ(OpenAs(self, damaged, opened_key, opened_id),
                    BB_ERR_DECRYPT_FAILED);
    }

    for (std::size_t i = 0; i < envelope.epk_x25519.size(); ++i) {
        bb::HybridEnvelope damaged = envelope;
        damaged.epk_x25519[i] ^= 0x80;
        BB_CHECK_EQ(OpenAs(self, damaged, opened_key, opened_id),
                    BB_ERR_DECRYPT_FAILED);
    }

    for (std::size_t i = 0; i < envelope.wrapped.size(); ++i) {
        bb::HybridEnvelope damaged = envelope;
        damaged.wrapped[i] ^= 0x80;
        BB_CHECK_EQ(OpenAs(self, damaged, opened_key, opened_id),
                    BB_ERR_DECRYPT_FAILED);
    }
}

// ---------------------------------------------------------------------------
// Вектор 4: неверный получатель
// ---------------------------------------------------------------------------

BB_TEST(hybrid_vector_4_wrong_recipient)
{
    bb::Identity sender_view;
    bb::Identity other;
    BB_CHECK(OpenIdentity(kMnemonic, 0, sender_view));
    BB_CHECK(OpenIdentity(kOtherMnemonic, 0, other));

    bb::FileKey k_file{};
    bb::Hash256 file_id{};
    Fill(k_file.data(), k_file.size(), 11);
    Fill(file_id.data(), file_id.size(), 12);

    bb::HybridEnvelope envelope;
    BB_CHECK_EQ(SealFor(sender_view, k_file, file_id, envelope), BB_OK);

    // Чужие ключи, но заголовок подделан под получателя: проверка identity_id
    // пройдена, а криптография — нет.
    bb::FileKey opened_key{};
    bb::Hash256 opened_id{};
    BB_CHECK_EQ(bb::HybridOpen(other.Kem(), other.Classic(), other.Id(),
                               BB_SUITE_ID, other.Id().data(), envelope,
                               opened_key, opened_id),
                BB_ERR_DECRYPT_FAILED);

    // Соседняя identity той же мнемоники — тоже чужая (§4).
    bb::Identity neighbour;
    BB_CHECK(OpenIdentity(kMnemonic, 1, neighbour));
    BB_CHECK_EQ(bb::HybridOpen(neighbour.Kem(), neighbour.Classic(), neighbour.Id(),
                               BB_SUITE_ID, neighbour.Id().data(), envelope,
                               opened_key, opened_id),
                BB_ERR_DECRYPT_FAILED);
}

// ---------------------------------------------------------------------------
// Вектор 5: подменённый suite_id
// ---------------------------------------------------------------------------

BB_TEST(hybrid_vector_5_unknown_suite)
{
    bb::Identity self;
    BB_CHECK(OpenIdentity(kMnemonic, 0, self));

    bb::FileKey k_file{};
    bb::Hash256 file_id{};

    bb::HybridEnvelope envelope;
    BB_CHECK_EQ(SealFor(self, k_file, file_id, envelope), BB_OK);

    bb::FileKey opened_key{};
    bb::Hash256 opened_id{};
    BB_CHECK_EQ(OpenAs(self, envelope, opened_key, opened_id, 2),
                BB_ERR_UNSUPPORTED);
    BB_CHECK_EQ(OpenAs(self, envelope, opened_key, opened_id, 0),
                BB_ERR_UNSUPPORTED);

    // Запечатать в неизвестный suite тоже нельзя.
    BB_CHECK_EQ(bb::HybridSeal(self.Kem(), self.Classic(), self.Id(),
                               2, k_file, file_id, envelope),
                BB_ERR_UNSUPPORTED);
}

// ---------------------------------------------------------------------------
// Вектор 6: подменённый identity_id
// ---------------------------------------------------------------------------

BB_TEST(hybrid_vector_6_wrong_identity_id)
{
    bb::Identity self;
    BB_CHECK(OpenIdentity(kMnemonic, 0, self));

    bb::FileKey k_file{};
    bb::Hash256 file_id{};

    bb::HybridEnvelope envelope;
    BB_CHECK_EQ(SealFor(self, k_file, file_id, envelope), BB_OK);

    bb::Hash256 foreign = self.Id();
    foreign[0] ^= 0x01;

    bb::FileKey opened_key{};
    bb::Hash256 opened_id{};

    // Отдельный код: чанк не повреждён, он просто не наш. Клиенту это нужно
    // отличать, чтобы не пытаться его чинить через Reed–Solomon.
    BB_CHECK_EQ(bb::HybridOpen(self.Kem(), self.Classic(), self.Id(),
                               BB_SUITE_ID, foreign.data(), envelope,
                               opened_key, opened_id),
                BB_ERR_WRONG_IDENTITY);

    // Неизвестный suite важнее чужого identity: сначала формат, потом адресат.
    BB_CHECK_EQ(bb::HybridOpen(self.Kem(), self.Classic(), self.Id(),
                               7, foreign.data(), envelope,
                               opened_key, opened_id),
                BB_ERR_UNSUPPORTED);
}

// ---------------------------------------------------------------------------
// Вектор 7: X25519 с точкой малого порядка
// ---------------------------------------------------------------------------

BB_TEST(hybrid_vector_7_small_order_point)
{
    bb::Identity self;
    BB_CHECK(OpenIdentity(kMnemonic, 0, self));

    bb::FileKey k_file{};
    bb::Hash256 file_id{};

    bb::HybridEnvelope envelope;
    BB_CHECK_EQ(SealFor(self, k_file, file_id, envelope), BB_OK);

    bb::FileKey opened_key{};
    bb::Hash256 opened_id{};

    // Все известные точки малого порядка кривой 25519. Каждая даёт нулевой
    // общий секрет, и принять такой envelope значило бы согласиться на
    // предсказуемый K_env.
    const std::uint8_t kSmallOrder[][32] = {
        {0},
        {1},
        {0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
         0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
         0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
        {0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1,
         0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c,
         0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    };

    for (const auto& point : kSmallOrder) {
        bb::HybridEnvelope degenerate = envelope;
        std::memcpy(degenerate.epk_x25519.data(), point,
                    degenerate.epk_x25519.size());

        // Тот же код, что у повреждённого ciphertext: снаружи вырожденная
        // точка неотличима от порчи, и это правильно.
        BB_CHECK_EQ(OpenAs(self, degenerate, opened_key, opened_id),
                    BB_ERR_DECRYPT_FAILED);
    }
}

// ---------------------------------------------------------------------------
// Свойства
// ---------------------------------------------------------------------------

// Каждый чанк получает свою encapsulation, поэтому два envelope одного и того
// же ключа не совпадают. Именно на этом держится обещание, что хранилище не
// свяжет объекты одного файла (§15).
BB_TEST(hybrid_envelopes_are_never_identical)
{
    bb::Identity self;
    BB_CHECK(OpenIdentity(kMnemonic, 0, self));

    bb::FileKey k_file{};
    bb::Hash256 file_id{};
    Fill(k_file.data(), k_file.size(), 11);
    Fill(file_id.data(), file_id.size(), 12);

    bb::HybridEnvelope first;
    bb::HybridEnvelope second;
    BB_CHECK_EQ(SealFor(self, k_file, file_id, first), BB_OK);
    BB_CHECK_EQ(SealFor(self, k_file, file_id, second), BB_OK);

    BB_CHECK(std::memcmp(first.ct_mlkem.data(), second.ct_mlkem.data(),
                         first.ct_mlkem.size()) != 0);
    BB_CHECK(std::memcmp(first.epk_x25519.data(), second.epk_x25519.data(),
                         first.epk_x25519.size()) != 0);
    BB_CHECK(std::memcmp(first.wrapped.data(), second.wrapped.data(),
                         first.wrapped.size()) != 0);

    // И оба всё равно открываются в один и тот же K_file.
    bb::FileKey key_a{};
    bb::FileKey key_b{};
    bb::Hash256 id_a{};
    bb::Hash256 id_b{};
    BB_CHECK_EQ(OpenAs(self, first, key_a, id_a), BB_OK);
    BB_CHECK_EQ(OpenAs(self, second, key_b, id_b), BB_OK);
    BB_CHECK_EQ(std::memcmp(key_a.data(), key_b.data(), key_a.size()), 0);
}

// Адресовать чанк можно identity, открытой из публичного блоба: приватных
// ключей получателя у отправителя нет и быть не должно (§26).
BB_TEST(hybrid_seals_to_a_public_only_identity)
{
    bb::Identity recipient;
    BB_CHECK(OpenIdentity(kOtherMnemonic, 0, recipient));

    std::vector<std::uint8_t> blob(bb::kPublicBlobLen);
    BB_CHECK(recipient.ExportPublicBlob(blob.data(), blob.size(), nullptr));

    bb::Identity public_only;
    BB_CHECK(bb::Identity::FromPublicBlob(blob.data(), blob.size(), public_only));
    BB_CHECK(!public_only.HasPrivateKey());

    bb::FileKey k_file{};
    bb::Hash256 file_id{};
    Fill(k_file.data(), k_file.size(), 21);
    Fill(file_id.data(), file_id.size(), 22);

    bb::HybridEnvelope envelope;
    BB_CHECK_EQ(SealFor(public_only, k_file, file_id, envelope), BB_OK);

    // Вскрыть может только настоящий владелец приватных ключей.
    bb::FileKey opened_key{};
    bb::Hash256 opened_id{};
    BB_CHECK_EQ(OpenAs(recipient, envelope, opened_key, opened_id), BB_OK);
    BB_CHECK_EQ(std::memcmp(opened_key.data(), k_file.data(), k_file.size()), 0);

    // А публичная identity — не может, и это ошибка вызывающего, не крипто.
    BB_CHECK_EQ(bb::HybridOpen(public_only.Kem(), public_only.Classic(),
                               public_only.Id(), BB_SUITE_ID,
                               public_only.Id().data(), envelope,
                               opened_key, opened_id),
                BB_ERR_INVALID_ARG);
}

// Ключ не должен просочиться наружу при отказе: вызывающий может не проверить
// код возврата, и тогда в буфере обязан лежать ноль, а не мусор из чужого чанка.
BB_TEST(hybrid_wipes_output_on_failure)
{
    bb::Identity self;
    BB_CHECK(OpenIdentity(kMnemonic, 0, self));

    bb::FileKey k_file{};
    bb::Hash256 file_id{};
    Fill(k_file.data(), k_file.size(), 11);
    Fill(file_id.data(), file_id.size(), 12);

    bb::HybridEnvelope envelope;
    BB_CHECK_EQ(SealFor(self, k_file, file_id, envelope), BB_OK);
    envelope.wrapped[5] ^= 0x40;

    bb::FileKey opened_key{};
    bb::Hash256 opened_id{};
    opened_key.fill(0xAA);
    opened_id.fill(0xBB);

    BB_CHECK_EQ(OpenAs(self, envelope, opened_key, opened_id), BB_ERR_DECRYPT_FAILED);

    for (std::uint8_t byte : opened_key) {
        BB_CHECK_EQ(static_cast<int>(byte), 0);
    }
    for (std::uint8_t byte : opened_id) {
        BB_CHECK_EQ(static_cast<int>(byte), 0);
    }
}
