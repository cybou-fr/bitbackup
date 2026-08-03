// Гибридная инкапсуляция ключа файла — ARCHITECTURE.md §15.
//
// Каждый чанк несёт собственный envelope, чтобы открываться независимо от
// остальных. Внутри — свежая encapsulation ML-KEM-1024, свежая эфемерная пара
// X25519 и обёрнутый ими блок K_file || file_id.
//
// ВНИМАНИЕ. Combiner ниже — НЕ стандартизованная конструкция. X-Wing определён
// для ML-KEM-768 и к suite 1 неприменим. Обосновывать эту схему сходством с
// чем-либо нельзя; она задана побайтово, закрыта golden-векторами и подлежит
// отдельному аудиту до первого стабильного релиза (§15).
//
//   encode(x) = u32be(len(x)) || x
//
//   transcript = encode("bbk/1/kem")
//             || u16be(format_version) || u16be(suite_id)
//             || encode(identity_id) || encode(pk_mlkem) || encode(pk_x25519)
//             || encode(ct_mlkem)    || encode(epk_x25519)
//
//   K_env = SHAKE256(encode(ss_mlkem) || encode(ss_x25519) || transcript, 32)
//
// Combiner связывает не только общие секреты, но и ciphertext'ы с публичными
// ключами получателя: без этого гибрид не наследовал бы стойкость сильнейшей
// из двух схем.
//
// Нонс обёртки спецификацией не задан — ни §15, ни §16 его не определяют.
// Здесь он берётся продолжением того же XOF:
//
//   K_env || N_env = SHAKE256(тот же вход, 44)
//
// K_env при этом побайтово тот же, что в §15: короткий вывод SHAKE является
// префиксом длинного. Согласуется с §9 и §14, где ключ и нонс тоже выводятся
// из одного источника, и снимает вопрос о повторе нонса. Дополнение к
// спецификации, которое аудит обязан рассмотреть отдельно.

#ifndef BBCORE_CRYPTO_HYBRIDKEM_H
#define BBCORE_CRYPTO_HYBRIDKEM_H

#include "bbcore/bbcore.h"

#include "crypto/Aead.h"
#include "crypto/Hash.h"
#include "crypto/Kem.h"
#include "crypto/X25519.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace bb {

inline constexpr std::size_t kFileKeyLen = 32;

/// Открытый текст обёртки: K_file (32) || file_id (32).
inline constexpr std::size_t kEnvelopeSecretLen = kFileKeyLen + kHashLen;

/// Он же после AEAD — 80 байт, как в раскладке чанка §16.
inline constexpr std::size_t kEnvelopeWrappedLen = kEnvelopeSecretLen + kAeadTagLen;

using FileKey         = std::array<std::uint8_t, kFileKeyLen>;
using EnvelopeWrapped = std::array<std::uint8_t, kEnvelopeWrappedLen>;

struct HybridEnvelope {
    MlKemCiphertext ct_mlkem{};
    X25519PublicKey epk_x25519{};
    EnvelopeWrapped wrapped{};
};

/// Combiner §15 в чистом виде, вместе с выводом нонса.
///
/// Вынесен в интерфейс намеренно: конструкция собственная, и зафиксировать её
/// golden-вектором надо напрямую, а не через encapsulation со свежей
/// случайностью, результат которой каждый раз новый.
bool HybridCombine(const MlKemShared&     ss_mlkem,
                   const X25519Shared&    ss_x25519,
                   const Hash256&         identity_id,
                   std::uint16_t          suite_id,
                   const MlKemPublicKey&  pk_mlkem,
                   const X25519PublicKey& pk_x25519,
                   const MlKemCiphertext& ct_mlkem,
                   const X25519PublicKey& epk_x25519,
                   AeadKey&               out_key,
                   AeadNonce&             out_nonce);

/// Запечатать K_file и file_id для получателя. Приватные ключи не нужны:
/// адресовать чанк можно и чужой identity, открытой из публичного блоба (§26).
///
/// Каждый вызов делает новую независимую encapsulation, поэтому два чанка
/// одного файла не связываются между собой одинаковым envelope.
bb_status HybridSeal(const MlKemKeyPair&  recipient_kem,
                     const X25519KeyPair& recipient_classic,
                     const Hash256&       recipient_identity_id,
                     std::uint16_t        suite_id,
                     const FileKey&       k_file,
                     const Hash256&       file_id,
                     HybridEnvelope&      out);

/// Вскрыть envelope своими приватными ключами.
///
/// suite_id и header_identity_id берутся из public header чанка (§16) и
/// проверяются до всякой криптографии: они и определяют, наш ли это чанк
/// и умеем ли мы его формат.
///
///   BB_ERR_UNSUPPORTED      неизвестный suite
///   BB_ERR_WRONG_IDENTITY   чанк адресован не нам
///   BB_ERR_DECRYPT_FAILED   всё остальное
///
/// Последний код намеренно один на все криптографические отказы. Повреждённый
/// ct_mlkem, повреждённый epk_x25519, точка малого порядка и чужой ключ обязаны
/// выглядеть одинаково: различие дало бы оракул, отличающий сломанную
/// классическую половину гибрида от сломанной post-quantum (§15).
bb_status HybridOpen(const MlKemKeyPair&   self_kem,
                     const X25519KeyPair&  self_classic,
                     const Hash256&        self_identity_id,
                     std::uint16_t         suite_id,
                     const std::uint8_t*   header_identity_id,
                     const HybridEnvelope& envelope,
                     FileKey&              out_k_file,
                     Hash256&              out_file_id);

}  // namespace bb

#endif  // BBCORE_CRYPTO_HYBRIDKEM_H
