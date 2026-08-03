// AES-256-GCM-SIV (RFC 8452) — единственный шифр bbk/1.
//
// Применяется в трёх местах, и везде ключ уникален:
//
//   shard core   K_shard, N_shard из K_file, stripe и position (§9)
//   метаданные   K_meta,  N_meta  из K_file и индекса чанка   (§14)
//   K_file       обёртка внутри гибридного envelope           (§15)
//
// Почему SIV, а не обычный GCM. Пара (ключ, nonce) в формате не повторяется
// никогда: ключ у каждого shard свой. GCM-SIV взят запасом прочности на случай
// ошибки в деривации — при повторе nonce он теряет только различимость
// одинаковых сообщений, тогда как обычный GCM отдаёт ключ аутентификации.
//
// AAD обязателен по сигнатуре, а не по договорённости: каждое место формата
// привязывает шифротекст к своей позиции (§9, §14), и молчаливый пропуск AAD
// сделал бы чанки взаимозаменяемыми.
//
// Результат — ciphertext || tag, ровно как shard_core в §9. Отдельного
// заголовка нет: длина шифротекста выводима, а тег всегда последние 16 байт.

#ifndef BBCORE_CRYPTO_AEAD_H
#define BBCORE_CRYPTO_AEAD_H

#include <array>
#include <cstddef>
#include <cstdint>

namespace bb {

inline constexpr std::size_t kAeadKeyLen   = 32;
inline constexpr std::size_t kAeadNonceLen = 12;
inline constexpr std::size_t kAeadTagLen   = 16;

using AeadKey   = std::array<std::uint8_t, kAeadKeyLen>;
using AeadNonce = std::array<std::uint8_t, kAeadNonceLen>;

/// Доступен ли шифр в этой сборке OpenSSL. AES-256-GCM-SIV есть в default
/// provider, но не в FIPS provider (§30) — в FIPS-режиме сборка соберётся, а
/// шифровать не сможет, и узнать об этом лучше при старте.
bool AeadIsAvailable();

/// Шифрование. out получает ciphertext || tag, то есть plain_len + 16 байт.
/// Пустой открытый текст допустим: получится один тег.
bool AeadSeal(const AeadKey&   key,
              const AeadNonce& nonce,
              const void*      aad, std::size_t aad_len,
              const void*      plaintext, std::size_t plain_len,
              std::uint8_t*    out, std::size_t out_cap, std::size_t* out_len);

/// Расшифрование. sealed — ciphertext || tag, не короче 16 байт.
///
/// Возвращает false и при неверном теге, и при испорченном AAD, и при чужом
/// ключе — различать эти случаи вызывающему нечем и не нужно.
bool AeadOpen(const AeadKey&      key,
              const AeadNonce&    nonce,
              const void*         aad, std::size_t aad_len,
              const std::uint8_t* sealed, std::size_t sealed_len,
              std::uint8_t*       out, std::size_t out_cap, std::size_t* out_len);

/// Длина запечатанного сообщения для открытого текста в plain_len байт.
inline constexpr std::size_t AeadSealedLen(std::size_t plain_len)
{
    return plain_len + kAeadTagLen;
}

}  // namespace bb

#endif  // BBCORE_CRYPTO_AEAD_H
