// ML-KEM-1024 (FIPS 203) через OpenSSL 3.5+.
//
// Ключевое требование bbk/1 — детерминированная генерация ключевой пары из
// 64-байтового seed: identity выводится из мнемоники, и та же мнемоника на
// любой машине обязана дать те же ключи. См. ARCHITECTURE.md §4.

#ifndef BBCORE_CRYPTO_KEM_H
#define BBCORE_CRYPTO_KEM_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace bb {

/// Размеры ML-KEM-1024, FIPS 203, таблица 3.
inline constexpr std::size_t kMlKemPublicKeyLen  = 1568;
inline constexpr std::size_t kMlKemSecretKeyLen  = 3168;
inline constexpr std::size_t kMlKemCiphertextLen = 1568;
inline constexpr std::size_t kMlKemSharedLen     = 32;
inline constexpr std::size_t kMlKemSeedLen       = 64;  // d || z

using MlKemPublicKey  = std::array<std::uint8_t, kMlKemPublicKeyLen>;
using MlKemCiphertext = std::array<std::uint8_t, kMlKemCiphertextLen>;
using MlKemShared     = std::array<std::uint8_t, kMlKemSharedLen>;
using MlKemSeed       = std::array<std::uint8_t, kMlKemSeedLen>;

/// Владеющая обёртка над EVP_PKEY. Приватный ключ затирается в деструкторе.
class MlKemKeyPair {
public:
    MlKemKeyPair() = default;
    ~MlKemKeyPair();

    MlKemKeyPair(const MlKemKeyPair&)            = delete;
    MlKemKeyPair& operator=(const MlKemKeyPair&) = delete;
    MlKemKeyPair(MlKemKeyPair&& other) noexcept;
    MlKemKeyPair& operator=(MlKemKeyPair&& other) noexcept;

    /// Детерминированная генерация из seed. Одинаковый seed — одинаковые ключи.
    static bool FromSeed(const MlKemSeed& seed, MlKemKeyPair& out);

    /// Импорт только публичного ключа — для адресации файлов чужой identity.
    static bool FromPublicKey(const MlKemPublicKey& pk, MlKemKeyPair& out);

    bool ExportPublicKey(MlKemPublicKey& out) const;

    /// Инкапсуляция к этому публичному ключу. Приватный ключ не нужен.
    bool Encapsulate(MlKemCiphertext& out_ct, MlKemShared& out_shared) const;

    /// Декапсуляция. Требует приватного ключа.
    ///
    /// ML-KEM по построению не различает «повреждённый ciphertext» и
    /// «чужой ciphertext»: при неудаче возвращается псевдослучайный секрет,
    /// а не ошибка. Это implicit rejection из FIPS 203, и полагаться на код
    /// возврата для проверки подлинности нельзя — её даёт AEAD уровнем выше.
    bool Decapsulate(const MlKemCiphertext& ct, MlKemShared& out_shared) const;

    bool HasPrivateKey() const { return has_private_; }
    bool IsValid() const { return pkey_ != nullptr; }

private:
    void Reset();

    void* pkey_       = nullptr;   // EVP_PKEY*, скрыт чтобы не тащить openssl в заголовок
    bool  has_private_ = false;
};

}  // namespace bb

#endif  // BBCORE_CRYPTO_KEM_H
