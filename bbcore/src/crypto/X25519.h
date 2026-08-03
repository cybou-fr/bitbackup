// X25519 (RFC 7748) — классическая половина гибрида bbk/1.
//
// Нужна не «на всякий случай»: ML-KEM молод, и риск не только в криптоанализе
// решёток, но и в ошибке реализации. X25519 стоит 32 байта на чанк и держит
// конфиденциальность, если ML-KEM подведёт. См. ARCHITECTURE.md §15.

#ifndef BBCORE_CRYPTO_X25519_H
#define BBCORE_CRYPTO_X25519_H

#include <array>
#include <cstddef>
#include <cstdint>

namespace bb {

inline constexpr std::size_t kX25519KeyLen    = 32;
inline constexpr std::size_t kX25519SharedLen = 32;

using X25519PublicKey  = std::array<std::uint8_t, kX25519KeyLen>;
using X25519PrivateKey = std::array<std::uint8_t, kX25519KeyLen>;
using X25519Shared     = std::array<std::uint8_t, kX25519SharedLen>;

class X25519KeyPair {
public:
    X25519KeyPair() = default;
    ~X25519KeyPair();

    X25519KeyPair(const X25519KeyPair&)            = delete;
    X25519KeyPair& operator=(const X25519KeyPair&) = delete;
    X25519KeyPair(X25519KeyPair&& other) noexcept;
    X25519KeyPair& operator=(X25519KeyPair&& other) noexcept;

    /// Приватный ключ — просто 32 байта; clamping выполняется внутри.
    /// Для identity эти байты берутся из ikm_kem (§4), а не из RNG.
    static bool FromPrivateKey(const X25519PrivateKey& sk, X25519KeyPair& out);

    static bool FromPublicKey(const X25519PublicKey& pk, X25519KeyPair& out);

    /// Эфемерная пара из системного CSPRNG — для envelope каждого чанка.
    static bool Generate(X25519KeyPair& out);

    bool ExportPublicKey(X25519PublicKey& out) const;

    /// Общий секрет с чужим публичным ключом.
    ///
    /// Отвергает точки малого порядка: нулевой общий секрет означает, что
    /// собеседник подсунул вырожденную точку, и продолжать нельзя.
    bool Agree(const X25519KeyPair& peer_public, X25519Shared& out) const;

    bool HasPrivateKey() const { return has_private_; }
    bool IsValid() const { return pkey_ != nullptr; }

    void* Handle() const { return pkey_; }

private:
    void Reset();

    void* pkey_        = nullptr;  // EVP_PKEY*
    bool  has_private_ = false;
};

}  // namespace bb

#endif  // BBCORE_CRYPTO_X25519_H
