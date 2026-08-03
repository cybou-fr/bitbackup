// Identity — всё, что выводится из мнемоники. См. ARCHITECTURE.md §4.
//
//   seed          = BIP39-seed(mnemonic, passphrase)              64
//   identity_root = SHAKE256(seed || "bbk/1/identity" || u32be(index), 32)
//
//   ikm_kem    = SHAKE256(identity_root || "kem",      128)
//   ikm_sig    = SHAKE256(identity_root || "sig",       32)
//   k_fileid   = SHAKE256(identity_root || "fileid",    32)
//   k_filekey  = SHAKE256(identity_root || "filekey",   32)
//   k_instance = SHAKE256(identity_root || "instance",  32)
//
//   identity_id = BLAKE3-XOF("bbk/1/identity-id" || pk_mlkem || pk_x25519, 32)
//
// Ничего из этого на диск не попадает: объект живёт в памяти сессии и затирает
// себя в деструкторе (§22).
//
// Identity бывает в двух видах. Полная — из мнемоники, с приватными ключами.
// Публичная — из блоба чужих ключей, умеет только адресовать файлы этому
// получателю (§26); приватных ключей и производных k_* у неё нет.

#ifndef BBCORE_IDENTITY_IDENTITY_H
#define BBCORE_IDENTITY_IDENTITY_H

#include "crypto/Hash.h"
#include "crypto/Kem.h"
#include "crypto/X25519.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace bb {

inline constexpr std::size_t kIdentityKeyLen  = 32;
inline constexpr std::size_t kIdentityRootLen = 32;
inline constexpr std::size_t kIkmKemLen       = 128;
inline constexpr std::size_t kIkmSigLen       = 32;

using IdentityKey = std::array<std::uint8_t, kIdentityKeyLen>;

/// Блоб публичных ключей для передачи файлов (§26).
///
///   0     6     magic "bbk1id"
///   6     1     версия = 1
///   7     1     флаги; бит 0 — присутствует публичный ключ ML-DSA
///   8     1568  pk_mlkem
///   1576  32    pk_x25519
///   1608  2592  pk_mldsa, только если выставлен бит 0
///
/// identity_id в блоб не входит намеренно: он выводится из самих ключей, и
/// хранить его рядом значило бы допустить блоб, в котором они не сходятся.
///
/// Формат контейнера bbk/1 это не затрагивает — блоб передаётся между людьми,
/// в хранилище не попадает и заморожен не был. Слот ML-DSA появится вместе с
/// самим ML-DSA-87 в фазе передачи файлов.
inline constexpr std::size_t kPublicBlobHeaderLen = 8;
inline constexpr std::size_t kPublicBlobLen =
    kPublicBlobHeaderLen + kMlKemPublicKeyLen + kX25519KeyLen;

class Identity {
public:
    Identity() = default;
    ~Identity();

    Identity(const Identity&)            = delete;
    Identity& operator=(const Identity&) = delete;

    /// Полная identity из мнемоники. Мнемоника проверяется по контрольной сумме.
    static bool FromMnemonic(std::string_view mnemonic,
                             std::string_view passphrase,
                             std::uint32_t    index,
                             Identity&        out);

    /// Публичная identity из блоба чужих ключей.
    static bool FromPublicBlob(const std::uint8_t* blob, std::size_t len, Identity& out);

    bool ExportPublicBlob(std::uint8_t* out, std::size_t cap, std::size_t* out_len) const;

    const Hash256& Id() const { return id_; }

    bool HasPrivateKey() const { return has_private_; }
    bool IsValid() const { return valid_; }

    const MlKemKeyPair&  Kem() const { return kem_; }
    const X25519KeyPair& Classic() const { return x25519_; }

    /// Ключи деривации. Есть только у полной identity; у публичной обнулены.
    const IdentityKey& KeyFileId() const { return k_fileid_; }
    const IdentityKey& KeyFileKey() const { return k_filekey_; }
    const IdentityKey& KeyInstance() const { return k_instance_; }

    /// Исходный материал для ML-DSA-87. Ключевая пара из него ещё не строится:
    /// подписи нужны только при передаче файлов (§26). Материал выводится уже
    /// сейчас, чтобы добавление подписей не поменяло деривацию задним числом.
    const IdentityKey& SigningSeed() const { return ikm_sig_; }

private:
    bool ComputeId();
    void Wipe();

    MlKemKeyPair  kem_;
    X25519KeyPair x25519_;

    Hash256     id_{};
    IdentityKey k_fileid_{};
    IdentityKey k_filekey_{};
    IdentityKey k_instance_{};
    IdentityKey ikm_sig_{};

    bool has_private_ = false;
    bool valid_       = false;
};

}  // namespace bb

#endif  // BBCORE_IDENTITY_IDENTITY_H
