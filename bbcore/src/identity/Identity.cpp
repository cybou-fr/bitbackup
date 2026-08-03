#include "identity/Identity.h"

#include "bbcore/bbcore.h"
#include "crypto/Shake.h"
#include "util/Bip39.h"

#include <cstring>

namespace bb {
namespace {

constexpr std::string_view kLabelIdentity   = "bbk/1/identity";
constexpr std::string_view kLabelIdentityId = "bbk/1/identity-id";
constexpr std::string_view kLabelKem        = "kem";
constexpr std::string_view kLabelSig        = "sig";
constexpr std::string_view kLabelFileId     = "fileid";
constexpr std::string_view kLabelFileKey    = "filekey";
constexpr std::string_view kLabelInstance   = "instance";

constexpr char kBlobMagic[6] = {'b', 'b', 'k', '1', 'i', 'd'};
constexpr std::uint8_t kBlobVersion = 1;
constexpr std::uint8_t kBlobFlagSignature = 0x01;

/// SHAKE256(identity_root || label, out_len) — общая форма всех дериваций §4.
bool DeriveFromRoot(const std::uint8_t* root, std::string_view label,
                    std::uint8_t* out, std::size_t out_len)
{
    Shake256 shake;
    shake.Update(root, kIdentityRootLen);
    shake.Update(label);
    return shake.Finish(out, out_len);
}

}  // namespace

Identity::~Identity()
{
    Wipe();
}

void Identity::Wipe()
{
    bb_secure_zero(k_fileid_.data(), k_fileid_.size());
    bb_secure_zero(k_filekey_.data(), k_filekey_.size());
    bb_secure_zero(k_instance_.data(), k_instance_.size());
    bb_secure_zero(ikm_sig_.data(), ikm_sig_.size());
    bb_secure_zero(id_.data(), id_.size());

    has_private_ = false;
    valid_       = false;
}

bool Identity::ComputeId()
{
    MlKemPublicKey  pk_kem{};
    X25519PublicKey pk_x{};

    if (!kem_.ExportPublicKey(pk_kem) || !x25519_.ExportPublicKey(pk_x)) {
        return false;
    }

    Blake3 hasher;
    hasher.Update(kLabelIdentityId);
    hasher.Update(pk_kem.data(), pk_kem.size());
    hasher.Update(pk_x.data(), pk_x.size());
    return hasher.Finish(id_);
}

bool Identity::FromMnemonic(std::string_view mnemonic,
                            std::string_view passphrase,
                            std::uint32_t    index,
                            Identity&        out)
{
    // BIP39 требует NFKD. Пока ICU/utf8proc не подключён, принимаем только
    // printable ASCII, чтобы визуально одинаковый Unicode не породил другую identity.
    for (const unsigned char byte : passphrase) {
        if (byte < 0x20u || byte > 0x7Eu) {
            return false;
        }
    }
    out.Wipe();

    if (!Bip39Validate(mnemonic)) {
        return false;
    }

    Bip39Seed seed{};
    if (!Bip39DeriveSeed(mnemonic, passphrase, seed)) {
        return false;
    }

    // identity_root = SHAKE256(seed || "bbk/1/identity" || u32be(index), 32)
    std::uint8_t root[kIdentityRootLen];
    bool         ok = false;
    {
        Shake256 shake;
        shake.Update(seed.data(), seed.size());
        shake.Update(kLabelIdentity);
        shake.UpdateU32(index);
        ok = shake.Finish(root, sizeof root);
    }
    bb_secure_zero(seed.data(), seed.size());

    if (!ok) {
        bb_secure_zero(root, sizeof root);
        return false;
    }

    std::uint8_t ikm_kem[kIkmKemLen];

    ok = DeriveFromRoot(root, kLabelKem, ikm_kem, sizeof ikm_kem)
      && DeriveFromRoot(root, kLabelSig, out.ikm_sig_.data(), out.ikm_sig_.size())
      && DeriveFromRoot(root, kLabelFileId, out.k_fileid_.data(), out.k_fileid_.size())
      && DeriveFromRoot(root, kLabelFileKey, out.k_filekey_.data(), out.k_filekey_.size())
      && DeriveFromRoot(root, kLabelInstance, out.k_instance_.data(), out.k_instance_.size());

    bb_secure_zero(root, sizeof root);

    if (ok) {
        // Первые 64 байта ikm_kem — seed ML-KEM, последние 32 — приватный ключ
        // X25519 (§4). Середина ikm_kem форматом не используется.
        MlKemSeed        kem_seed{};
        X25519PrivateKey classic_sk{};

        std::memcpy(kem_seed.data(), ikm_kem, kem_seed.size());
        std::memcpy(classic_sk.data(),
                    ikm_kem + kIkmKemLen - classic_sk.size(), classic_sk.size());

        ok = MlKemKeyPair::FromSeed(kem_seed, out.kem_)
          && X25519KeyPair::FromPrivateKey(classic_sk, out.x25519_);

        bb_secure_zero(kem_seed.data(), kem_seed.size());
        bb_secure_zero(classic_sk.data(), classic_sk.size());
    }

    bb_secure_zero(ikm_kem, sizeof ikm_kem);

    if (!ok || !out.ComputeId()) {
        out.Wipe();
        return false;
    }

    out.has_private_ = true;
    out.valid_       = true;
    return true;
}

bool Identity::FromPublicBlob(const std::uint8_t* blob, std::size_t len, Identity& out)
{
    out.Wipe();

    if (blob == nullptr || len < kPublicBlobLen) {
        return false;
    }
    if (std::memcmp(blob, kBlobMagic, sizeof kBlobMagic) != 0) {
        return false;
    }
    if (blob[6] != kBlobVersion) {
        return false;
    }

    const std::uint8_t flags = blob[7];

    // Неизвестные флаги отвергаются, а не игнорируются: тихо принятый блоб
    // более новой версии означал бы адресацию файлов не тому получателю.
    if ((flags & ~kBlobFlagSignature) != 0) {
        return false;
    }
    if ((flags & kBlobFlagSignature) != 0) {
        return false;  // ML-DSA-87 ещё не реализован
    }
    if (len != kPublicBlobLen) {
        return false;
    }

    MlKemPublicKey  pk_kem{};
    X25519PublicKey pk_x{};

    std::memcpy(pk_kem.data(), blob + kPublicBlobHeaderLen, pk_kem.size());
    std::memcpy(pk_x.data(), blob + kPublicBlobHeaderLen + pk_kem.size(), pk_x.size());

    if (!MlKemKeyPair::FromPublicKey(pk_kem, out.kem_)
     || !X25519KeyPair::FromPublicKey(pk_x, out.x25519_)
     || !out.ComputeId()) {
        out.Wipe();
        return false;
    }

    out.has_private_ = false;
    out.valid_       = true;
    return true;
}

bool Identity::ExportPublicBlob(std::uint8_t* out, std::size_t cap, std::size_t* out_len) const
{
    if (out_len != nullptr) {
        *out_len = kPublicBlobLen;
    }
    if (!valid_ || out == nullptr || cap < kPublicBlobLen) {
        return false;
    }

    MlKemPublicKey  pk_kem{};
    X25519PublicKey pk_x{};
    if (!kem_.ExportPublicKey(pk_kem) || !x25519_.ExportPublicKey(pk_x)) {
        return false;
    }

    std::memcpy(out, kBlobMagic, sizeof kBlobMagic);
    out[6] = kBlobVersion;
    out[7] = 0;
    std::memcpy(out + kPublicBlobHeaderLen, pk_kem.data(), pk_kem.size());
    std::memcpy(out + kPublicBlobHeaderLen + pk_kem.size(), pk_x.data(), pk_x.size());

    return true;
}

}  // namespace bb
