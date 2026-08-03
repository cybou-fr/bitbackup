#include "crypto/HybridKem.h"

#include "crypto/Shake.h"

#include <cstring>

namespace bb {
namespace {

constexpr std::string_view kLabelKem = "bbk/1/kem";
constexpr std::string_view kLabelAad = "bbk/1/env-aad";

/// encode(x) = u32be(len(x)) || x. Все поля suite 1 фиксированной длины, но
/// длина пишется всё равно: иначе переменные поля будущих suite создали бы
/// неоднозначность разбора transcript'а (§15).
void Encode(Shake256& shake, const void* data, std::size_t len)
{
    shake.UpdateU32(static_cast<std::uint32_t>(len));
    shake.Update(data, len);
}

void Encode(Shake256& shake, std::string_view text)
{
    Encode(shake, text.data(), text.size());
}

/// AAD обёртки: "bbk/1/env-aad" || identity_id (§15).
std::array<std::uint8_t, kLabelAad.size() + BB_ID_LEN> BuildAad(const Hash256& identity_id)
{
    std::array<std::uint8_t, kLabelAad.size() + BB_ID_LEN> aad{};
    std::memcpy(aad.data(), kLabelAad.data(), kLabelAad.size());
    std::memcpy(aad.data() + kLabelAad.size(), identity_id.data(), identity_id.size());
    return aad;
}

}  // namespace

// Combiner §15 плюс нонс продолжением того же XOF — см. HybridKem.h.
bool HybridCombine(const MlKemShared&     ss_mlkem,
                   const X25519Shared&    ss_x25519,
                   const Hash256&         identity_id,
                   std::uint16_t          suite_id,
                   const MlKemPublicKey&  pk_mlkem,
                   const X25519PublicKey& pk_x25519,
                   const MlKemCiphertext& ct_mlkem,
                   const X25519PublicKey& epk_x25519,
                   AeadKey&               out_key,
                   AeadNonce&             out_nonce)
{
    Shake256 shake;

    // Общие секреты идут первыми, весь публичный материал — в transcript.
    Encode(shake, ss_mlkem.data(), ss_mlkem.size());
    Encode(shake, ss_x25519.data(), ss_x25519.size());

    Encode(shake, kLabelKem);
    shake.UpdateU16(BB_FORMAT_VERSION);
    shake.UpdateU16(suite_id);
    Encode(shake, identity_id.data(), identity_id.size());
    Encode(shake, pk_mlkem.data(), pk_mlkem.size());
    Encode(shake, pk_x25519.data(), pk_x25519.size());
    Encode(shake, ct_mlkem.data(), ct_mlkem.size());
    Encode(shake, epk_x25519.data(), epk_x25519.size());

    std::uint8_t stream[kAeadKeyLen + kAeadNonceLen];
    if (!shake.Finish(stream, sizeof stream)) {
        bb_secure_zero(stream, sizeof stream);
        return false;
    }

    std::memcpy(out_key.data(), stream, out_key.size());
    std::memcpy(out_nonce.data(), stream + out_key.size(), out_nonce.size());

    bb_secure_zero(stream, sizeof stream);
    return true;
}

bb_status HybridSeal(const MlKemKeyPair&  recipient_kem,
                     const X25519KeyPair& recipient_classic,
                     const Hash256&       recipient_identity_id,
                     std::uint16_t        suite_id,
                     const FileKey&       k_file,
                     const Hash256&       file_id,
                     HybridEnvelope&      out)
{
    if (suite_id != BB_SUITE_ID) {
        return BB_ERR_UNSUPPORTED;
    }
    if (!recipient_kem.IsValid() || !recipient_classic.IsValid()) {
        return BB_ERR_INVALID_ARG;
    }

    MlKemPublicKey  pk_mlkem{};
    X25519PublicKey pk_x25519{};
    if (!recipient_kem.ExportPublicKey(pk_mlkem)
     || !recipient_classic.ExportPublicKey(pk_x25519)) {
        return BB_ERR_INTERNAL;
    }

    MlKemShared ss_mlkem{};
    if (!recipient_kem.Encapsulate(out.ct_mlkem, ss_mlkem)) {
        return BB_ERR_INTERNAL;
    }

    // Эфемерная пара своя на каждый чанк — отсюда и несвязываемость объектов.
    X25519KeyPair ephemeral;
    X25519Shared  ss_x25519{};
    bb_status     status = BB_OK;

    if (!X25519KeyPair::Generate(ephemeral)
     || !ephemeral.ExportPublicKey(out.epk_x25519)
     || !ephemeral.Agree(recipient_classic, ss_x25519)) {
        status = BB_ERR_INTERNAL;
    }

    AeadKey   k_env{};
    AeadNonce n_env{};

    if (status == BB_OK
     && !HybridCombine(ss_mlkem, ss_x25519, recipient_identity_id, suite_id,
                           pk_mlkem, pk_x25519, out.ct_mlkem, out.epk_x25519,
                           k_env, n_env)) {
        status = BB_ERR_INTERNAL;
    }

    bb_secure_zero(ss_mlkem.data(), ss_mlkem.size());
    bb_secure_zero(ss_x25519.data(), ss_x25519.size());

    if (status == BB_OK) {
        std::uint8_t secret[kEnvelopeSecretLen];
        std::memcpy(secret, k_file.data(), k_file.size());
        std::memcpy(secret + k_file.size(), file_id.data(), file_id.size());

        const auto  aad      = BuildAad(recipient_identity_id);
        std::size_t produced = 0;

        if (!AeadSeal(k_env, n_env, aad.data(), aad.size(),
                      secret, sizeof secret,
                      out.wrapped.data(), out.wrapped.size(), &produced)
         || produced != out.wrapped.size()) {
            status = BB_ERR_INTERNAL;
        }

        bb_secure_zero(secret, sizeof secret);
    }

    bb_secure_zero(k_env.data(), k_env.size());
    bb_secure_zero(n_env.data(), n_env.size());

    return status;
}

bb_status HybridOpen(const MlKemKeyPair&   self_kem,
                     const X25519KeyPair&  self_classic,
                     const Hash256&        self_identity_id,
                     std::uint16_t         suite_id,
                     const std::uint8_t*   header_identity_id,
                     const HybridEnvelope& envelope,
                     FileKey&              out_k_file,
                     Hash256&              out_file_id)
{
    // Порядок проверок задан §15: сначала формат, потом адресат, и только
    // потом криптография.
    if (suite_id != BB_SUITE_ID) {
        return BB_ERR_UNSUPPORTED;
    }
    if (header_identity_id == nullptr) {
        return BB_ERR_INVALID_ARG;
    }
    if (std::memcmp(header_identity_id, self_identity_id.data(),
                    self_identity_id.size()) != 0) {
        return BB_ERR_WRONG_IDENTITY;
    }
    if (!self_kem.HasPrivateKey() || !self_classic.HasPrivateKey()) {
        return BB_ERR_INVALID_ARG;
    }

    MlKemPublicKey  pk_mlkem{};
    X25519PublicKey pk_x25519{};
    if (!self_kem.ExportPublicKey(pk_mlkem)
     || !self_classic.ExportPublicKey(pk_x25519)) {
        return BB_ERR_INTERNAL;
    }

    // Отсюда и до конца любой отказ обязан выглядеть одинаково. ML-KEM при
    // повреждённом ciphertext по построению возвращает псевдослучайный секрет,
    // а не ошибку (implicit rejection, FIPS 203); X25519 на точке малого
    // порядка отказывает явно. Оба случая сводятся к BB_ERR_DECRYPT_FAILED,
    // иначе получился бы оракул, отличающий сломанную половину гибрида.
    bb_status status = BB_ERR_DECRYPT_FAILED;

    MlKemShared  ss_mlkem{};
    X25519Shared ss_x25519{};
    AeadKey      k_env{};
    AeadNonce    n_env{};

    X25519KeyPair ephemeral;

    const bool ok =
        self_kem.Decapsulate(envelope.ct_mlkem, ss_mlkem)
     && X25519KeyPair::FromPublicKey(envelope.epk_x25519, ephemeral)
     && self_classic.Agree(ephemeral, ss_x25519)
     && HybridCombine(ss_mlkem, ss_x25519, self_identity_id, suite_id,
                          pk_mlkem, pk_x25519, envelope.ct_mlkem,
                          envelope.epk_x25519, k_env, n_env);

    bb_secure_zero(ss_mlkem.data(), ss_mlkem.size());
    bb_secure_zero(ss_x25519.data(), ss_x25519.size());

    if (ok) {
        std::uint8_t secret[kEnvelopeSecretLen];
        const auto   aad      = BuildAad(self_identity_id);
        std::size_t  produced = 0;

        if (AeadOpen(k_env, n_env, aad.data(), aad.size(),
                     envelope.wrapped.data(), envelope.wrapped.size(),
                     secret, sizeof secret, &produced)
         && produced == sizeof secret) {
            std::memcpy(out_k_file.data(), secret, out_k_file.size());
            std::memcpy(out_file_id.data(), secret + out_k_file.size(),
                        out_file_id.size());
            status = BB_OK;
        }

        bb_secure_zero(secret, sizeof secret);
    }

    bb_secure_zero(k_env.data(), k_env.size());
    bb_secure_zero(n_env.data(), n_env.size());

    if (status != BB_OK) {
        bb_secure_zero(out_k_file.data(), out_k_file.size());
        bb_secure_zero(out_file_id.data(), out_file_id.size());
    }

    return status;
}

}  // namespace bb
