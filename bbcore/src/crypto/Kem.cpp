#include "crypto/Kem.h"

#include "bbcore/bbcore.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>

#include <cstring>
#include <utility>

namespace bb {
namespace {

constexpr const char* kAlgorithm = "ML-KEM-1024";

EVP_PKEY* AsPkey(void* p)
{
    return static_cast<EVP_PKEY*>(p);
}

}  // namespace

MlKemKeyPair::~MlKemKeyPair()
{
    Reset();
}

MlKemKeyPair::MlKemKeyPair(MlKemKeyPair&& other) noexcept
    : pkey_(std::exchange(other.pkey_, nullptr)),
      has_private_(std::exchange(other.has_private_, false))
{
}

MlKemKeyPair& MlKemKeyPair::operator=(MlKemKeyPair&& other) noexcept
{
    if (this != &other) {
        Reset();
        pkey_        = std::exchange(other.pkey_, nullptr);
        has_private_ = std::exchange(other.has_private_, false);
    }
    return *this;
}

void MlKemKeyPair::Reset()
{
    if (pkey_ != nullptr) {
        EVP_PKEY_free(AsPkey(pkey_));
        pkey_ = nullptr;
    }
    has_private_ = false;
}

bool MlKemKeyPair::FromSeed(const MlKemSeed& seed, MlKemKeyPair& out)
{
    out.Reset();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, kAlgorithm, nullptr);
    if (ctx == nullptr) {
        return false;
    }

    bool ok = false;
    EVP_PKEY* pkey = nullptr;

    // Детерминированный keygen: OpenSSL принимает seed как параметр генерации.
    // Без этого ML-KEM брал бы случайность из RAND_bytes, и одна мнемоника
    // давала бы разные ключи при каждом запуске.
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_ML_KEM_SEED,
            const_cast<std::uint8_t*>(seed.data()),
            seed.size()),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_params(ctx, params) == 1 &&
        EVP_PKEY_generate(ctx, &pkey) == 1) {
        out.pkey_        = pkey;
        out.has_private_ = true;
        ok               = true;
    } else if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }

    EVP_PKEY_CTX_free(ctx);
    return ok;
}

bool MlKemKeyPair::FromPublicKey(const MlKemPublicKey& pk, MlKemKeyPair& out)
{
    out.Reset();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, kAlgorithm, nullptr);
    if (ctx == nullptr) {
        return false;
    }

    bool      ok   = false;
    EVP_PKEY* pkey = nullptr;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            const_cast<std::uint8_t*>(pk.data()),
            pk.size()),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_fromdata_init(ctx) == 1 &&
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) == 1) {
        out.pkey_        = pkey;
        out.has_private_ = false;
        ok               = true;
    } else if (pkey != nullptr) {
        EVP_PKEY_free(pkey);
    }

    EVP_PKEY_CTX_free(ctx);
    return ok;
}

bool MlKemKeyPair::ExportPublicKey(MlKemPublicKey& out) const
{
    if (pkey_ == nullptr) {
        return false;
    }

    std::size_t len = 0;
    if (EVP_PKEY_get_octet_string_param(
            AsPkey(pkey_), OSSL_PKEY_PARAM_PUB_KEY,
            out.data(), out.size(), &len) != 1) {
        return false;
    }

    return len == out.size();
}

bool MlKemKeyPair::Encapsulate(MlKemCiphertext& out_ct, MlKemShared& out_shared) const
{
    if (pkey_ == nullptr) {
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, AsPkey(pkey_), nullptr);
    if (ctx == nullptr) {
        return false;
    }

    std::size_t ct_len     = out_ct.size();
    std::size_t shared_len = out_shared.size();

    const bool ok =
        EVP_PKEY_encapsulate_init(ctx, nullptr) == 1 &&
        EVP_PKEY_encapsulate(ctx, out_ct.data(), &ct_len,
                             out_shared.data(), &shared_len) == 1 &&
        ct_len == out_ct.size() &&
        shared_len == out_shared.size();

    EVP_PKEY_CTX_free(ctx);
    return ok;
}

bool MlKemKeyPair::Decapsulate(const MlKemCiphertext& ct, MlKemShared& out_shared) const
{
    if (pkey_ == nullptr || !has_private_) {
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey(nullptr, AsPkey(pkey_), nullptr);
    if (ctx == nullptr) {
        return false;
    }

    std::size_t shared_len = out_shared.size();

    const bool ok =
        EVP_PKEY_decapsulate_init(ctx, nullptr) == 1 &&
        EVP_PKEY_decapsulate(ctx, out_shared.data(), &shared_len,
                             ct.data(), ct.size()) == 1 &&
        shared_len == out_shared.size();

    EVP_PKEY_CTX_free(ctx);
    return ok;
}

}  // namespace bb
