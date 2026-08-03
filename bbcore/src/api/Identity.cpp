// Реализация bb_mnemonic_* и bb_identity_* из плоского C ABI.

#include "bbcore/bbcore.h"

#include "identity/Identity.h"
#include "util/Base32.h"
#include "util/Bip39.h"

#include <cstring>
#include <new>
#include <string>
#include <tuple>

struct bb_identity {
    bb::Identity impl;
};

namespace {

const bb::Identity* Impl(const bb_identity* identity)
{
    return (identity != nullptr && identity->impl.IsValid()) ? &identity->impl : nullptr;
}

}  // namespace

BB_API bb_status BB_CALL bb_mnemonic_new(
    unsigned words, char* out, size_t cap, size_t* out_len)
{
    if (words != bb::kBip39Words12 && words != bb::kBip39Words24) {
        return BB_ERR_INVALID_ARG;
    }

    std::string mnemonic;
    if (!bb::Bip39Generate(words, mnemonic)) {
        return BB_ERR_INTERNAL;
    }

    const size_t needed = mnemonic.size() + 1;
    if (out_len != nullptr) {
        *out_len = needed;
    }
    if (out == nullptr || cap < needed) {
        bb_secure_zero(&mnemonic[0], mnemonic.size());
        return BB_ERR_BUFFER_TOO_SMALL;
    }

    std::memcpy(out, mnemonic.data(), mnemonic.size());
    out[mnemonic.size()] = '\0';

    bb_secure_zero(&mnemonic[0], mnemonic.size());
    return BB_OK;
}

BB_API bb_status BB_CALL bb_mnemonic_validate(const char* mnemonic)
{
    if (mnemonic == nullptr) {
        return BB_ERR_INVALID_ARG;
    }
    return bb::Bip39Validate(mnemonic) ? BB_OK : BB_ERR_BAD_MNEMONIC;
}

BB_API bb_status BB_CALL bb_identity_open(
    const char* mnemonic, const char* passphrase, uint32_t index,
    bb_identity** out_identity)
{
    if (mnemonic == nullptr || out_identity == nullptr) {
        return BB_ERR_INVALID_ARG;
    }
    *out_identity = nullptr;

    bb_identity* identity = new (std::nothrow) bb_identity();
    if (identity == nullptr) {
        return BB_ERR_OUT_OF_MEMORY;
    }

    // Мнемоника отделена от прочих ошибок: пользователю нужно знать, что дело
    // в опечатке в словах, а не в сбое библиотеки.
    if (!bb::Bip39Validate(mnemonic)) {
        delete identity;
        return BB_ERR_BAD_MNEMONIC;
    }

    if (!bb::Identity::FromMnemonic(mnemonic,
                                    passphrase != nullptr ? passphrase : "",
                                    index, identity->impl)) {
        delete identity;
        return BB_ERR_INTERNAL;
    }

    *out_identity = identity;
    return BB_OK;
}

BB_API bb_status BB_CALL bb_identity_open_public(
    const uint8_t* public_blob, size_t public_len, bb_identity** out_identity)
{
    if (public_blob == nullptr || out_identity == nullptr) {
        return BB_ERR_INVALID_ARG;
    }
    *out_identity = nullptr;

    bb_identity* identity = new (std::nothrow) bb_identity();
    if (identity == nullptr) {
        return BB_ERR_OUT_OF_MEMORY;
    }

    if (!bb::Identity::FromPublicBlob(public_blob, public_len, identity->impl)) {
        delete identity;
        return BB_ERR_UNSUPPORTED;
    }

    *out_identity = identity;
    return BB_OK;
}

BB_API void BB_CALL bb_identity_free(bb_identity* identity)
{
    delete identity;  // деструктор bb::Identity затирает ключевой материал
}

BB_API bb_status BB_CALL bb_identity_id(
    const bb_identity* identity, uint8_t out[BB_ID_LEN])
{
    const bb::Identity* impl = Impl(identity);
    if (impl == nullptr || out == nullptr) {
        return BB_ERR_INVALID_ARG;
    }

    static_assert(std::tuple_size<bb::Hash256>::value == BB_ID_LEN,
                  "identity_id length must match BB_ID_LEN");

    std::memcpy(out, impl->Id().data(), BB_ID_LEN);
    return BB_OK;
}

BB_API bb_status BB_CALL bb_identity_id_text(
    const bb_identity* identity, char* out, size_t cap)
{
    const bb::Identity* impl = Impl(identity);
    if (impl == nullptr || out == nullptr) {
        return BB_ERR_INVALID_ARG;
    }
    if (cap < BB_ID_B32_LEN + 1) {
        return BB_ERR_BUFFER_TOO_SMALL;
    }

    if (!bb::Base32Encode(impl->Id().data(), impl->Id().size(), out, cap, nullptr)) {
        return BB_ERR_INTERNAL;
    }
    out[BB_ID_B32_LEN] = '\0';
    return BB_OK;
}

BB_API bb_status BB_CALL bb_identity_export_public(
    const bb_identity* identity, uint8_t* out, size_t cap, size_t* out_len)
{
    const bb::Identity* impl = Impl(identity);
    if (impl == nullptr) {
        return BB_ERR_INVALID_ARG;
    }

    size_t needed = 0;
    if (!impl->ExportPublicBlob(out, cap, &needed)) {
        if (out_len != nullptr) {
            *out_len = needed;
        }
        return (out == nullptr || cap < needed) ? BB_ERR_BUFFER_TOO_SMALL
                                                : BB_ERR_INTERNAL;
    }

    if (out_len != nullptr) {
        *out_len = needed;
    }
    return BB_OK;
}

BB_API int BB_CALL bb_identity_has_private(const bb_identity* identity)
{
    const bb::Identity* impl = Impl(identity);
    return (impl != nullptr && impl->HasPrivateKey()) ? 1 : 0;
}
