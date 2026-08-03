#include "crypto/Shake.h"

#include <openssl/evp.h>

namespace bb {
namespace {

EVP_MD_CTX* AsCtx(void* p)
{
    return static_cast<EVP_MD_CTX*>(p);
}

}  // namespace

Shake256::Shake256()
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        failed_ = true;
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        failed_ = true;
        return;
    }

    ctx_ = ctx;
}

Shake256::~Shake256()
{
    if (ctx_ != nullptr) {
        EVP_MD_CTX_free(AsCtx(ctx_));
        ctx_ = nullptr;
    }
}

Shake256& Shake256::Update(const void* data, std::size_t len)
{
    if (ctx_ == nullptr || failed_) {
        failed_ = true;
        return *this;
    }
    if (len == 0) {
        return *this;
    }
    if (data == nullptr || EVP_DigestUpdate(AsCtx(ctx_), data, len) != 1) {
        failed_ = true;
    }
    return *this;
}

Shake256& Shake256::Update(std::string_view label)
{
    return Update(label.data(), label.size());
}

Shake256& Shake256::UpdateU16(std::uint16_t value)
{
    const std::uint8_t be[2] = {
        static_cast<std::uint8_t>(value >> 8),
        static_cast<std::uint8_t>(value),
    };
    return Update(be, sizeof be);
}

Shake256& Shake256::UpdateU32(std::uint32_t value)
{
    const std::uint8_t be[4] = {
        static_cast<std::uint8_t>(value >> 24),
        static_cast<std::uint8_t>(value >> 16),
        static_cast<std::uint8_t>(value >> 8),
        static_cast<std::uint8_t>(value),
    };
    return Update(be, sizeof be);
}

Shake256& Shake256::UpdateU64(std::uint64_t value)
{
    const std::uint8_t be[8] = {
        static_cast<std::uint8_t>(value >> 56),
        static_cast<std::uint8_t>(value >> 48),
        static_cast<std::uint8_t>(value >> 40),
        static_cast<std::uint8_t>(value >> 32),
        static_cast<std::uint8_t>(value >> 24),
        static_cast<std::uint8_t>(value >> 16),
        static_cast<std::uint8_t>(value >> 8),
        static_cast<std::uint8_t>(value),
    };
    return Update(be, sizeof be);
}

bool Shake256::Finish(std::uint8_t* out, std::size_t out_len)
{
    if (ctx_ == nullptr || failed_ || out == nullptr || out_len == 0) {
        return false;
    }

    const bool ok = EVP_DigestFinalXOF(AsCtx(ctx_), out, out_len) == 1;

    EVP_MD_CTX_free(AsCtx(ctx_));
    ctx_    = nullptr;
    failed_ = true;  // повторное использование запрещено

    return ok;
}

}  // namespace bb
