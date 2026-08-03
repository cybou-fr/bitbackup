#include "crypto/X25519.h"

#include "bbcore/bbcore.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <utility>

namespace bb {
namespace {

EVP_PKEY* AsPkey(void* p)
{
    return static_cast<EVP_PKEY*>(p);
}

}  // namespace

X25519KeyPair::~X25519KeyPair()
{
    Reset();
}

X25519KeyPair::X25519KeyPair(X25519KeyPair&& other) noexcept
    : pkey_(std::exchange(other.pkey_, nullptr)),
      has_private_(std::exchange(other.has_private_, false))
{
}

X25519KeyPair& X25519KeyPair::operator=(X25519KeyPair&& other) noexcept
{
    if (this != &other) {
        Reset();
        pkey_        = std::exchange(other.pkey_, nullptr);
        has_private_ = std::exchange(other.has_private_, false);
    }
    return *this;
}

void X25519KeyPair::Reset()
{
    if (pkey_ != nullptr) {
        EVP_PKEY_free(AsPkey(pkey_));
        pkey_ = nullptr;
    }
    has_private_ = false;
}

bool X25519KeyPair::FromPrivateKey(const X25519PrivateKey& sk, X25519KeyPair& out)
{
    out.Reset();

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, sk.data(), sk.size());
    if (pkey == nullptr) {
        return false;
    }

    out.pkey_        = pkey;
    out.has_private_ = true;
    return true;
}

bool X25519KeyPair::FromPublicKey(const X25519PublicKey& pk, X25519KeyPair& out)
{
    out.Reset();

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr, pk.data(), pk.size());
    if (pkey == nullptr) {
        return false;
    }

    out.pkey_        = pkey;
    out.has_private_ = false;
    return true;
}

bool X25519KeyPair::Generate(X25519KeyPair& out)
{
    X25519PrivateKey sk{};
    if (RAND_bytes(sk.data(), static_cast<int>(sk.size())) != 1) {
        return false;
    }

    const bool ok = FromPrivateKey(sk, out);
    bb_secure_zero(sk.data(), sk.size());
    return ok;
}

bool X25519KeyPair::ExportPublicKey(X25519PublicKey& out) const
{
    if (pkey_ == nullptr) {
        return false;
    }

    std::size_t len = out.size();
    if (EVP_PKEY_get_raw_public_key(AsPkey(pkey_), out.data(), &len) != 1) {
        return false;
    }
    return len == out.size();
}

bool X25519KeyPair::Agree(const X25519KeyPair& peer_public, X25519Shared& out) const
{
    if (pkey_ == nullptr || !has_private_ || !peer_public.IsValid()) {
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(AsPkey(pkey_), nullptr);
    if (ctx == nullptr) {
        return false;
    }

    std::size_t len = out.size();

    // EVP_PKEY_derive для X25519 возвращает ошибку на нулевом общем секрете,
    // то есть точка малого порядка отвергается здесь же (RFC 7748 §6.1).
    const bool ok =
        EVP_PKEY_derive_init(ctx) == 1 &&
        EVP_PKEY_derive_set_peer(ctx, AsPkey(peer_public.Handle())) == 1 &&
        EVP_PKEY_derive(ctx, out.data(), &len) == 1 &&
        len == out.size();

    EVP_PKEY_CTX_free(ctx);

    if (!ok) {
        bb_secure_zero(out.data(), out.size());
    }
    return ok;
}

}  // namespace bb
