#include "crypto/Hash.h"

#include "bbcore/bbcore.h"

#include <blake3.h>

namespace bb {
namespace {

static_assert(sizeof(blake3_hasher) <= kBlake3StateSize,
              "blake3_hasher outgrew Blake3::state_; raise kBlake3StateSize");
static_assert(alignof(blake3_hasher) <= 16,
              "blake3_hasher needs stricter alignment than Blake3::state_ gives");

blake3_hasher* AsHasher(unsigned char* p)
{
    return reinterpret_cast<blake3_hasher*>(p);
}

}  // namespace

Blake3::Blake3()
{
    blake3_hasher_init(AsHasher(state_));
}

Blake3::Blake3(const Blake3Key& key)
{
    blake3_hasher_init_keyed(AsHasher(state_), key.data());
}

Blake3::~Blake3()
{
    // Состояние keyed-хешера содержит производный ключ identity (k_instance,
    // k_fileid), поэтому затирается всегда, а не только при ошибке. См. §22.
    bb_secure_zero(state_, sizeof state_);
}

Blake3& Blake3::Update(const void* data, std::size_t len)
{
    if (failed_) {
        return *this;
    }
    if (len == 0) {
        return *this;
    }
    if (data == nullptr) {
        failed_ = true;
        return *this;
    }

    blake3_hasher_update(AsHasher(state_), data, len);
    return *this;
}

Blake3& Blake3::Update(std::string_view label)
{
    return Update(label.data(), label.size());
}

Blake3& Blake3::UpdateU8(std::uint8_t value)
{
    return Update(&value, 1);
}

bool Blake3::Finish(std::uint8_t* out, std::size_t out_len)
{
    if (failed_ || out == nullptr || out_len == 0) {
        return false;
    }

    blake3_hasher_finalize(AsHasher(state_), out, out_len);

    failed_ = true;  // повторное использование запрещено, как у Shake256
    return true;
}

bool Blake3::Finish(Hash256& out)
{
    return Finish(out.data(), out.size());
}

bool Blake3Hash(const void* data, std::size_t len,
                std::uint8_t* out, std::size_t out_len)
{
    Blake3 hasher;
    hasher.Update(data, len);
    return hasher.Finish(out, out_len);
}

bool Blake3KeyedHash(const Blake3Key& key, const void* data, std::size_t len,
                     std::uint8_t* out, std::size_t out_len)
{
    Blake3 hasher(key);
    hasher.Update(data, len);
    return hasher.Finish(out, out_len);
}

}  // namespace bb
