// SHAKE256 (FIPS 202) — единственный KDF и XOF в bbk/1.
//
// Спецификация записывает деривации как SHAKE256(a || b || c, n). Здесь это
// выражено явным Update на каждую часть: конкатенация в буфер потребовала бы
// лишнего копирования ключевого материала, который потом пришлось бы затирать.
//
// Все метки доменного разделения ("bbk/1/...") входят как ASCII-байты без
// завершающего нуля — см. ARCHITECTURE.md §30.

#ifndef BBCORE_CRYPTO_SHAKE_H
#define BBCORE_CRYPTO_SHAKE_H

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace bb {

class Shake256 {
public:
    Shake256();
    ~Shake256();

    Shake256(const Shake256&)            = delete;
    Shake256& operator=(const Shake256&) = delete;

    bool IsValid() const { return ctx_ != nullptr; }

    Shake256& Update(const void* data, std::size_t len);
    Shake256& Update(std::string_view label);

    /// Big-endian, как во всех формулах спецификации.
    Shake256& UpdateU16(std::uint16_t value);
    Shake256& UpdateU32(std::uint32_t value);
    Shake256& UpdateU64(std::uint64_t value);

    /// Выдавливает out_len байт. Вызывается один раз; после этого объект
    /// использовать нельзя.
    bool Finish(std::uint8_t* out, std::size_t out_len);

private:
    void* ctx_ = nullptr;  // EVP_MD_CTX*
    bool  failed_ = false;
};

}  // namespace bb

#endif  // BBCORE_CRYPTO_SHAKE_H
