// Арифметика GF(2^8) для Reed–Solomon (§30).
//
// Примитивный полином — 0x11D, то есть x^8 + x^4 + x^3 + x^2 + 1.
// Спецификация его не называла: §30 говорит только «GF(2^8), матрица Коши».
// Выбран 0x11D как де-факто стандарт erasure coding — на нём построены Intel
// ISA-L, реализация Backblaze и klauspost/reedsolomon. Выбор заморожен
// вектором: parity-байты лежат в объектах хранилища, и смена полинома сделала
// бы все ранее записанные parity нечитаемыми.
//
// Таблицы log/exp строятся один раз на процесс от порождающего элемента 2.
// Таблица exp продлена до 512 элементов, чтобы умножение обходилось без
// приведения показателя по модулю 255.

#ifndef BBCORE_REDUNDANCY_GF256_H
#define BBCORE_REDUNDANCY_GF256_H

#include <cstdint>

namespace bb {

inline constexpr std::uint16_t kGf256Polynomial = 0x11D;

struct Gf256Tables {
    std::uint8_t exp[512];
    std::uint8_t log[256];
};

const Gf256Tables& Gf256();

/// Сложение в GF(2^8) — это XOR, поэтому оно же и вычитание.
inline std::uint8_t GfAdd(std::uint8_t a, std::uint8_t b)
{
    return static_cast<std::uint8_t>(a ^ b);
}

inline std::uint8_t GfMul(std::uint8_t a, std::uint8_t b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    const Gf256Tables& t = Gf256();
    return t.exp[static_cast<int>(t.log[a]) + static_cast<int>(t.log[b])];
}

inline std::uint8_t GfDiv(std::uint8_t a, std::uint8_t b)
{
    if (a == 0 || b == 0) {
        return 0;  // деление на ноль не встречается: вызывающий его исключает
    }
    const Gf256Tables& t = Gf256();
    return t.exp[static_cast<int>(t.log[a]) + 255 - static_cast<int>(t.log[b])];
}

inline std::uint8_t GfInv(std::uint8_t a)
{
    if (a == 0) {
        return 0;
    }
    const Gf256Tables& t = Gf256();
    return t.exp[255 - static_cast<int>(t.log[a])];
}

}  // namespace bb

#endif  // BBCORE_REDUNDANCY_GF256_H
