#include "redundancy/Gf256.h"

namespace bb {
namespace {

Gf256Tables BuildTables()
{
    Gf256Tables tables{};

    std::uint16_t value = 1;
    for (int i = 0; i < 255; ++i) {
        tables.exp[i]     = static_cast<std::uint8_t>(value);
        tables.log[value] = static_cast<std::uint8_t>(i);

        value <<= 1;
        if ((value & 0x100u) != 0) {
            value ^= kGf256Polynomial;
        }
    }

    // Продление: exp[i + 255] = exp[i]. Умножение складывает два логарифма,
    // каждый до 254, поэтому индекс не выходит за 508.
    for (int i = 255; i < 512; ++i) {
        tables.exp[i] = tables.exp[i - 255];
    }

    // log[0] не определён; ноль обрабатывается отдельно во всех операциях.
    tables.log[0] = 0;

    return tables;
}

}  // namespace

const Gf256Tables& Gf256()
{
    static const Gf256Tables tables = BuildTables();
    return tables;
}

}  // namespace bb
