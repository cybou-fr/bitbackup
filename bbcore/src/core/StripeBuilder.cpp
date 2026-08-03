#include "core/StripeBuilder.h"

#include "crypto/Aead.h"

#include <algorithm>
#include <numeric>

namespace bb {

std::uint32_t ShardCoreLength(std::uint32_t fragment_length)
{
    return fragment_length + static_cast<std::uint32_t>(kAeadTagLen);
}

bb_status BuildStripes(const std::vector<Fragment>& fragments,
                       std::uint32_t                rs_data,
                       std::uint32_t                rs_parity,
                       FileLayout&                  out_layout)
{
    out_layout = FileLayout{};

    if (fragments.empty() || rs_data == 0 || rs_parity == 0) {
        return BB_ERR_INVALID_ARG;
    }
    if (fragments.size() > BB_MAX_CHUNKS) {
        return BB_ERR_UNSUPPORTED;
    }
    if (SplitShardCount(fragments.size(), rs_data, rs_parity) > BB_MAX_CHUNKS) {
        return BB_ERR_UNSUPPORTED;
    }

    out_layout.rs_data   = rs_data;
    out_layout.rs_parity = rs_parity;

    // Стабильная сортировка индексов по длине: при равных длинах порядок задаёт
    // исходный индекс, иначе раскладка перестала бы быть чистой функцией.
    std::vector<std::uint32_t> order(fragments.size());
    std::iota(order.begin(), order.end(), 0u);

    std::stable_sort(order.begin(), order.end(),
                     [&fragments](std::uint32_t a, std::uint32_t b) {
                         return fragments[a].length < fragments[b].length;
                     });

    const std::uint32_t slots  = rs_data + rs_parity;
    const std::size_t   stripe_count = (order.size() + rs_data - 1) / rs_data;

    out_layout.stripes.reserve(stripe_count);
    out_layout.shards.reserve(order.size() + stripe_count * rs_parity);

    for (std::size_t stripe = 0; stripe < stripe_count; ++stripe) {
        const std::size_t first = stripe * rs_data;
        const std::size_t count = std::min<std::size_t>(rs_data, order.size() - first);

        // stripe_len — максимум по stripe. Так как порядок отсортирован по
        // возрастанию, это длина последнего элемента группы.
        const std::uint32_t stripe_len =
            ShardCoreLength(fragments[order[first + count - 1]].length);

        out_layout.stripes.push_back(StripeInfo{
            static_cast<std::uint32_t>(count), stripe_len});

        for (std::size_t j = 0; j < count; ++j) {
            const std::uint32_t fragment = order[first + j];
            out_layout.shards.push_back(ShardRef{
                fragment,
                static_cast<std::uint32_t>(stripe),
                static_cast<std::uint16_t>(j),
                static_cast<std::uint32_t>(stripe * slots + j),
                ShardCoreLength(fragments[fragment].length),
                false});
        }

        // Позиции parity не сдвигаются при неполной stripe: §12 задаёт индекс
        // через фиксированное число слотов, и сдвиг сломал бы имена объектов.
        for (std::uint32_t p = 0; p < rs_parity; ++p) {
            const std::uint32_t position = rs_data + p;
            out_layout.shards.push_back(ShardRef{
                kNoFragment,
                static_cast<std::uint32_t>(stripe),
                static_cast<std::uint16_t>(position),
                static_cast<std::uint32_t>(stripe * slots + position),
                stripe_len,
                true});
        }
    }

    return BB_OK;
}

bool StripeFragmentCount(std::uint64_t  chunk_count,
                         std::uint32_t  rs_data,
                         std::uint32_t  rs_parity,
                         std::uint64_t* out_fragment_count)
{
    if (out_fragment_count == nullptr || rs_data == 0 || rs_parity == 0) {
        return false;
    }
    if (chunk_count == 0) {
        *out_fragment_count = 0;
        return true;
    }

    // chunk_count = n + ceil(n / rs_data) * rs_parity строго растёт с n,
    // поэтому n определяется однозначно и находится двоичным поиском.
    //
    // Здесь была оценка n ≈ chunk_count * rs_data / (rs_data + rs_parity) с
    // коротким подъёмом от неё. Оценка не является нижней границей: неполная
    // последняя stripe поднимает её до n + rs_data, и при 16+4 поиск стартовал
    // выше искомого значения. Двоичный поиск обходится без таких поправок.
    std::uint64_t low  = 0;
    std::uint64_t high = chunk_count;

    while (low < high) {
        const std::uint64_t mid      = low + (high - low) / 2;
        const std::uint64_t produced = SplitShardCount(mid, rs_data, rs_parity);

        if (produced < chunk_count) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    if (SplitShardCount(low, rs_data, rs_parity) != chunk_count) {
        return false;  // такое число объектов недостижимо
    }

    *out_fragment_count = low;
    return true;
}

}  // namespace bb
