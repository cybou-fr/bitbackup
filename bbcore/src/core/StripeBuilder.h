// Раскладка фрагментов по stripes — ARCHITECTURE.md §10 и §12.
//
// Reed–Solomon требует одинаковой длины внутри stripe, а фрагменты после split
// разной длины. Поэтому они сортируются по возрастанию длины (стабильно, при
// равных — по исходному индексу) и уже отсортированная последовательность
// режется на группы по rs_data. Сортировка сближает длины внутри stripe и
// уменьшает parity: ~1.38x против 1.91x при дополнении всего до максимума.
//
// Порядок операций обязателен (§10): K_shard и nonce выводятся из stripe и
// position, а те известны только после раскладки. Раскладка при этом не читает
// ни байта данных — только таблицу длин из split.
//
//   i = stripe * (rs_data + rs_parity) + position          (§12)
//
// position 0..rs_data-1 — data shards, дальше parity.
//
// НЕПОЛНАЯ ПОСЛЕДНЯЯ STRIPE. Спецификация об этом случае молчала. Принято: у
// последней stripe ровно столько data shards, сколько фрагментов в неё попало,
// а parity всё равно rs_parity штук. Позиции parity при этом НЕ сдвигаются —
// они всегда rs_data..rs_data+rs_parity-1, поэтому §12 остаётся как есть и
// индексы предыдущих stripes не меняются. Позиции от k до rs_data-1 в неполной
// stripe просто не существуют: объектов с такими именами нет.
//
// Следствие: канонические индексы не сплошные. Это не мешает вывести имена
// всех чанков из одного, потому что число фрагментов однозначно восстанавливается
// из chunk_count — см. StripeFragmentCount.

#ifndef BBCORE_CORE_STRIPEBUILDER_H
#define BBCORE_CORE_STRIPEBUILDER_H

#include "bbcore/bbcore.h"

#include "core/Splitter.h"

#include <cstdint>
#include <vector>

namespace bb {

/// У parity shard нет фрагмента-источника.
inline constexpr std::uint32_t kNoFragment = 0xFFFFFFFFu;

struct ShardRef {
    std::uint32_t fragment;    ///< индекс в stored stream либо kNoFragment
    std::uint32_t stripe;
    std::uint16_t position;
    std::uint32_t index;       ///< канонический индекс §12
    std::uint32_t core_length; ///< длина shard core; у parity — stripe_len
    bool          is_parity;
};

struct StripeInfo {
    std::uint32_t data_count;  ///< фактическое k, у последней может быть < rs_data
    std::uint32_t stripe_len;  ///< максимальная длина core в stripe
};

struct FileLayout {
    std::uint32_t rs_data   = 0;
    std::uint32_t rs_parity = 0;

    std::vector<StripeInfo> stripes;

    /// Все реально существующие шарды, по возрастанию канонического индекса.
    std::vector<ShardRef> shards;
};

/// Длина shard core: фрагмент плюс AEAD-тег (§9). У parity тега нет, но длина
/// равна максимальной длине core в stripe, чтобы Reed–Solomon сошёлся.
std::uint32_t ShardCoreLength(std::uint32_t fragment_length);

/// Разложить фрагменты по stripes. Данные не читаются.
bb_status BuildStripes(const std::vector<Fragment>& fragments,
                       std::uint32_t                rs_data,
                       std::uint32_t                rs_parity,
                       FileLayout&                  out_layout);

/// Обратное к SplitShardCount: сколько фрагментов стоит за таким числом
/// объектов. Восстановимо однозначно, потому что chunk_count строго растёт с
/// числом фрагментов. Нужно читателю, у которого есть один чанк и метаданные:
/// зная число фрагментов, он выводит имена всех остальных объектов.
bool StripeFragmentCount(std::uint64_t  chunk_count,
                         std::uint32_t  rs_data,
                         std::uint32_t  rs_parity,
                         std::uint64_t* out_fragment_count);

}  // namespace bb

#endif  // BBCORE_CORE_STRIPEBUILDER_H
