// Раскладка по stripes — §10 и §12.
//
// Внешних векторов здесь быть не может: это чистая логика над таблицей длин.
// Проверяются свойства, на которых держится формат, — детерминированность,
// сортировка, канонический индекс и поведение неполной последней stripe.

#include "Testing.h"

#include "core/StripeBuilder.h"

#include <algorithm>
#include <set>
#include <vector>

namespace {

std::vector<bb::Fragment> FragmentsOfLengths(const std::vector<std::uint32_t>& lengths)
{
    std::vector<bb::Fragment> fragments;
    std::uint64_t             offset = 0;
    for (std::uint32_t length : lengths) {
        fragments.push_back(bb::Fragment{offset, length});
        offset += length;
    }
    return fragments;
}

/// Псевдоразные длины, чтобы сортировка была не тождественной.
std::vector<bb::Fragment> SyntheticFragments(std::size_t count)
{
    std::vector<std::uint32_t> lengths;
    for (std::size_t i = 0; i < count; ++i) {
        lengths.push_back(static_cast<std::uint32_t>(
            (1u << 20) + ((i * 2654435761u) % (2u << 20))));
    }
    return FragmentsOfLengths(lengths);
}

}  // namespace

BB_TEST(stripe_core_length_adds_the_aead_tag)
{
    BB_CHECK_EQ(bb::ShardCoreLength(0), static_cast<std::uint32_t>(bb::kAeadTagLen));
    BB_CHECK_EQ(bb::ShardCoreLength(1000), 1000u + bb::kAeadTagLen);
}

// Сортировка по возрастанию длины — то, ради чего parity ужимается с 1.91x
// до ~1.38x.
BB_TEST(stripe_sorts_fragments_by_length)
{
    const std::vector<bb::Fragment> fragments =
        FragmentsOfLengths({500, 100, 400, 200, 300, 800, 600, 700});

    bb::FileLayout layout;
    BB_CHECK_EQ(bb::BuildStripes(fragments, 8, 3, layout), BB_OK);
    BB_CHECK_EQ(layout.stripes.size(), std::size_t{1});

    const std::uint32_t expected[] = {1, 3, 4, 2, 0, 6, 7, 5};
    std::size_t         seen       = 0;

    for (const bb::ShardRef& shard : layout.shards) {
        if (shard.is_parity) {
            continue;
        }
        BB_CHECK_EQ(shard.fragment, expected[seen]);
        BB_CHECK_EQ(shard.position, static_cast<std::uint16_t>(seen));
        ++seen;
    }
    BB_CHECK_EQ(seen, std::size_t{8});
}

// При равных длинах порядок задаёт исходный индекс: без стабильности раскладка
// перестала бы быть чистой функцией от (K_file, stored_size, профиль).
BB_TEST(stripe_sort_is_stable_on_equal_lengths)
{
    const std::vector<bb::Fragment> fragments =
        FragmentsOfLengths({100, 100, 100, 100, 100, 100, 100, 100});

    bb::FileLayout layout;
    BB_CHECK_EQ(bb::BuildStripes(fragments, 8, 3, layout), BB_OK);

    std::uint32_t expected = 0;
    for (const bb::ShardRef& shard : layout.shards) {
        if (!shard.is_parity) {
            BB_CHECK_EQ(shard.fragment, expected++);
        }
    }
}

// stripe_len — максимум длины core внутри stripe, и именно его получают parity.
BB_TEST(stripe_len_is_the_longest_core_in_the_stripe)
{
    const std::vector<bb::Fragment> fragments =
        FragmentsOfLengths({10, 20, 30, 40, 50, 60, 70, 80, 90, 100});

    bb::FileLayout layout;
    BB_CHECK_EQ(bb::BuildStripes(fragments, 8, 3, layout), BB_OK);
    BB_CHECK_EQ(layout.stripes.size(), std::size_t{2});

    BB_CHECK_EQ(layout.stripes[0].stripe_len, bb::ShardCoreLength(80));
    BB_CHECK_EQ(layout.stripes[1].stripe_len, bb::ShardCoreLength(100));

    for (const bb::ShardRef& shard : layout.shards) {
        if (shard.is_parity) {
            BB_CHECK_EQ(shard.core_length, layout.stripes[shard.stripe].stripe_len);
        } else {
            BB_CHECK(shard.core_length <= layout.stripes[shard.stripe].stripe_len);
        }
    }
}

// ---------------------------------------------------------------------------
// Неполная последняя stripe
// ---------------------------------------------------------------------------

// Принятое решение: у последней stripe фактическое k, parity всё равно три.
BB_TEST(stripe_partial_last_stripe_keeps_actual_k)
{
    const std::vector<bb::Fragment> fragments = SyntheticFragments(10);

    bb::FileLayout layout;
    BB_CHECK_EQ(bb::BuildStripes(fragments, 8, 3, layout), BB_OK);

    BB_CHECK_EQ(layout.stripes.size(), std::size_t{2});
    BB_CHECK_EQ(layout.stripes[0].data_count, 8u);
    BB_CHECK_EQ(layout.stripes[1].data_count, 2u);

    // 10 data + 2 * 3 parity = 16 объектов, а не 22.
    BB_CHECK_EQ(layout.shards.size(), std::size_t{16});
    BB_CHECK_EQ(bb::SplitShardCount(10, 8, 3), std::uint64_t{16});
}

// Позиции parity не сдвигаются: §12 считает индекс через фиксированные слоты,
// и сдвиг переименовал бы все объекты после первой неполной stripe.
BB_TEST(stripe_parity_positions_do_not_shift_in_a_partial_stripe)
{
    const std::vector<bb::Fragment> fragments = SyntheticFragments(10);

    bb::FileLayout layout;
    BB_CHECK_EQ(bb::BuildStripes(fragments, 8, 3, layout), BB_OK);

    std::vector<std::uint16_t> parity_positions;
    for (const bb::ShardRef& shard : layout.shards) {
        if (shard.is_parity && shard.stripe == 1) {
            parity_positions.push_back(shard.position);
        }
    }

    BB_CHECK_EQ(parity_positions.size(), std::size_t{3});
    BB_CHECK_EQ(parity_positions[0], std::uint16_t{8});
    BB_CHECK_EQ(parity_positions[1], std::uint16_t{9});
    BB_CHECK_EQ(parity_positions[2], std::uint16_t{10});
}

// Индексы 8..15 не существуют — в неполной stripe там нет data shards. Именно
// поэтому канонический ряд не сплошной.
BB_TEST(stripe_canonical_indices_have_gaps_when_the_last_stripe_is_partial)
{
    const std::vector<bb::Fragment> fragments = SyntheticFragments(10);

    bb::FileLayout layout;
    BB_CHECK_EQ(bb::BuildStripes(fragments, 8, 3, layout), BB_OK);

    std::set<std::uint32_t> present;
    for (const bb::ShardRef& shard : layout.shards) {
        present.insert(shard.index);
    }

    // Первая stripe заполнена целиком: 0..10.
    for (std::uint32_t i = 0; i <= 10; ++i) {
        BB_CHECK(present.count(i) == 1);
    }
    // Вторая: два data (11, 12) и три parity (19, 20, 21).
    BB_CHECK(present.count(11) == 1);
    BB_CHECK(present.count(12) == 1);
    BB_CHECK(present.count(19) == 1);
    BB_CHECK(present.count(20) == 1);
    BB_CHECK(present.count(21) == 1);
    // А позиций 2..7 второй stripe нет.
    for (std::uint32_t i = 13; i <= 18; ++i) {
        BB_CHECK(present.count(i) == 0);
    }
}

// ---------------------------------------------------------------------------
// Канонический индекс §12
// ---------------------------------------------------------------------------

BB_TEST(stripe_canonical_index_follows_the_formula)
{
    for (std::size_t count : {std::size_t{1}, std::size_t{7}, std::size_t{8},
                              std::size_t{9}, std::size_t{64}, std::size_t{100}}) {
        bb::FileLayout layout;
        BB_CHECK_EQ(bb::BuildStripes(SyntheticFragments(count), 8, 3, layout), BB_OK);

        std::set<std::uint32_t> seen;
        std::uint32_t           previous = 0;
        bool                    first    = true;

        for (const bb::ShardRef& shard : layout.shards) {
            BB_CHECK_EQ(shard.index, shard.stripe * 11 + shard.position);

            // Индексы уникальны и строго возрастают: обход идёт в каноническом
            // порядке, на котором держится вывод имён.
            BB_CHECK(seen.insert(shard.index).second);
            if (!first) {
                BB_CHECK(shard.index > previous);
            }
            previous = shard.index;
            first    = false;
        }

        BB_CHECK_EQ(layout.shards.size(),
                    static_cast<std::size_t>(bb::SplitShardCount(count, 8, 3)));
    }
}

BB_TEST(stripe_every_fragment_appears_exactly_once)
{
    const std::size_t count = 100;

    bb::FileLayout layout;
    BB_CHECK_EQ(bb::BuildStripes(SyntheticFragments(count), 8, 3, layout), BB_OK);

    std::vector<int> times(count, 0);
    std::size_t      parity = 0;

    for (const bb::ShardRef& shard : layout.shards) {
        if (shard.is_parity) {
            BB_CHECK_EQ(shard.fragment, bb::kNoFragment);
            ++parity;
        } else {
            BB_CHECK(shard.fragment < count);
            ++times[shard.fragment];
        }
    }

    for (int seen : times) {
        BB_CHECK_EQ(seen, 1);
    }
    BB_CHECK_EQ(parity, layout.stripes.size() * 3);
}

BB_TEST(stripe_layout_is_deterministic)
{
    bb::FileLayout first;
    bb::FileLayout second;
    BB_CHECK_EQ(bb::BuildStripes(SyntheticFragments(37), 8, 3, first), BB_OK);
    BB_CHECK_EQ(bb::BuildStripes(SyntheticFragments(37), 8, 3, second), BB_OK);

    BB_CHECK_EQ(first.shards.size(), second.shards.size());
    for (std::size_t i = 0; i < first.shards.size() && i < second.shards.size(); ++i) {
        BB_CHECK_EQ(first.shards[i].fragment, second.shards[i].fragment);
        BB_CHECK_EQ(first.shards[i].index, second.shards[i].index);
        BB_CHECK_EQ(first.shards[i].core_length, second.shards[i].core_length);
    }
}

// ---------------------------------------------------------------------------
// Восстановление числа фрагментов из chunk_count
// ---------------------------------------------------------------------------

// Без этого читатель, имея один чанк, не знал бы, какие индексы существуют, —
// и обещание «любой чанк открывает весь файл» не выполнялось бы при неполной
// последней stripe.
BB_TEST(stripe_fragment_count_is_recoverable_from_chunk_count)
{
    for (std::uint64_t n = 1; n <= 2000; ++n) {
        const std::uint64_t chunks = bb::SplitShardCount(n, 8, 3);

        std::uint64_t recovered = 0;
        BB_CHECK(bb::StripeFragmentCount(chunks, 8, 3, &recovered));
        if (recovered != n) {
            std::printf("    n = %llu recovered as %llu from %llu chunks\n",
                        static_cast<unsigned long long>(n),
                        static_cast<unsigned long long>(recovered),
                        static_cast<unsigned long long>(chunks));
            ++bb_failures;
            return;
        }
    }
}

BB_TEST(stripe_fragment_count_works_for_other_rs_parameters)
{
    const std::uint32_t configurations[][2] = {{4, 2}, {8, 3}, {16, 4}, {1, 1}};

    for (const auto& rs : configurations) {
        for (std::uint64_t n = 1; n <= 200; ++n) {
            const std::uint64_t chunks = bb::SplitShardCount(n, rs[0], rs[1]);

            std::uint64_t recovered = 0;
            BB_CHECK(bb::StripeFragmentCount(chunks, rs[0], rs[1], &recovered));
            BB_CHECK_EQ(recovered, n);
        }
    }
}

// Не всякое число объектов достижимо: между 11 (n = 8) и 15 (n = 9) значений
// нет. Испорченный chunk_count обязан быть отвергнут, а не округлён.
BB_TEST(stripe_fragment_count_rejects_impossible_totals)
{
    std::uint64_t recovered = 0;

    BB_CHECK(bb::StripeFragmentCount(11, 8, 3, &recovered));
    BB_CHECK_EQ(recovered, std::uint64_t{8});

    for (std::uint64_t impossible : {std::uint64_t{12}, std::uint64_t{13},
                                     std::uint64_t{14}}) {
        BB_CHECK(!bb::StripeFragmentCount(impossible, 8, 3, &recovered));
    }

    BB_CHECK(bb::StripeFragmentCount(0, 8, 3, &recovered));
    BB_CHECK_EQ(recovered, std::uint64_t{0});

    BB_CHECK(!bb::StripeFragmentCount(11, 0, 3, &recovered));
    BB_CHECK(!bb::StripeFragmentCount(11, 8, 3, nullptr));
}

BB_TEST(stripe_rejects_invalid_input)
{
    bb::FileLayout layout;

    BB_CHECK_EQ(bb::BuildStripes({}, 8, 3, layout), BB_ERR_INVALID_ARG);
    BB_CHECK_EQ(bb::BuildStripes(SyntheticFragments(4), 0, 3, layout),
                BB_ERR_INVALID_ARG);
    BB_CHECK_EQ(bb::BuildStripes(SyntheticFragments(4), 8, 0, layout),
                BB_ERR_INVALID_ARG);
}
