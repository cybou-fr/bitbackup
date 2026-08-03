// Псевдослучайное разбиение — §8.
//
// Раскладка для 40 MiB посчитана независимой реализацией §8 на Python
// (hashlib.shake_256): разбиение целиком сводится к SHAKE и целочисленной
// арифметике, вторая реализация возможна.
//
// K_file — байты (11 * 61 + i * 7) mod 256, тот же, что в тестах ключевого
// расписания.

#include "Testing.h"

#include "core/Splitter.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

bb::FileKey TestFileKey()
{
    bb::FileKey key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>((11 * 61 + i * 7) & 0xFF);
    }
    return key;
}

std::vector<bb::Fragment> Split(std::uint64_t size,
                                const bb::SplitProfile& profile = bb::kDefaultSplitProfile)
{
    std::vector<bb::Fragment> fragments;
    if (!bb::SplitFragments(TestFileKey(), size, profile, fragments)) {
        fragments.clear();
    }
    return fragments;
}

/// Покрытие потока без дыр и нахлёстов — то, ради чего split и существует.
bool CoversStream(const std::vector<bb::Fragment>& fragments, std::uint64_t size)
{
    std::uint64_t offset = 0;
    for (const bb::Fragment& f : fragments) {
        if (f.offset != offset) {
            return false;
        }
        offset += f.length;
    }
    return offset == size;
}

}  // namespace

BB_TEST(split_matches_independent_implementation)
{
    const std::vector<bb::Fragment> fragments = Split(40u * 1024 * 1024);

    const std::uint32_t expected[] = {
        2752512, 2621440, 1769472, 3145728, 1966080, 1376256,
        2752512, 2621440, 2424832, 1835008, 2162688, 2162688,
        3014656, 2490368, 3145728, 2555904, 1507328, 1638400,
    };

    BB_CHECK_EQ(fragments.size(), sizeof expected / sizeof expected[0]);
    if (fragments.size() != sizeof expected / sizeof expected[0]) {
        return;
    }

    for (std::size_t i = 0; i < fragments.size(); ++i) {
        BB_CHECK_EQ(fragments[i].length, expected[i]);
    }
    BB_CHECK(CoversStream(fragments, 40u * 1024 * 1024));
}

BB_TEST(split_covers_the_stream_exactly)
{
    for (std::uint64_t size : {std::uint64_t{1}, std::uint64_t{100},
                               std::uint64_t{1} << 20, std::uint64_t{5} << 20,
                               std::uint64_t{40} << 20, std::uint64_t{257} << 20}) {
        const std::vector<bb::Fragment> fragments = Split(size);
        BB_CHECK(!fragments.empty());
        BB_CHECK(CoversStream(fragments, size));
    }
}

// Пустой файл всё равно даёт чанк: он несёт метаданные, без которых файла в
// архиве просто нет.
BB_TEST(split_of_empty_stream_gives_one_empty_fragment)
{
    const std::vector<bb::Fragment> fragments = Split(0);

    BB_CHECK_EQ(fragments.size(), std::size_t{1});
    if (fragments.empty()) {
        return;
    }
    BB_CHECK_EQ(fragments[0].offset, std::uint64_t{0});
    BB_CHECK_EQ(fragments[0].length, std::uint32_t{0});
}

// Все фрагменты, кроме последнего, лежат в [min, max] и выровнены. Последний
// остаточный и может быть меньше минимума — §8 разрешает это явно.
BB_TEST(split_respects_the_profile)
{
    const bb::SplitProfile& p = bb::kDefaultSplitProfile;
    const std::vector<bb::Fragment> fragments = Split(std::uint64_t{200} << 20);

    BB_CHECK(fragments.size() > 1);
    for (std::size_t i = 0; i + 1 < fragments.size(); ++i) {
        BB_CHECK(fragments[i].length >= p.min);
        BB_CHECK(fragments[i].length <= p.max);
        BB_CHECK_EQ(fragments[i].length % p.align, std::uint32_t{0});
    }
    BB_CHECK(fragments.back().length <= p.max);
    BB_CHECK(fragments.back().length > 0);
}

// Без этого пропала бы дедупликация: повторный backup дал бы другой набор
// чанков, и в хранилище легла бы вторая копия файла.
BB_TEST(split_is_deterministic)
{
    const std::vector<bb::Fragment> first  = Split(std::uint64_t{37} << 20);
    const std::vector<bb::Fragment> second = Split(std::uint64_t{37} << 20);

    BB_CHECK_EQ(first.size(), second.size());
    for (std::size_t i = 0; i < first.size() && i < second.size(); ++i) {
        BB_CHECK_EQ(first[i].offset, second[i].offset);
        BB_CHECK_EQ(first[i].length, second[i].length);
    }
}

// А вот у разных файлов границы обязаны разойтись, иначе хранилище увидело бы
// одинаковый профиль размеров у двух версий и связало их.
BB_TEST(split_differs_between_file_keys)
{
    bb::FileKey other = TestFileKey();
    other[0] ^= 0x01;

    std::vector<bb::Fragment> mine;
    std::vector<bb::Fragment> theirs;
    BB_CHECK(bb::SplitFragments(TestFileKey(), std::uint64_t{40} << 20,
                                bb::kDefaultSplitProfile, mine));
    BB_CHECK(bb::SplitFragments(other, std::uint64_t{40} << 20,
                                bb::kDefaultSplitProfile, theirs));

    bool identical = mine.size() == theirs.size();
    for (std::size_t i = 0; identical && i < mine.size(); ++i) {
        identical = mine[i].length == theirs[i].length;
    }
    BB_CHECK(!identical);
}

// Размеры должны выглядеть случайными: раскладка из одинаковых кусков сказала
// бы хранилищу, что split вырожден.
BB_TEST(split_lengths_are_spread_over_the_range)
{
    const std::vector<bb::Fragment> fragments = Split(std::uint64_t{300} << 20);
    BB_CHECK(fragments.size() > 50);

    std::size_t distinct = 0;
    std::uint32_t seen[64] = {};
    for (const bb::Fragment& f : fragments) {
        const std::uint32_t units = f.length / bb::kDefaultSplitProfile.align;
        if (units < 64 && seen[units] == 0) {
            seen[units] = 1;
            ++distinct;
        }
    }
    // Диапазон профиля — 33 значения; ожидать все не стоит, но десяток
    // различных длин обязан набраться.
    BB_CHECK(distinct > 10);
}

// ---------------------------------------------------------------------------
// Рост профиля под потолок в 8192 шарда
// ---------------------------------------------------------------------------

BB_TEST(split_profile_grows_for_large_files)
{
    bb::SplitProfile chosen{};

    // Небольшой файл профиль не трогает.
    BB_CHECK(bb::SplitChooseProfile(std::uint64_t{100} << 20,
                                    bb::kDefaultSplitProfile, 8, 3, chosen));
    BB_CHECK_EQ(chosen.avg, bb::kDefaultSplitProfile.avg);

    // 100 GiB при среднем 2 MiB дал бы более 50 000 фрагментов — профиль
    // обязан вырасти.
    BB_CHECK(bb::SplitChooseProfile(std::uint64_t{100} << 30,
                                    bb::kDefaultSplitProfile, 8, 3, chosen));
    BB_CHECK(chosen.avg > bb::kDefaultSplitProfile.avg);
    BB_CHECK(bb::SplitProfileIsValid(chosen));

    // Пропорции сохраняются: min и max растут вместе с avg.
    BB_CHECK_EQ(chosen.min * 2, chosen.avg);
    BB_CHECK_EQ(chosen.avg * 3, chosen.max * 2);
}

BB_TEST(split_file_never_exceeds_the_shard_ceiling)
{
    for (std::uint64_t size : {std::uint64_t{1} << 30, std::uint64_t{16} << 30,
                               std::uint64_t{100} << 30, std::uint64_t{1} << 40}) {
        std::vector<bb::Fragment> fragments;
        bb::SplitProfile          profile{};

        BB_CHECK_EQ(bb::SplitFile(TestFileKey(), size, bb::kDefaultSplitProfile,
                                  8, 3, fragments, profile),
                    BB_OK);
        BB_CHECK(CoversStream(fragments, size));
        BB_CHECK(bb::SplitShardCount(fragments.size(), 8, 3) <= BB_MAX_CHUNKS);
    }
}

BB_TEST(split_shard_count_accounts_for_a_partial_stripe)
{
    // 8 фрагментов — ровно одна stripe: 8 data + 3 parity.
    BB_CHECK_EQ(bb::SplitShardCount(8, 8, 3), std::uint64_t{11});

    // Девятый начинает вторую stripe, и parity у неё свои: 9 data + 6 parity.
    // Не 22 — несуществующих позиций второй stripe в хранилище нет.
    BB_CHECK_EQ(bb::SplitShardCount(9, 8, 3), std::uint64_t{15});

    // Один фрагмент — одна stripe из одного data shard и трёх parity.
    BB_CHECK_EQ(bb::SplitShardCount(1, 8, 3), std::uint64_t{4});
    BB_CHECK_EQ(bb::SplitShardCount(0, 8, 3), std::uint64_t{0});
}

// ---------------------------------------------------------------------------
// Проверка профиля
// ---------------------------------------------------------------------------

BB_TEST(split_rejects_invalid_profiles)
{
    BB_CHECK(bb::SplitProfileIsValid(bb::kDefaultSplitProfile));

    // Невыровненные границы: units_min и units_max перестали бы задавать
    // диапазон, и средний размер уехал бы.
    BB_CHECK(!bb::SplitProfileIsValid({1 << 20, 2 << 20, (3 << 20) + 1, 64 << 10}));
    BB_CHECK(!bb::SplitProfileIsValid({(1 << 20) + 1, 2 << 20, 3 << 20, 64 << 10}));

    BB_CHECK(!bb::SplitProfileIsValid({3 << 20, 2 << 20, 1 << 20, 64 << 10}));
    BB_CHECK(!bb::SplitProfileIsValid({1 << 20, 2 << 20, 3 << 20, 0}));
    BB_CHECK(!bb::SplitProfileIsValid({0, 2 << 20, 3 << 20, 64 << 10}));

    std::vector<bb::Fragment> fragments;
    BB_CHECK(!bb::SplitFragments(TestFileKey(), 1024,
                                 {3 << 20, 2 << 20, 1 << 20, 64 << 10}, fragments));

    bb::SplitProfile profile{};
    BB_CHECK_EQ(bb::SplitFile(TestFileKey(), 1024, bb::kDefaultSplitProfile,
                              0, 3, fragments, profile),
                BB_ERR_INVALID_ARG);
}

// Профиль с одним допустимым размером — вырожденный, но законный: границы
// совпали, значит все фрагменты одной длины.
BB_TEST(split_handles_a_degenerate_profile)
{
    const bb::SplitProfile fixed{1 << 20, 1 << 20, 1 << 20, 1 << 20};
    BB_CHECK(bb::SplitProfileIsValid(fixed));

    const std::vector<bb::Fragment> fragments = Split((5 << 20) + 12345, fixed);
    BB_CHECK_EQ(fragments.size(), std::size_t{6});
    BB_CHECK(CoversStream(fragments, (5 << 20) + 12345));

    for (std::size_t i = 0; i + 1 < fragments.size(); ++i) {
        BB_CHECK_EQ(fragments[i].length, std::uint32_t{1} << 20);
    }
    BB_CHECK_EQ(fragments.back().length, std::uint32_t{12345});
}
