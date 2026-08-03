// Псевдослучайное разбиение хранимого потока — ARCHITECTURE.md §8.
//
// Размеры фрагментов обязаны выглядеть случайными для хранилища и при этом
// воспроизводиться для одной версии файла: полностью случайный split уничтожил
// бы дедупликацию, потому что повторный backup давал бы другой набор чанков.
//
// Разбиение — чистая функция от (K_file, stored_size, профиль). Границы нигде
// не хранятся: клиент пересчитывает их, имея K_file и метаданные.
//
// Поток размеров берётся продолжением того же XOF, которым §8 задаёт seed:
//
//   SHAKE256(K_file || "bbk/1/split", 32 + 4 * n)
//
// Первые 32 байта — это ровно split_seed из §8 (короткий вывод SHAKE является
// префиксом длинного), дальше по 4 байта на фрагмент. Спецификация говорит
// «из seed криптографический поток выдаёт размеры», но чем именно этот поток
// является, не пишет; продолжение той же выжимки выбрано по той же причине,
// что и N_env в §15, — не заводить второй источник там, где хватает одного.
//
// Размер фрагмента выбирается в единицах выравнивания:
//
//   units = units_min + (u32be(draw) mod (units_max - units_min + 1))
//   size  = units * alignment
//
// При базовом профиле это 16..48 единиц по 64 KiB, то есть 1..3 MiB со средним
// ровно 2 MiB — заявленный §8 средний размер получается сам, без подгонки.
//
// Смещение по модулю даёт смещение распределения порядка 33/2^32; оно принято
// сознательно. Отбраковка выровняла бы распределение, но сделала бы расход
// потока зависящим от значений, а вместе с ним и раскладку — менее очевидной
// для проверки.

#ifndef BBCORE_CORE_SPLITTER_H
#define BBCORE_CORE_SPLITTER_H

#include "bbcore/bbcore.h"

#include "crypto/HybridKem.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bb {

struct SplitProfile {
    std::uint32_t min;
    std::uint32_t avg;
    std::uint32_t max;
    std::uint32_t align;
};

inline constexpr SplitProfile kDefaultSplitProfile{
    BB_SPLIT_MIN, BB_SPLIT_AVG, BB_SPLIT_MAX, BB_SPLIT_ALIGN};

/// Фрагмент хранимого потока. Смещения нужны потому, что шифрование читает
/// поток не последовательно, а в порядке stripes (§10).
struct Fragment {
    std::uint64_t offset;
    std::uint32_t length;
};

/// Профиль пригоден, если min ≤ avg ≤ max, все три кратны align и align > 0.
/// Кратность обязательна: иначе units_min и units_max не задавали бы границы.
bool SplitProfileIsValid(const SplitProfile& profile);

/// Профиль после роста под потолок в BB_MAX_CHUNKS шардов (§8).
///
/// avg удваивается вместе с min и max, пока раскладка не уложится в лимит.
/// Проверяется именно итоговое число шардов, а не оценка stored_size / avg:
/// у оценки есть разброс порядка корня из числа фрагментов, и файл ровно на
/// границе мог бы её перешагнуть.
bool SplitChooseProfile(std::uint64_t       stored_size,
                        const SplitProfile& base,
                        std::uint32_t       rs_data,
                        std::uint32_t       rs_parity,
                        SplitProfile&       out_profile);

/// Границы фрагментов для заданного профиля. Данные не читаются.
///
/// Последний фрагмент имеет остаточный размер и может быть меньше min.
/// Пустой поток даёт один фрагмент нулевой длины: чанк всё равно нужен —
/// он несёт метаданные файла.
bool SplitFragments(const FileKey&      k_file,
                    std::uint64_t       stored_size,
                    const SplitProfile& profile,
                    std::vector<Fragment>& out_fragments);

/// SplitChooseProfile и SplitFragments одним вызовом — обычный путь.
bb_status SplitFile(const FileKey&      k_file,
                    std::uint64_t       stored_size,
                    const SplitProfile& base,
                    std::uint32_t       rs_data,
                    std::uint32_t       rs_parity,
                    std::vector<Fragment>& out_fragments,
                    SplitProfile&          out_profile);

/// Сколько объектов (data + parity) даст такое число фрагментов.
///
/// Считаются реально существующие: у неполной последней stripe ровно столько
/// data shards, сколько фрагментов в неё попало, а parity всё равно свои (§10).
/// Отсюда count = fragment_count + stripes * rs_parity, а не
/// stripes * (rs_data + rs_parity) — иначе потолок §8 срабатывал бы раньше
/// времени на несуществующих позициях.
std::uint64_t SplitShardCount(std::uint64_t fragment_count,
                              std::uint32_t rs_data,
                              std::uint32_t rs_parity);

}  // namespace bb

#endif  // BBCORE_CORE_SPLITTER_H
