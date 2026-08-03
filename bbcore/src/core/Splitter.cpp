#include "core/Splitter.h"

#include "crypto/Shake.h"

#include <string_view>

namespace bb {
namespace {

constexpr std::string_view kLabelSplit = "bbk/1/split";

/// §8 называет первые 32 байта выжимки split_seed. Сами размеры берутся
/// дальше по потоку, по 4 байта на фрагмент.
constexpr std::size_t kSeedLen  = 32;
constexpr std::size_t kDrawLen  = 4;

/// Потолок роста профиля. При базовых 2 MiB и лимите в 8192 шарда удвоений
/// хватает на файлы далеко за пределами разумного; ограничение стоит только
/// чтобы цикл не мог стать бесконечным на испорченных входных данных.
constexpr unsigned kMaxDoublings = 32;

std::uint64_t CeilDiv(std::uint64_t value, std::uint64_t divisor)
{
    return divisor == 0 ? 0 : (value + divisor - 1) / divisor;
}

bool DoubleProfile(SplitProfile& profile)
{
    // Переполнение практически недостижимо, но профиль приходит извне.
    if (profile.max > (0xFFFFFFFFu / 2)) {
        return false;
    }
    profile.min *= 2;
    profile.avg *= 2;
    profile.max *= 2;
    return true;
}

}  // namespace

bool SplitProfileIsValid(const SplitProfile& profile)
{
    if (profile.align == 0 || profile.min == 0) {
        return false;
    }
    if (profile.min > profile.avg || profile.avg > profile.max) {
        return false;
    }
    return profile.min % profile.align == 0
        && profile.avg % profile.align == 0
        && profile.max % profile.align == 0;
}

std::uint64_t SplitShardCount(std::uint64_t fragment_count,
                              std::uint32_t rs_data,
                              std::uint32_t rs_parity)
{
    if (rs_data == 0) {
        return 0;
    }
    const std::uint64_t stripes = CeilDiv(fragment_count, rs_data);
    return stripes * (static_cast<std::uint64_t>(rs_data) + rs_parity);
}

bool SplitFragments(const FileKey&      k_file,
                    std::uint64_t       stored_size,
                    const SplitProfile& profile,
                    std::vector<Fragment>& out_fragments)
{
    out_fragments.clear();

    if (!SplitProfileIsValid(profile)) {
        return false;
    }

    // Пустой поток — всё равно один чанк: он несёт метаданные файла.
    if (stored_size == 0) {
        out_fragments.push_back(Fragment{0, 0});
        return true;
    }

    const std::uint64_t units_min = profile.min / profile.align;
    const std::uint64_t units_max = profile.max / profile.align;
    const std::uint64_t range     = units_max - units_min + 1;

    // Верхняя граница числа фрагментов: все по минимуму. Плюс один на остаток.
    const std::uint64_t draws = CeilDiv(stored_size, profile.min) + 1;
    if (draws > (BB_MAX_CHUNKS * 4ull)) {
        return false;  // профиль явно не выбран под этот размер
    }

    std::vector<std::uint8_t> stream(kSeedLen + kDrawLen * static_cast<std::size_t>(draws));
    {
        Shake256 shake;
        shake.Update(k_file.data(), k_file.size());
        shake.Update(kLabelSplit);
        if (!shake.Finish(stream.data(), stream.size())) {
            return false;
        }
    }

    std::uint64_t offset = 0;
    std::size_t   draw   = 0;

    while (offset < stored_size) {
        if (draw >= draws) {
            return false;  // оценка draws оказалась неверной — это ошибка кода
        }

        const std::uint8_t* p = stream.data() + kSeedLen + draw * kDrawLen;
        const std::uint32_t value = static_cast<std::uint32_t>(p[0]) << 24
                                  | static_cast<std::uint32_t>(p[1]) << 16
                                  | static_cast<std::uint32_t>(p[2]) << 8
                                  | static_cast<std::uint32_t>(p[3]);

        const std::uint64_t units  = units_min + (value % range);
        const std::uint64_t wanted = units * profile.align;
        const std::uint64_t left   = stored_size - offset;

        // Последний фрагмент — остаточный, и он единственный может оказаться
        // меньше min и невыровненным.
        const std::uint32_t length =
            static_cast<std::uint32_t>(wanted < left ? wanted : left);

        out_fragments.push_back(Fragment{offset, length});
        offset += length;
        ++draw;
    }

    bb_secure_zero(stream.data(), stream.size());
    return true;
}

bool SplitChooseProfile(std::uint64_t       stored_size,
                        const SplitProfile& base,
                        std::uint32_t       rs_data,
                        std::uint32_t       rs_parity,
                        SplitProfile&       out_profile)
{
    if (!SplitProfileIsValid(base) || rs_data == 0) {
        return false;
    }

    out_profile = base;

    for (unsigned step = 0; step <= kMaxDoublings; ++step) {
        // Дешёвая оценка §8: сколько фрагментов даст средний размер.
        const std::uint64_t estimate = CeilDiv(stored_size, out_profile.avg);

        if (SplitShardCount(estimate == 0 ? 1 : estimate, rs_data, rs_parity)
                <= BB_MAX_CHUNKS) {
            return true;
        }
        if (!DoubleProfile(out_profile)) {
            return false;
        }
    }
    return false;
}

bb_status SplitFile(const FileKey&      k_file,
                    std::uint64_t       stored_size,
                    const SplitProfile& base,
                    std::uint32_t       rs_data,
                    std::uint32_t       rs_parity,
                    std::vector<Fragment>& out_fragments,
                    SplitProfile&          out_profile)
{
    if (!SplitProfileIsValid(base) || rs_data == 0) {
        return BB_ERR_INVALID_ARG;
    }
    if (!SplitChooseProfile(stored_size, base, rs_data, rs_parity, out_profile)) {
        return BB_ERR_UNSUPPORTED;
    }

    // «удваивается, пока ограничение не выполнится» (§8) — проверяется
    // фактическая раскладка, а не оценка по среднему: разброс числа фрагментов
    // порядка корня из их количества, и файл на самой границе оценку
    // перешагнул бы.
    for (unsigned step = 0; step <= kMaxDoublings; ++step) {
        if (!SplitFragments(k_file, stored_size, out_profile, out_fragments)) {
            return BB_ERR_INTERNAL;
        }
        if (SplitShardCount(out_fragments.size(), rs_data, rs_parity) <= BB_MAX_CHUNKS) {
            return BB_OK;
        }
        if (!DoubleProfile(out_profile)) {
            return BB_ERR_UNSUPPORTED;
        }
    }

    out_fragments.clear();
    return BB_ERR_UNSUPPORTED;
}

}  // namespace bb
