// Reed–Solomon над GF(2^8) с матрицей Коши — ARCHITECTURE.md §10, §29, §30.
//
// Гарантия: потеря любых parity элементов одной stripe восстановима. Она
// действует НА КАЖДУЮ STRIPE ОТДЕЛЬНО — потеря четырёх чанков внутри одной
// stripe невосстановима, даже если все остальные stripes целы (§10).
//
// Матрица Коши. §30 называет её, но не задаёт параметры; выбрано
//
//   a[i][j] = 1 / (x_i ⊕ y_j),   x_i = i,   y_j = parity + j
//
// Множества {x_i} и {y_j} не пересекаются, поэтому знаменатель никогда не ноль,
// а любая квадратная подматрица обратима — это и есть свойство Коши, из
// которого следует восстановимость при любом наборе потерь. Требуется
// data + parity ≤ 256.
//
// Выбор заморожен вектором: parity-байты лежат в объектах хранилища, и другая
// матрица сделала бы ранее записанные parity бесполезными.
//
// Кодирование идёт по УЖЕ ЗАШИФРОВАННЫМ данным (§10). Поэтому хранилище или
// будущий сетевой узел может чинить повреждённый ciphertext, не имея ключа.
//
// О длинах. Все шарды stripe подаются сюда одной длины: RS иначе не работает.
// Дополнять data shards нулями до stripe_len — задача вызывающего, и делается
// это только в памяти; на диск data shard пишется в своей истинной длине (§10).

#ifndef BBCORE_REDUNDANCY_REEDSOLOMON_H
#define BBCORE_REDUNDANCY_REEDSOLOMON_H

#include "bbcore/bbcore.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bb {

class ReedSolomon {
public:
    /// data + parity ≤ 256, оба не нули.
    static bool Create(std::uint32_t data, std::uint32_t parity, ReedSolomon& out);

    std::uint32_t DataShards() const { return data_; }
    std::uint32_t ParityShards() const { return parity_; }
    std::uint32_t TotalShards() const { return data_ + parity_; }

    /// Посчитать parity по data. data — data_ буферов длины shard_len,
    /// parity — parity_ буферов той же длины.
    bool Encode(const std::uint8_t* const* data,
                std::uint8_t* const*       parity,
                std::size_t                shard_len) const;

    /// Восстановить недостающие шарды на месте.
    ///
    /// shards — TotalShards() буферов длины shard_len; отсутствующие обязаны
    /// быть выделены, но их содержимое не читается. present[i] == false
    /// означает «шард потерян и подлежит восстановлению».
    ///
    /// Возвращает BB_ERR_UNRECOVERABLE, если уцелело меньше data_ шардов.
    bb_status Decode(std::uint8_t* const* shards,
                     const bool*          present,
                     std::size_t          shard_len) const;

private:
    /// Строка i матрицы Коши, столбец j.
    std::uint8_t Coefficient(std::uint32_t i, std::uint32_t j) const;

    std::uint32_t data_   = 0;
    std::uint32_t parity_ = 0;

    /// parity_ × data_, построчно.
    std::vector<std::uint8_t> matrix_;
};

}  // namespace bb

#endif  // BBCORE_REDUNDANCY_REEDSOLOMON_H
